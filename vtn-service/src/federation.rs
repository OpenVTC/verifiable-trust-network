//! Federated directory search across member networks (design §7).
//!
//! The network searches its own entries, then the **signed indexes** of its acknowledged
//! member networks, and theirs in turn, down to `[directory] federate_depth`:
//! - Each index is fetched from the URL its entry's profile names, and verified as signed by
//!   that network's DID.
//! - Every result carries its **path**: the networks between here and the network that lists
//!   it, each with its own entry state. Nesting never flattens (VTI-VTN-032/033).
//! - A member network whose index cannot be read is reported as indeterminate, not absent
//!   (VTI-REG-012).
//!
//! **Assumption A16:** a member network is reached at its entry profile's `url`, set by the
//! parent's admins, rather than through its DID document's `VerifiableTrustNetwork` service.
//! Indexes are cached for five minutes.

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vtn_core::directory::{self, DirectoryQuery, FederatedEntry, PathHop, Unreachable};
use vtn_core::index::NetworkIndex;
use vtn_core::model::EntryKind;
use vtn_core::verify::{ASSERTION_METHOD, verify_document};

use crate::error::ApiResult;
use crate::network::Network;

const INDEX_CACHE_TTL: Duration = Duration::minutes(5);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FederatedResult {
    pub determined_at: DateTime<Utc>,
    pub results: Vec<FederatedEntry>,
    pub unreachable: Vec<Unreachable>,
}

struct Frontier {
    did: String,
    url: String,
    path: Vec<PathHop>,
}

impl Network {
    pub async fn federated_directory(&self, query: &DirectoryQuery) -> ApiResult<FederatedResult> {
        let entries = self.store.entries().await?;
        let mut results: Vec<FederatedEntry> = directory::search(&entries, query)
            .into_iter()
            .map(|entry| FederatedEntry {
                entry,
                listed_by: self.did().to_string(),
                path: Vec::new(),
            })
            .collect();
        let mut unreachable = Vec::new();
        let mut visited: HashSet<String> = HashSet::from([self.did().to_string()]);
        let mut frontier: Vec<Frontier> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Network && e.state.is_membership())
            .filter_map(|e| {
                Some(Frontier {
                    did: e.did.clone(),
                    url: e.profile.url.clone()?,
                    path: vec![PathHop {
                        network: e.did.clone(),
                        name: e.label.clone(),
                        state: e.state,
                        acknowledged: true,
                    }],
                })
            })
            .collect();

        for _ in 0..self.directory.federate_depth {
            let mut next = Vec::new();
            for hop in frontier {
                if !visited.insert(hop.did.clone()) {
                    continue;
                }
                match self.member_index(&hop.did, &hop.url).await {
                    Ok(index) => {
                        results.extend(directory::search_index(&index, query).into_iter().map(
                            |entry| FederatedEntry {
                                entry,
                                listed_by: hop.did.clone(),
                                path: hop.path.clone(),
                            },
                        ));
                        next.extend(
                            index
                                .entries
                                .iter()
                                .filter(|e| e.kind == EntryKind::Network && e.acknowledged)
                                .filter_map(|e| {
                                    let mut path = hop.path.clone();
                                    path.push(PathHop {
                                        network: e.did.clone(),
                                        name: e.label.clone(),
                                        state: e.state,
                                        acknowledged: e.acknowledged,
                                    });
                                    Some(Frontier {
                                        did: e.did.clone(),
                                        url: e.profile.url.clone()?,
                                        path,
                                    })
                                }),
                        );
                    }
                    Err(reason) => unreachable.push(Unreachable {
                        network: hop.did,
                        path: hop.path,
                        reason,
                    }),
                }
            }
            frontier = next;
        }
        Ok(FederatedResult {
            determined_at: Utc::now(),
            results,
            unreachable,
        })
    }

    /// A member network's signed index, verified as its own.
    pub(crate) async fn member_index(&self, did: &str, url: &str) -> Result<NetworkIndex, String> {
        let now = Utc::now();
        if let Some((at, index)) = self.index_cache.lock().await.get(did)
            && now - *at < INDEX_CACHE_TTL
        {
            return Ok(index.clone());
        }
        let json: Value = self
            .client(url)
            .get("/v1/index")
            .await
            .map_err(|e| e.to_string())?;
        if json.get("network").and_then(Value::as_str) != Some(did) {
            return Err(format!("{url} answers for another network"));
        }
        verify_document(&json, did, ASSERTION_METHOD, self.resolver.as_ref())
            .await
            .map_err(|e| format!("index signature: {e}"))?;
        let index: NetworkIndex =
            serde_json::from_value(json).map_err(|e| format!("unreadable index: {e}"))?;
        self.index_cache
            .lock()
            .await
            .insert(did.to_string(), (now, index.clone()));
        Ok(index)
    }
}

impl Network {
    /// A member network's graph, from its verified signed index, for expanding it in a graph
    /// view. Only acknowledged member networks with a known URL are expanded.
    pub async fn member_graph(&self, did: &str) -> ApiResult<vtn_core::graph::Graph> {
        let entry = self.entry(did).await?;
        let url = entry
            .profile
            .url
            .clone()
            .filter(|_| entry.kind == EntryKind::Network && entry.state.is_membership())
            .ok_or_else(|| {
                crate::error::ApiError::NotFound(format!(
                    "{did} is not a member network with a known URL"
                ))
            })?;
        let index = self
            .member_index(did, &url)
            .await
            .map_err(crate::error::ApiError::Upstream)?;
        Ok(vtn_core::graph::from_index(&index))
    }
}
