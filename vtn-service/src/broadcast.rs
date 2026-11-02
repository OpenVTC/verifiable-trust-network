//! Broadcast to a role across the network, cascading through member networks.
//!
//! - **Send:** an admin sends to a role. The network signs a message and delivers it to the
//!   endpoint of every group its acknowledged members registered for that role. Each delivery
//!   carries a hop signed by this network.
//! - **Receive** (`POST /v1/relay/{role}`): a parent network delivers to this network's
//!   network group. The envelope is verified, end to end: origin signature, hop chain, hop
//!   limit, expiry. The delivery must come from a network this one is a current member of,
//!   addressed to the group this network registered with it. Then it is relayed on to this
//!   network's own groups for the local role.
//!
//! Each network expands only its own groups, so no network learns another's roster. The
//! sender learns which groups accepted, counted through relays (the receipts), and never who
//! is in them.
//!
//! **Assumption A15:** delivery is synchronous HTTPS, one request per group per hop, with
//! receipts returned inline. A durable queue with retries, and TSP/DIDComm delivery, are
//! still to come.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinSet;
use vtn_client::VtnClient;
use vtn_core::VtnError;
use vtn_core::groups::network_group_id;
use vtn_core::identity::Identity;
use vtn_core::relay::{self, DeliveryStatus, Envelope, Outgoing, Receipt};

use crate::error::{ApiError, ApiResult};
use crate::network::Network;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Sent,
    Received,
}

/// A broadcast this network sent or relayed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastRecord {
    pub id: String,
    pub direction: Direction,
    /// The local role it went to.
    pub role: String,
    pub message: Value,
    /// For a received broadcast: the network that delivered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// For a sent broadcast: the admin who sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub at: DateTime<Utc>,
    pub receipts: Vec<Receipt>,
    /// Groups reached, counted through relays.
    pub reached: usize,
}

/// The answer to a relay delivery.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayResponse {
    pub status: DeliveryStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relayed: Vec<Receipt>,
}

fn rejected(why: impl Into<String>) -> ApiError {
    ApiError::Vtn(VtnError::Rejected(why.into()))
}

impl Network {
    /// Send `outgoing` to every group registered for its role.
    pub async fn broadcast(&self, outgoing: Outgoing, actor: &str) -> ApiResult<BroadcastRecord> {
        if self.role(&outgoing.role).is_none() {
            return Err(rejected(format!(
                "this network defines no role {:?}",
                outgoing.role
            )));
        }
        let message = relay::new_message(
            &self.identity,
            &outgoing,
            Duration::hours(self.settings.relay.ttl_hours),
            Utc::now(),
        )
        .await?;
        let id = message["id"].as_str().unwrap_or_default().to_string();
        // Marked seen, so a copy routed back here through a cycle is a duplicate.
        self.store.first_sighting(&id).await?;
        let receipts = self.fan_out(&message, Vec::new(), &outgoing.role).await?;
        let record = BroadcastRecord {
            id: id.clone(),
            direction: Direction::Sent,
            role: outgoing.role,
            message,
            from: None,
            actor: Some(actor.to_string()),
            at: Utc::now(),
            reached: receipts.iter().map(Receipt::reached).sum(),
            receipts,
        };
        self.store.put_broadcast(&id, &record).await?;
        tracing::info!(id, role = %record.role, reached = record.reached, actor, "broadcast sent");
        Ok(record)
    }

    /// A parent network delivers to this network's group for `local_role`.
    pub async fn receive(&self, local_role: &str, envelope: Envelope) -> ApiResult<RelayResponse> {
        if !self.settings.relay.accept {
            return Err(ApiError::Forbidden);
        }
        let verified = relay::verify(
            &envelope,
            self.resolver.as_ref(),
            Utc::now(),
            self.settings.relay.max_hops,
        )
        .await?;
        let group = network_group_id(self.did(), local_role);
        if verified.to != group {
            return Err(rejected(
                "the envelope is not addressed to this network's group",
            ));
        }
        if self.upstream_role(&verified.from, &group).await?.as_deref() != Some(local_role) {
            return Err(rejected(format!(
                "{} is not a network this one serves with role {local_role:?}",
                verified.from
            )));
        }
        if !self.store.first_sighting(&verified.id).await? {
            return Ok(RelayResponse {
                status: DeliveryStatus::Duplicate,
                relayed: Vec::new(),
            });
        }
        let receipts = self
            .fan_out(&envelope.message, envelope.hops.clone(), local_role)
            .await?;
        let record = BroadcastRecord {
            id: verified.id.clone(),
            direction: Direction::Received,
            role: local_role.to_string(),
            message: envelope.message,
            from: Some(verified.from.clone()),
            actor: None,
            at: Utc::now(),
            reached: receipts.iter().map(Receipt::reached).sum(),
            receipts: receipts.clone(),
        };
        self.store.put_broadcast(&verified.id, &record).await?;
        tracing::info!(
            id = %verified.id,
            origin = %verified.origin,
            from = %verified.from,
            role = local_role,
            reached = record.reached,
            "broadcast relayed"
        );
        Ok(RelayResponse {
            status: DeliveryStatus::Delivered,
            relayed: receipts,
        })
    }

    pub async fn broadcasts(&self) -> ApiResult<Vec<BroadcastRecord>> {
        let mut all: Vec<BroadcastRecord> = self.store.broadcasts().await?;
        all.sort_by_key(|b| std::cmp::Reverse(b.at));
        Ok(all)
    }

    pub async fn broadcast_record(&self, id: &str) -> ApiResult<BroadcastRecord> {
        self.store
            .broadcast(id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("no broadcast {id}")))
    }

    /// Deliver `message` to every current member's group for `role`, each with a new hop.
    async fn fan_out(
        &self,
        message: &Value,
        hops: Vec<Value>,
        role: &str,
    ) -> ApiResult<Vec<Receipt>> {
        let id = message["id"].as_str().unwrap_or_default().to_string();
        let mut set = JoinSet::new();
        for group in self.groups(Some(role)).await? {
            // Only current members are delivered to; a suspended member's groups wait.
            let current = self
                .store
                .entry(&group.member)
                .await?
                .is_some_and(|e| e.state.is_membership());
            if !current {
                continue;
            }
            if hops.len() + 1 > self.settings.relay.max_hops {
                set.spawn(async move {
                    Receipt {
                        group: group.group,
                        member: group.member,
                        status: DeliveryStatus::Refused,
                        detail: Some("hop limit reached".into()),
                        network: false,
                        relayed: Vec::new(),
                    }
                });
                continue;
            }
            let identity: Identity = self.identity.clone();
            let client = self.client("");
            let (message, mut hops, id, role) =
                (message.clone(), hops.clone(), id.clone(), role.to_string());
            set.spawn(async move {
                let receipt =
                    |status, detail: Option<String>, relayed: Option<Vec<Receipt>>| Receipt {
                        group: group.group.clone(),
                        member: group.member.clone(),
                        status,
                        detail,
                        network: relayed.is_some(),
                        relayed: relayed.unwrap_or_default(),
                    };
                match relay::new_hop(&identity, &id, &group.group, &role, hops.len()).await {
                    Ok(hop) => hops.push(hop),
                    Err(e) => {
                        return receipt(DeliveryStatus::Failed, Some(e.to_string()), None);
                    }
                }
                deliver(
                    &client,
                    &group.endpoint,
                    Envelope { message, hops },
                    receipt,
                )
                .await
            });
        }
        let mut receipts = Vec::new();
        while let Some(done) = set.join_next().await {
            receipts.push(done.map_err(|e| ApiError::Vtn(VtnError::Internal(e.to_string())))?);
        }
        receipts.sort_by(|a, b| a.group.cmp(&b.group));
        Ok(receipts)
    }
}

async fn deliver(
    client: &VtnClient,
    endpoint: &str,
    envelope: Envelope,
    receipt: impl Fn(DeliveryStatus, Option<String>, Option<Vec<Receipt>>) -> Receipt,
) -> Receipt {
    match client
        .post_url(endpoint, &json!({ "envelope": envelope }))
        .await
    {
        // A network relay answers with a RelayResponse. Any other endpoint (a community's
        // group inbox) that answers 2xx has accepted it.
        Ok(body) => match serde_json::from_value::<RelayResponse>(body) {
            Ok(r) => receipt(r.status, None, Some(r.relayed)),
            Err(_) => receipt(DeliveryStatus::Delivered, None, None),
        },
        Err(e) if matches!(e.status(), Some(403 | 422)) => {
            receipt(DeliveryStatus::Refused, Some(e.to_string()), None)
        }
        Err(e) => receipt(DeliveryStatus::Failed, Some(e.to_string()), None),
    }
}
