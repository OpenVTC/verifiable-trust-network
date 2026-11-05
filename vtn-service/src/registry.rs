//! The network's membership, projected to a trust registry as TRQP records (design §7, A22,
//! `docs/trust-registry.md`).
//!
//! A verifier that already trusts a registry asks it "has this network authorised X as a
//! `member` of `vtn`?" and gets an answer without speaking `vtn/*`. The network stays the
//! source of truth: every record is derived from an entry ([`expected`]), and a change to an
//! entry re-derives the projection. The records are flat, so a question about a path
//! (WHN → Health-AU → St Vincent's) is answered by the network's own federated directory,
//! not the registry.
//!
//! # Record shape (A22)
//!
//! | TRQP | Value |
//! |---|---|
//! | `entity_id` | the listed party's DID |
//! | `authority_id` | this network's DID |
//! | `action` | [`MEMBER_ACTION`] for an acknowledged entry (membership, VTI-VTN-013), [`LISTED_ACTION`] for a listed one when [`Publish::MembersAndListed`] |
//! | `resource` | [`RESOURCE`] |
//! | `context` | the party's kind, the governance framework, and the ids of the listing and grant credentials that evidence the record |
//!
//! A suspended, removed, departed or repudiated entry has no record. Unacknowledged is never
//! membership, so a listed party is published only under its own action, and only when the
//! operator asks for it.
//!
//! # Writes
//!
//! Records are written through a [`RegistryWriter`]. The Affinidi registry accepts record
//! writes (`registry/record/put`, `/delete`) over DIDComm or TSP only, from a DID in its
//! `ADMIN_DIDS`; its HTTPS binding is read-only. This network has no mediator session yet, so
//! the production writer is [`NoWriteTransport`]: the projection is computed and reported,
//! and nothing is written, until a messaging writer is plugged in here. Reads (checking a
//! record) work over HTTPS today (`nnm registry check`, the landing page's Verify tab).
//!
//! # Sync
//!
//! [`Syncer::reconcile`] puts every record that should exist and deletes every record under
//! this authority and resource that should not, against what the registry lists (or, when the
//! writer cannot list, against the local mirror of what was written). It runs at startup,
//! which is how existing members are added, every `sync_interval_secs`, and shortly after
//! every lifecycle change ([`crate::network::Network`] nudges it). A failed write is retried
//! by the next reconcile: the projection is recomputed from the entries each time, so there
//! is no queue to lose.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_vtn::model::{Entry, EntryState, Framework};

use crate::config::RegistryConfig;
use crate::network::Network;

/// The TRQP `resource` every record of this network is published under (A22).
pub const RESOURCE: &str = "vtn";
/// The TRQP `action` of an acknowledged entry: membership (A22).
pub const MEMBER_ACTION: &str = "member";
/// The TRQP `action` of a listed, unacknowledged entry, when published (A22).
pub const LISTED_ACTION: &str = "lists";

/// What the network publishes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Publish {
    /// Acknowledged entries only.
    #[default]
    Members,
    /// Acknowledged entries, and listed ones under [`LISTED_ACTION`].
    MembersAndListed,
}

impl Publish {
    pub fn as_str(self) -> &'static str {
        match self {
            Publish::Members => "members",
            Publish::MembersAndListed => "members-and-listed",
        }
    }
}

/// The `scheme://host[:port]` of an `https://` URL, or `None` for anything else.
pub fn origin_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains(['@', ' ', '\'', '"', ';']) {
        return None;
    }
    Some(format!("https://{host}"))
}

/// One record this network publishes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub entity_id: String,
    pub action: String,
    /// The record's `context`: what it is evidence of.
    pub context: Value,
}

impl Record {
    /// The TRQP `TrustRecord` this record is written as, under `authority`.
    pub fn trust_record(&self, authority: &str) -> Value {
        json!({
            "entityId": self.entity_id,
            "authorityId": authority,
            "action": self.action,
            "resource": RESOURCE,
            "recognized": false,
            "authorized": true,
            "context": self.context,
        })
    }
}

/// The record `entry` is projected to, if any.
pub fn record_for(entry: &Entry, publish: Publish, framework: &Framework) -> Option<Record> {
    let action = match entry.state {
        s if s.is_membership() => MEMBER_ACTION,
        EntryState::Listed if publish == Publish::MembersAndListed => LISTED_ACTION,
        _ => return None,
    };
    let mut context = json!({
        "kind": entry.kind,
        "governanceFramework": { "iri": framework.iri, "version": framework.version },
        "listing": entry.listing.credential.get("id"),
    });
    if let Some(grant) = &entry.grant
        && action == MEMBER_ACTION
    {
        context["grant"] = grant.credential.get("id").cloned().unwrap_or(Value::Null);
    }
    if let Some(label) = &entry.label {
        context["name"] = json!(label);
    }
    Some(Record {
        entity_id: entry.did.clone(),
        action: action.to_string(),
        context,
    })
}

/// Every record the entries project to, by entity.
pub fn expected(
    entries: &[Entry],
    publish: Publish,
    framework: &Framework,
) -> BTreeMap<String, Record> {
    entries
        .iter()
        .filter_map(|e| record_for(e, publish, framework))
        .map(|r| (r.entity_id.clone(), r))
        .collect()
}

/// Why a write did not happen.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WriteError {
    /// This network cannot write to the registry at all (no transport). Not retried until
    /// the writer changes; reported.
    #[error("{0}")]
    Unsupported(String),
    /// The registry refused the write (for example, this network's DID is not in its
    /// `ADMIN_DIDS`). Retried by the next reconcile, and reported.
    #[error("the registry refused the write: {0}")]
    Refused(String),
    /// The registry could not be reached. Retried by the next reconcile.
    #[error("the registry could not be reached: {0}")]
    Unreachable(String),
}

/// A record already in the registry, under this network's authority.
#[derive(Debug, Clone, PartialEq)]
pub struct Held {
    pub entity_id: String,
    pub action: String,
    pub context: Value,
}

/// How records reach the registry.
#[async_trait]
pub trait RegistryWriter: Send + Sync {
    /// Put (create or replace) `record` under `authority`.
    async fn put(&self, authority: &str, record: &Record) -> Result<(), WriteError>;
    /// Delete the record for `entity_id` and `action` under `authority`. An absent record is
    /// success: its absence is what is wanted.
    async fn delete(
        &self,
        authority: &str,
        entity_id: &str,
        action: &str,
    ) -> Result<(), WriteError>;
    /// Every record under `authority` and [`RESOURCE`], or `None` when this writer cannot
    /// enumerate (the reconcile then uses its local mirror).
    async fn list(&self, authority: &str) -> Result<Option<Vec<Held>>, WriteError>;
    /// What this writer is, for operators.
    fn describe(&self) -> String;
}

/// The writer until this network speaks DIDComm or TSP to the registry: every write is
/// [`WriteError::Unsupported`], with what the operator needs to know.
pub struct NoWriteTransport;

const NO_TRANSPORT: &str = "the trust registry accepts record writes over DIDComm or TSP only, \
     and this network has no mediator session yet: the projection is computed and reported, \
     and nothing is written (docs/trust-registry.md, \"Writes\")";

#[async_trait]
impl RegistryWriter for NoWriteTransport {
    async fn put(&self, _: &str, _: &Record) -> Result<(), WriteError> {
        Err(WriteError::Unsupported(NO_TRANSPORT.into()))
    }
    async fn delete(&self, _: &str, _: &str, _: &str) -> Result<(), WriteError> {
        Err(WriteError::Unsupported(NO_TRANSPORT.into()))
    }
    async fn list(&self, _: &str) -> Result<Option<Vec<Held>>, WriteError> {
        Ok(None)
    }
    fn describe(&self) -> String {
        "none (no DIDComm or TSP session)".into()
    }
}

/// An in-memory registry, for tests: what was written, and failures on demand.
#[derive(Default)]
pub struct MockRegistry {
    records: Mutex<BTreeMap<(String, String, String), Value>>,
    failing: std::sync::atomic::AtomicBool,
    can_list: std::sync::atomic::AtomicBool,
}

impl MockRegistry {
    /// A mock that can list its records.
    pub fn listing() -> Self {
        let mock = Self::default();
        mock.can_list
            .store(true, std::sync::atomic::Ordering::SeqCst);
        mock
    }
    /// Make every write fail as unreachable (`true`), or succeed again.
    pub fn fail(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }
    /// The records under `authority`, as `(entity, action)`.
    pub async fn held(&self, authority: &str) -> Vec<(String, String)> {
        self.records
            .lock()
            .await
            .keys()
            .filter(|(a, _, _)| a == authority)
            .map(|(_, e, act)| (e.clone(), act.clone()))
            .collect()
    }
    /// Plant a record directly, as another writer (or an old run) left it.
    pub async fn plant(&self, authority: &str, entity: &str, action: &str) {
        self.records
            .lock()
            .await
            .insert((authority.into(), entity.into(), action.into()), json!({}));
    }
    fn check(&self) -> Result<(), WriteError> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            Err(WriteError::Unreachable("mock registry is down".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl RegistryWriter for MockRegistry {
    async fn put(&self, authority: &str, record: &Record) -> Result<(), WriteError> {
        self.check()?;
        self.records.lock().await.insert(
            (
                authority.into(),
                record.entity_id.clone(),
                record.action.clone(),
            ),
            record.trust_record(authority),
        );
        Ok(())
    }
    async fn delete(
        &self,
        authority: &str,
        entity_id: &str,
        action: &str,
    ) -> Result<(), WriteError> {
        self.check()?;
        self.records
            .lock()
            .await
            .remove(&(authority.into(), entity_id.into(), action.into()));
        Ok(())
    }
    async fn list(&self, authority: &str) -> Result<Option<Vec<Held>>, WriteError> {
        if !self.can_list.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        self.check()?;
        Ok(Some(
            self.records
                .lock()
                .await
                .iter()
                .filter(|((a, _, _), _)| a == authority)
                .map(|((_, e, act), v)| Held {
                    entity_id: e.clone(),
                    action: act.clone(),
                    context: v.get("context").cloned().unwrap_or(Value::Null),
                })
                .collect(),
        ))
    }
    fn describe(&self) -> String {
        "mock".into()
    }
}

/// The outcome of one reconcile.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub at: Option<DateTime<Utc>>,
    /// Records this network should have in the registry.
    pub expected: usize,
    /// Records written (created or replaced).
    pub put: Vec<String>,
    /// Records deleted, as `entity action`.
    pub deleted: Vec<String>,
    /// Writes that failed, as `entity: why`. Each is retried by the next reconcile.
    pub failed: Vec<String>,
    /// Why nothing could be written at all, when so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
}

const MIRROR_PREFIX: &str = "mirror:";
const LAST_REPORT: &str = "last";

/// Reconciles the projection against the registry.
pub struct Syncer {
    network: Arc<Network>,
    writer: Arc<dyn RegistryWriter>,
    config: RegistryConfig,
    state: KeyspaceHandle,
    running: Mutex<()>,
}

impl Syncer {
    pub fn new(
        network: Arc<Network>,
        writer: Arc<dyn RegistryWriter>,
        config: RegistryConfig,
    ) -> Self {
        let state = network.store.registry().clone();
        Self {
            network,
            writer,
            config,
            state,
            running: Mutex::new(()),
        }
    }

    pub fn writer(&self) -> &dyn RegistryWriter {
        self.writer.as_ref()
    }

    /// The last reconcile's report, if one ran.
    pub async fn last_report(&self) -> Result<Option<SyncReport>, AppError> {
        self.state.get(LAST_REPORT).await
    }

    /// Bring the registry into line with the entries: put what should exist, delete what
    /// should not.
    pub async fn reconcile(&self) -> Result<SyncReport, AppError> {
        let _one_at_a_time = self.running.lock().await;
        let authority = self.network.did().to_string();
        let entries = self.network.store.entries().await?;
        let want = expected(
            &entries,
            self.config.publish,
            &self.network.profile.framework,
        );
        let mut report = SyncReport {
            at: Some(Utc::now()),
            expected: want.len(),
            ..Default::default()
        };

        // What the registry holds: its own list when it can say, else what we wrote.
        let mirror: BTreeMap<String, Held> = self
            .state
            .prefix_iter_raw(MIRROR_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<MirrorRow>(&v).ok())
            .map(|m| {
                (
                    m.entity_id.clone(),
                    Held {
                        entity_id: m.entity_id,
                        action: m.action,
                        context: m.context,
                    },
                )
            })
            .collect();
        let held: Vec<Held> = match self.writer.list(&authority).await {
            Ok(Some(listed)) => listed,
            Ok(None) => mirror.values().cloned().collect(),
            Err(e) => {
                report.blocked = Some(e.to_string());
                self.save_report(&report).await?;
                return Ok(report);
            }
        };

        // Stale: held, but not wanted under the same action.
        for h in &held {
            let stale = want.get(&h.entity_id).is_none_or(|r| r.action != h.action);
            if !stale {
                continue;
            }
            match self
                .writer
                .delete(&authority, &h.entity_id, &h.action)
                .await
            {
                Ok(()) => {
                    self.state
                        .remove(format!("{MIRROR_PREFIX}{}", h.entity_id))
                        .await?;
                    tracing::info!(entity = %h.entity_id, action = %h.action, "registry record deleted");
                    report.deleted.push(format!("{} {}", h.entity_id, h.action));
                }
                Err(e) => {
                    if self.note_failure(&mut report, &h.entity_id, e) {
                        break;
                    }
                }
            }
        }
        if report.blocked.is_none() {
            let held_now: BTreeMap<&str, &Held> =
                held.iter().map(|h| (h.entity_id.as_str(), h)).collect();
            for record in want.values() {
                let current = held_now
                    .get(record.entity_id.as_str())
                    .is_some_and(|h| h.action == record.action && h.context == record.context);
                if current {
                    continue;
                }
                match self.writer.put(&authority, record).await {
                    Ok(()) => {
                        self.state
                            .insert(
                                format!("{MIRROR_PREFIX}{}", record.entity_id),
                                &MirrorRow {
                                    entity_id: record.entity_id.clone(),
                                    action: record.action.clone(),
                                    context: record.context.clone(),
                                    written_at: Utc::now(),
                                },
                            )
                            .await?;
                        tracing::info!(entity = %record.entity_id, action = %record.action, "registry record put");
                        report.put.push(record.entity_id.clone());
                    }
                    Err(e) => {
                        if self.note_failure(&mut report, &record.entity_id, e) {
                            break;
                        }
                    }
                }
            }
        }
        self.save_report(&report).await?;
        if report.blocked.is_some() || !report.failed.is_empty() {
            tracing::warn!(
                expected = report.expected,
                failed = report.failed.len(),
                blocked = report.blocked.as_deref().unwrap_or(""),
                "trust registry projection incomplete"
            );
        }
        Ok(report)
    }

    /// Record a failed write. Returns `true` when nothing else can be written either.
    fn note_failure(&self, report: &mut SyncReport, entity: &str, e: WriteError) -> bool {
        match e {
            WriteError::Unsupported(why) => {
                report.blocked = Some(why);
                true
            }
            other => {
                report.failed.push(format!("{entity}: {other}"));
                false
            }
        }
    }

    async fn save_report(&self, report: &SyncReport) -> Result<(), AppError> {
        self.state.insert(LAST_REPORT, report).await
    }

    /// Reconcile at once, then whenever an entry changes (debounced) and every
    /// `sync_interval_secs`.
    pub fn spawn(self: Arc<Self>) {
        let nudge = self.network.registry_nudge.clone();
        let interval = Duration::from_secs(self.config.sync_interval_secs.max(60));
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.reconcile().await {
                    tracing::warn!(error = %e, "trust registry reconcile failed");
                }
                tokio::select! {
                    () = nudge.notified() => {
                        // Let a burst of changes settle into one reconcile.
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    () = tokio::time::sleep(interval) => {}
                }
            }
        });
    }
}

/// What was last written for one entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MirrorRow {
    entity_id: String,
    action: String,
    context: Value,
    written_at: DateTime<Utc>,
}

/// The `trustRegistry` member of the network profile (`/.well-known/vtn`): where a verifier
/// asks, and what to ask.
pub fn profile_json(config: &RegistryConfig, authority: &str) -> Value {
    json!({
        "did": config.did,
        "queryUrl": config.query_url,
        "authority": authority,
        "resource": RESOURCE,
        "actions": { "member": MEMBER_ACTION, "listed": LISTED_ACTION },
        "publishes": config.publish.as_str(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_https_url_has_an_origin() {
        assert_eq!(
            origin_of("https://registry.example.org/v1/x").as_deref(),
            Some("https://registry.example.org")
        );
        assert_eq!(
            origin_of("https://r.example:8443").as_deref(),
            Some("https://r.example:8443")
        );
        assert_eq!(origin_of("http://r.example"), None);
        assert_eq!(origin_of("https://"), None);
        assert_eq!(origin_of("https://a.example;b"), None);
    }
}
