//! Persistence. Keyspaces:
//!
//! | keyspace | key | value |
//! |---|---|---|
//! | `entries` | entry DID | [`Entry`] |
//! | `status` | `revocation` / `suspension` / `next` | [`Bitstring`] / `u32` |
//! | `credentials` | credential `id` | entry DID |
//! | `audit` | `<rfc3339>:<uuid>` | [`AuditEvent`] |
//! | `groups` | `<member DID>\u{0}<role>` | [`RegisteredGroup`] |
//! | `memberships` | parent network DID | [`Membership`](crate::memberships::Membership) |
//! | `broadcasts` | message id | [`BroadcastRecord`](crate::broadcast::BroadcastRecord) |
//! | `relay_seen` | message id | first-seen time |
//! | `outbox` | `<message id>\u{0}<group>` | [`OutboxItem`](crate::broadcast::OutboxItem) |
//! | `accepted_ids` | Trust Task document `id` | [`AcceptedId`](crate::tasks::accepted::AcceptedId) |
//! | `oob` | `oob_req:<request id>`, `delegation:<browser key>` | `auth/oob` sign-in requests and the delegations `redeem` arms (`vti_oob_server`) |

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};
use vti_vtn::groups::RegisteredGroup;
use vti_vtn::lifecycle::Event;
use vti_vtn::model::{Entry, EntryState, StatusIndex};
use vti_vtn::status::{Bitstring, LIST_BITS, Purpose};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub did: String,
    pub event: Event,
    pub to: EntryState,
    /// `admin` for network-side actions, the party's DID for its own.
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct VtnStore {
    entries: KeyspaceHandle,
    status: KeyspaceHandle,
    credentials: KeyspaceHandle,
    audit: KeyspaceHandle,
    groups: KeyspaceHandle,
    memberships: KeyspaceHandle,
    broadcasts: KeyspaceHandle,
    relay_seen: KeyspaceHandle,
    outbox: KeyspaceHandle,
    accepted_ids: KeyspaceHandle,
    oob: KeyspaceHandle,
}

const NEXT_INDEX: &str = "next";

impl VtnStore {
    pub fn open(dir: &Path) -> Result<Self, AppError> {
        let store = Store::open(&StoreConfig {
            data_dir: dir.to_path_buf(),
        })?;
        Ok(Self {
            entries: store.keyspace("entries")?,
            status: store.keyspace("status")?,
            credentials: store.keyspace("credentials")?,
            audit: store.keyspace("audit")?,
            groups: store.keyspace("groups")?,
            memberships: store.keyspace("memberships")?,
            broadcasts: store.keyspace("broadcasts")?,
            relay_seen: store.keyspace("relay_seen")?,
            outbox: store.keyspace("outbox")?,
            accepted_ids: store.keyspace("accepted_ids")?,
            oob: store.keyspace("oob")?,
        })
    }

    pub async fn entry(&self, did: &str) -> Result<Option<Entry>, AppError> {
        self.entries.get(did).await
    }

    pub async fn put_entry(&self, entry: &Entry) -> Result<(), AppError> {
        self.entries.insert(entry.did.as_str(), entry).await
    }

    pub async fn entries(&self) -> Result<Vec<Entry>, AppError> {
        self.entries
            .prefix_iter_raw(Vec::new())
            .await?
            .into_iter()
            .map(|(_, v)| serde_json::from_slice(&v).map_err(AppError::from))
            .collect()
    }

    /// Allocate the next status-list index. Callers hold the network's write lock.
    pub async fn allocate_status_index(&self) -> Result<StatusIndex, AppError> {
        let next: u32 = self.status.get(NEXT_INDEX).await?.unwrap_or(0);
        if next as usize >= LIST_BITS {
            return Err(AppError::Internal("status list is full".into()));
        }
        self.status.insert(NEXT_INDEX, &(next + 1)).await?;
        Ok(next)
    }

    pub async fn status_list(&self, purpose: Purpose) -> Result<Bitstring, AppError> {
        Ok(self.status.get(purpose.as_str()).await?.unwrap_or_default())
    }

    pub async fn set_status(
        &self,
        purpose: Purpose,
        index: StatusIndex,
        value: bool,
    ) -> Result<(), AppError> {
        let mut bits = self.status_list(purpose).await?;
        bits.set(index, value)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        self.status.insert(purpose.as_str(), &bits).await
    }

    pub async fn index_credential(&self, id: &str, did: &str) -> Result<(), AppError> {
        self.credentials.insert(id, &did.to_string()).await
    }

    pub async fn credential_owner(&self, id: &str) -> Result<Option<String>, AppError> {
        self.credentials.get(id).await
    }

    pub async fn append_audit(&self, event: &AuditEvent) -> Result<(), AppError> {
        let key = format!("{}:{}", event.at.to_rfc3339(), uuid::Uuid::new_v4());
        self.audit.insert(key, event).await
    }

    pub async fn audit(&self) -> Result<Vec<AuditEvent>, AppError> {
        self.audit
            .prefix_iter_raw(Vec::new())
            .await?
            .into_iter()
            .map(|(_, v)| serde_json::from_slice(&v).map_err(AppError::from))
            .collect()
    }

    // ------------------------------------------------------------- groups

    fn group_key(member: &str, role: &str) -> Vec<u8> {
        let mut key = member.as_bytes().to_vec();
        key.push(0);
        key.extend_from_slice(role.as_bytes());
        key
    }

    pub async fn put_group(&self, group: &RegisteredGroup) -> Result<(), AppError> {
        self.groups
            .insert(Self::group_key(&group.member, &group.role), group)
            .await
    }

    pub async fn group(
        &self,
        member: &str,
        role: &str,
    ) -> Result<Option<RegisteredGroup>, AppError> {
        self.groups.get(Self::group_key(member, role)).await
    }

    pub async fn remove_group(&self, member: &str, role: &str) -> Result<(), AppError> {
        self.groups.remove(Self::group_key(member, role)).await
    }

    pub async fn groups(&self) -> Result<Vec<RegisteredGroup>, AppError> {
        all(&self.groups, Vec::new()).await
    }

    pub async fn groups_of(&self, member: &str) -> Result<Vec<RegisteredGroup>, AppError> {
        let mut prefix = member.as_bytes().to_vec();
        prefix.push(0);
        all(&self.groups, prefix).await
    }

    // -------------------------------------------------------- memberships

    pub async fn put_membership<V: serde::Serialize>(
        &self,
        parent: &str,
        m: &V,
    ) -> Result<(), AppError> {
        self.memberships.insert(parent, m).await
    }

    pub async fn membership<V: DeserializeOwned + Send + 'static>(
        &self,
        parent: &str,
    ) -> Result<Option<V>, AppError> {
        self.memberships.get(parent).await
    }

    pub async fn memberships<V: DeserializeOwned>(&self) -> Result<Vec<V>, AppError> {
        all(&self.memberships, Vec::new()).await
    }

    // --------------------------------------------------------- broadcasts

    pub async fn put_broadcast<V: serde::Serialize>(
        &self,
        id: &str,
        record: &V,
    ) -> Result<(), AppError> {
        self.broadcasts.insert(id, record).await
    }

    pub async fn broadcast<V: DeserializeOwned + Send + 'static>(
        &self,
        id: &str,
    ) -> Result<Option<V>, AppError> {
        self.broadcasts.get(id).await
    }

    pub async fn broadcasts<V: DeserializeOwned>(&self) -> Result<Vec<V>, AppError> {
        all(&self.broadcasts, Vec::new()).await
    }

    fn outbox_key(message: &str, group: &str) -> Vec<u8> {
        let mut key = message.as_bytes().to_vec();
        key.push(0);
        key.extend_from_slice(group.as_bytes());
        key
    }

    pub async fn put_outbox<V: serde::Serialize>(
        &self,
        message: &str,
        group: &str,
        item: &V,
    ) -> Result<(), AppError> {
        self.outbox
            .insert(Self::outbox_key(message, group), item)
            .await
    }

    pub async fn remove_outbox(&self, message: &str, group: &str) -> Result<(), AppError> {
        self.outbox.remove(Self::outbox_key(message, group)).await
    }

    pub async fn outbox<V: DeserializeOwned>(&self) -> Result<Vec<V>, AppError> {
        all(&self.outbox, Vec::new()).await
    }

    /// Record `id` as seen. `false` if it had been seen already.
    pub async fn first_sighting(&self, id: &str) -> Result<bool, AppError> {
        self.relay_seen
            .insert_if_absent(id, &chrono::Utc::now())
            .await
    }

    /// The accepted-document-id record (`crate::tasks::accepted`).
    pub fn accepted_ids(&self) -> &KeyspaceHandle {
        &self.accepted_ids
    }

    /// Browser sign-in requests and the delegations they arm (`crate::tasks::oob`).
    pub fn oob(&self) -> &KeyspaceHandle {
        &self.oob
    }
}

async fn all<V: DeserializeOwned>(
    ks: &KeyspaceHandle,
    prefix: Vec<u8>,
) -> Result<Vec<V>, AppError> {
    ks.prefix_iter_raw(prefix)
        .await?
        .into_iter()
        .map(|(_, v)| serde_json::from_slice(&v).map_err(AppError::from))
        .collect()
}
