//! Persistence. Keyspaces:
//!
//! | keyspace | key | value |
//! |---|---|---|
//! | `entries` | entry DID | [`Entry`] |
//! | `status` | `revocation` / `suspension` / `next` | [`Bitstring`] / `u32` |
//! | `credentials` | credential `id` | entry DID |
//! | `audit` | `<rfc3339>:<uuid>` | [`AuditEvent`] |

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};
use vtn_core::lifecycle::Event;
use vtn_core::model::{Entry, EntryState, StatusIndex};
use vtn_core::status::{Bitstring, LIST_BITS, Purpose};

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
}
