//! The accepted-document-id record (VTI-OPS-025…027, SPEC §7.2 item 11), in the store.
//!
//! A document `id` accepted for execution is recorded with the digest of the document, so the
//! same document again is a duplicate (answered with the first response) and a different one
//! under that `id` is an `idConflict`. The record is in the store, not memory, so a restart
//! inside a document's acceptance window does not let it execute twice.
//!
//! One process serves every binding this network has (HTTPS), and claims are serialised by a
//! lock, so a claim is a check and a write with no gap between them.

use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use trust_tasks_rs::TrustTask;
use vti_common::store::KeyspaceHandle;
use vti_trust_task_server::accepted::FALLBACK_RETENTION_SECS;
use vti_trust_task_server::{Acceptance, AcceptedIdStore, AcceptedIdsError, Claim, ClaimSettle};

/// One accepted document.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedId {
    digest: String,
    retain_until: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    completed: bool,
}

#[derive(Clone)]
pub struct StoreAcceptedIds {
    records: KeyspaceHandle,
    lock: Arc<Mutex<()>>,
}

impl StoreAcceptedIds {
    pub fn new(records: KeyspaceHandle) -> Self {
        Self {
            records,
            lock: Arc::default(),
        }
    }

    /// Drop every record past its retention. Returns how many went.
    pub async fn prune(&self, now: DateTime<Utc>) -> Result<usize, vti_common::error::AppError> {
        let _guard = self.lock.lock().await;
        let mut dropped = 0;
        for (key, bytes) in self.records.prefix_iter_raw(Vec::new()).await? {
            let expired = serde_json::from_slice::<AcceptedId>(&bytes)
                .map(|r| r.retain_until <= now)
                .unwrap_or(true);
            if expired {
                self.records.remove(key).await?;
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}

fn unavailable(e: impl std::fmt::Display) -> AcceptedIdsError {
    tracing::error!(error = %e, "the accepted-id record is unavailable");
    AcceptedIdsError::Unavailable
}

#[async_trait::async_trait]
impl AcceptedIdStore for StoreAcceptedIds {
    async fn claim(
        &self,
        doc: &TrustTask<Value>,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AcceptedIdsError> {
        let digest = trust_tasks_rs::document_digest(doc)
            .map_err(|e| AcceptedIdsError::NotDigestible(e.to_string()))?
            .as_str()
            .to_string();
        let retain_until =
            retain_until.unwrap_or_else(|| now + TimeDelta::seconds(FALLBACK_RETENTION_SECS));
        let _guard = self.lock.lock().await;
        let existing: Option<AcceptedId> = self
            .records
            .get(doc.id.as_str())
            .await
            .map_err(unavailable)?;
        if let Some(existing) = existing.filter(|r| r.retain_until > now) {
            return Ok(if existing.digest == digest {
                Acceptance::Duplicate {
                    prior_response: existing.response,
                    in_flight: !existing.completed,
                }
            } else {
                Acceptance::Conflict
            });
        }
        let record = AcceptedId {
            digest: digest.clone(),
            retain_until,
            response: None,
            completed: false,
        };
        self.records
            .insert(doc.id.as_str(), &record)
            .await
            .map_err(unavailable)?;
        Ok(Acceptance::Fresh(Claim::new(StoreClaim {
            store: self.clone(),
            id: doc.id.clone(),
            digest,
        })))
    }
}

struct StoreClaim {
    store: StoreAcceptedIds,
    id: String,
    digest: String,
}

impl StoreClaim {
    async fn mine(&self) -> Option<AcceptedId> {
        match self.store.records.get::<AcceptedId>(self.id.as_str()).await {
            Ok(Some(r)) if r.digest == self.digest => Some(r),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(id = %self.id, error = %e, "reading the accepted-id record");
                None
            }
        }
    }
}

#[async_trait::async_trait]
impl ClaimSettle for StoreClaim {
    async fn completed(self: Box<Self>, response: Option<&Value>) {
        let _guard = self.store.lock.lock().await;
        if let Some(mut record) = self.mine().await {
            record.response = response.cloned();
            record.completed = true;
            if let Err(e) = self.store.records.insert(self.id.as_str(), &record).await {
                tracing::error!(id = %self.id, error = %e, "recording a completed document");
            }
        }
    }

    async fn release(self: Box<Self>) {
        let _guard = self.store.lock.lock().await;
        if self.mine().await.is_some_and(|r| !r.completed)
            && let Err(e) = self.store.records.remove(self.id.as_str()).await
        {
            tracing::error!(id = %self.id, error = %e, "releasing a document id");
        }
    }
}
