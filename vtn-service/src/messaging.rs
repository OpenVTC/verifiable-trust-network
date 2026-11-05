//! The network's mediator session: DIDComm through its mediator, for what the network
//! *sends* (`[messaging]`, `docs/trust-registry.md`).
//!
//! The session is `vti_common::host_session`'s, the one the witness and the ballot box run:
//! one socket per DID, the reconnect supervisor, and a [`Requester`] that sends a signed
//! Trust Task to a DID and waits for its answer. Today the network sends only its
//! trust-registry records ([`crate::registry::MessagingWriter`]). Its API stays HTTPS
//! (`POST /v1/trust-tasks`): a Trust Task that arrives over DIDComm is not answered.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::Value;
use tokio::sync::watch;
use vti_common::host_session::{IdentitySession, Responder, Shared, supervise_reporting};

pub use vti_common::host_session::{RequestError, Requester};

/// Sends a signed Trust Task to a DID and returns its answer: the session's [`Requester`],
/// or a test double.
#[async_trait::async_trait]
pub trait Exchange: Send + Sync {
    async fn request(
        &self,
        peer: &str,
        document: Value,
        timeout: std::time::Duration,
    ) -> Result<Value, RequestError>;
    fn is_connected(&self) -> bool;
}

#[async_trait::async_trait]
impl Exchange for Requester {
    async fn request(
        &self,
        peer: &str,
        document: Value,
        timeout: std::time::Duration,
    ) -> Result<Value, RequestError> {
        Requester::request(self, peer, document, timeout).await
    }
    fn is_connected(&self) -> bool {
        Requester::is_connected(self)
    }
}

use crate::config::MessagingConfig;

/// The network as a session responder: it answers nothing over DIDComm.
struct Silent {
    did: String,
}

#[async_trait::async_trait]
impl Responder for Silent {
    fn name(&self) -> &str {
        "vtn"
    }
    fn did(&self) -> &str {
        &self.did
    }
    async fn answer(&self, sender: &str, _document: &[u8]) -> Option<Value> {
        tracing::debug!(%sender, "a Trust Task over DIDComm is not answered: the network's API is POST /v1/trust-tasks");
        None
    }
}

/// A running session: send through `requester`; `connected` is whether the mediator holds
/// the socket right now.
pub struct Session {
    pub requester: Requester,
    pub connected: watch::Receiver<bool>,
    pub task: tokio::task::JoinHandle<()>,
}

/// Start the network's session as `did`, with its `secrets`, until `shutdown`.
pub async fn start(
    did: &str,
    secrets: Vec<Secret>,
    config: &MessagingConfig,
    resolver_url: Option<&str>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<Session> {
    let did_resolver = DIDCacheClient::new(vta_sdk::resolver::build_verifier_did_cache_config(
        resolver_url,
        300,
        1_000,
    ))
    .await
    .map_err(|e| anyhow::anyhow!("build the DID resolver: {e}"))?;
    let shared = Arc::new(Shared {
        did_resolver,
        resolver_url: resolver_url.map(str::to_string),
    });
    let requester = Requester::new();
    let session = IdentitySession::new(
        Arc::new(Silent {
            did: did.to_string(),
        }),
        config.mediator_did.clone(),
        secrets,
    )
    .with_requester(requester.clone());
    let (connected_tx, connected) = watch::channel(false);
    let task = tokio::spawn(supervise_reporting(session, shared, shutdown, connected_tx));
    Ok(Session {
        requester,
        connected,
        task,
    })
}
