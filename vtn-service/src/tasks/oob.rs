//! Browser sign-in: a wallet approves the landing page's key (`auth/oob/*`, A13).
//!
//! The landing page generates an Ed25519 key, `K_b`, and starts `auth/oob/request`. A
//! wallet scans the trigger link, proves its DID (`prove`) and signs a grant (`respond`).
//! The page then `redeem`s, and `K_b` may sign `vtn/*` reads **as the approver** until the
//! earlier of the grant's end and `[auth] browser_key_hours` (8 hours by default, at most
//! 24, A20). There is no session and no cookie: every request `K_b` signs is a Trust Task
//! like any other, read as the approver's ([`crate::tasks`]), so the approver's standing is
//! decided again each time.
//!
//! The check order, the records and every refusal are `vti_oob_server`'s, shared with the
//! VTC. What is the network's:
//!
//! - **Who may approve:** an administrator, or a member or listed community or network, as
//!   itself. Decided from local records only, before the DID is resolved (T15). A person
//!   with a member community's credential has no record here; they present it with each
//!   request instead.
//! - **What the key may sign** ([`SIGNING_SCOPE`]): reads of the published set. Nothing
//!   administrative: that stays with the NNM, signed by the administrator's own key.
//! - **What `redeem` issues:** a delegation of `K_b` to the approver, in the store.
//! - **Sign-out:** `auth/revoke-session` `{ all: true }`, signed by `K_b` itself (a
//!   delegation never covers `auth/*`), drops `K_b`'s delegation ([`revoke`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_oob_server::delegation::{self, AlwaysLive, Delegation};
use vti_oob_server::{
    Approved, Audience, Completion, Eligibility, Gate, OobHost, SESSION_EXT, SignInEvent,
};
use vti_trust_task_server::AcceptedIdStore;
use vti_vtn::verify::{ASSERTION_METHOD, AUTHENTICATION, verify_document};

use crate::routes::AppState;

/// The `vtn/*` task families a wallet-approved browser key signs for as its approver: the
/// reads of the published set.
pub const SIGNING_SCOPE: &[&str] = &[
    "vtn/directory",
    "vtn/graph",
    "vtn/entries",
    "vtn/roles",
    "vtn/rooms/list",
];

/// A network has one kind of sign-in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reader {
    #[default]
    Reader,
}

impl Audience for Reader {
    fn from_ext(ext: Option<&Value>) -> Result<Self, String> {
        match ext.and_then(|e| e.get(SESSION_EXT)) {
            None => Ok(Reader::Reader),
            Some(_) => Err("this network offers one kind of sign-in; send no session ext".into()),
        }
    }

    fn to_ext(self) -> Option<Value> {
        None
    }
}

/// The network as an `auth/oob` host.
pub struct VtnOobHost<'a> {
    pub state: &'a AppState,
}

/// The approver `signer` (a browser key) signs `type_uri` for, if a live delegation covers
/// it.
pub async fn delegated_approver(
    state: &AppState,
    signer: &str,
    type_uri: &str,
) -> Result<Option<String>, AppError> {
    if !vti_oob_server::is_ed25519_did_key(signer) {
        return Ok(None);
    }
    Ok(
        delegation::armed::<Delegation, _>(
            state.network.store.oob(),
            signer,
            type_uri,
            &AlwaysLive,
        )
        .await?
        .map(|d| d.approver_did),
    )
}

/// `auth/revoke-session/0.2`: how the landing page signs out.
pub use vti_specs_core::auth::revoke_session::v0_2::Payload as RevokeSession;

/// Sign `key` out: drop the delegation it holds. `all`, or `subject` naming the key itself,
/// targets it. Anything else names no session this network holds for the key, and revokes
/// nothing (`revokedCount: 0`, which the task allows in place of `sessionNotFound`).
/// Returns how many delegations went: 0 or 1.
pub async fn revoke(
    state: &AppState,
    key: &str,
    p: &RevokeSession,
) -> Result<u64, crate::error::ApiError> {
    if p.all == Some(false) {
        return Err(crate::error::ApiError::BadRequest(
            "`all: false` targets nothing".into(),
        ));
    }
    let own = p.all == Some(true) || p.subject.as_ref().is_some_and(|s| s.as_str() == key);
    if !own || !vti_oob_server::is_ed25519_did_key(key) {
        return Ok(0);
    }
    let records = state.network.store.oob();
    let at = delegation::delegation_key(key);
    if records.get_raw(at.clone()).await?.is_none() {
        return Ok(0);
    }
    records.remove(at).await?;
    tracing::info!(key, reason = ?p.reason.as_deref(), "browser key signed out");
    Ok(1)
}

/// Drop ended sign-in requests past their retention. Returns how many went.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    vti_oob_server::sweep::<Reader>(state.network.store.oob()).await
}

impl VtnOobHost<'_> {
    /// An administrator, or a party listed here (as itself).
    async fn known(&self, did: &str) -> Result<bool, AppError> {
        if self.state.auth.is_admin(did) {
            return Ok(true);
        }
        Ok(self.state.network.store.entry(did).await?.is_some_and(|e| {
            e.state.is_membership() || e.state == vti_vtn::model::EntryState::Listed
        }))
    }

    fn verify(
        &self,
        received: &Value,
        purpose: &str,
    ) -> impl Future<Output = Result<String, AppError>> {
        let resolver = self.state.network.resolver.clone();
        let received = received.clone();
        let purpose = purpose.to_string();
        async move {
            let issuer = received
                .get("issuer")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Unauthorized("a carried document names no issuer".into()))?
                .to_string();
            verify_document(&received, &issuer, &purpose, resolver.as_ref())
                .await
                .map_err(|e| AppError::Unauthorized(format!("carried document proof: {e}")))?;
            Ok(issuer)
        }
    }
}

#[async_trait::async_trait]
impl OobHost for VtnOobHost<'_> {
    type Audience = Reader;

    fn records(&self) -> &KeyspaceHandle {
        self.state.network.store.oob()
    }

    async fn service_did(&self) -> Option<String> {
        Some(self.state.network.did().to_string())
    }

    async fn public_url(&self) -> Option<String> {
        Some(self.state.network.base_url.clone())
    }

    async fn service_name(&self) -> Option<String> {
        Some(self.state.network.profile.name.clone()).filter(|n| !n.is_empty())
    }

    async fn sign_step(&self, response: &mut Value) -> Result<(), String> {
        let signed = self
            .state
            .network
            .identity
            .sign_document_for(std::mem::take(response), ASSERTION_METHOD)
            .await
            .map_err(|e| e.to_string())?;
        *response = signed;
        Ok(())
    }

    async fn verify_authentication(&self, received: &Value) -> Result<String, AppError> {
        self.verify(received, AUTHENTICATION).await
    }

    async fn verify_assertion(
        &self,
        received: &Value,
        _type_uri: &str,
    ) -> Result<String, AppError> {
        self.verify(received, ASSERTION_METHOD).await
    }

    fn accepted_ids(&self) -> &dyn AcceptedIdStore {
        &self.state.accepted
    }

    async fn gate(&self, _gate: Gate, _: Reader, did: &str) -> Result<Eligibility, AppError> {
        Ok(if self.known(did).await? {
            Eligibility::Eligible
        } else {
            Eligibility::Refused {
                reason: "neither an administrator nor a party listed here".into(),
            }
        })
    }

    fn signing_scope(&self, _: Reader) -> Option<Vec<String>> {
        Some(SIGNING_SCOPE.iter().map(|s| s.to_string()).collect())
    }

    async fn audit(&self, event: SignInEvent<'_, Reader>) {
        tracing::info!(
            stage = event.stage,
            request_id = %event.record.request_id,
            approver = event.member,
            reason = event.reason,
            "browser sign-in"
        );
    }

    async fn complete(&self, approved: Approved<'_, Reader>) -> Result<Completion, AppError> {
        // Re-checked now: a party removed since it approved gets nothing (T18).
        if !self.known(approved.subject).await? {
            return Ok(Completion::NotAuthorized);
        }
        let Some(scope) = approved.signing_scope() else {
            return Ok(Completion::NotAuthorized);
        };
        let cap = now_epoch() + self.state.sign_in.browser_key_hours.min(24) * 3600;
        let not_after = approved.not_after.min(cap);
        delegation::record(
            self.records(),
            &approved.record.start_key,
            &Delegation {
                approver_did: approved.subject.to_string(),
                scope,
                not_after,
                grant_id: approved.grant_id(),
            },
        )
        .await?;
        let display_name = match self.state.network.store.entry(approved.subject).await? {
            Some(entry) => entry.label.unwrap_or_else(|| approved.subject.to_string()),
            None => approved.subject.to_string(),
        };
        tracing::info!(
            approver = approved.subject,
            not_after,
            "browser key delegated"
        );
        Ok(Completion::Issued {
            display_name,
            ends_at: not_after,
        })
    }
}
