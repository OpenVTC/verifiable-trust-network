//! The network's API: `vtn/*` Trust Tasks (trusttasks.org, `vtn/*/0.1`) at
//! `POST /v1/trust-tasks` (`docs/trust-tasks.md`).
//!
//! Every document goes through the shared receive pipeline (`vti_trust_task_server`): size,
//! freshness (the 10-minute VTI acceptance window), recipient (this network), the task's own
//! specification policy, the proof (made for `authentication` by the document's `issuer`),
//! the duplicate-id record ([`accepted`]), then [`VtnTasks::dispatch`]. Every answer is
//! signed by this network.
//!
//! The proof's signer is the caller ([`crate::auth`]); there are no sessions. Payloads are
//! held to their published schema on the way in, and responses on the way out ([`wire`]).
//! A Trust Task answer is never evidence of a relationship: the credentials it carries are
//! (A19).

pub mod accepted;
pub mod oob;
pub mod wire;

use std::future::Future;
use std::sync::Arc;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, RequestPayload, SpecPolicy, TrustTask};
use vti_common::error::AppError;
use vti_specs_vtn::vtn as specs;
use vti_trust_task_server::http::TrustTaskService;
use vti_trust_task_server::reject::{
    app_error_to_reject, extended_code, parse_payload, reject_with, reject_with_code,
    unsupported_type_or_version,
};
use vti_trust_task_server::typed::{parse_spec_payload, respond};
use vti_trust_task_server::{
    ArrivalCtx, BoxFuture, Dispatcher, ProofVerifier, ResponseSigner, Spine, SpineHooks,
    TrustTaskOutcome,
};
use vti_vtn::VtnError;
use vti_vtn::directory::DirectoryQuery;
use vti_vtn::index::IndexEntry;
use vti_vtn::model::{EntryKind, EntryProfile, EntryState};
use vti_vtn::relay::{Envelope, Outgoing};
use vti_vtn::rooms::ChainLink;
use vti_vtn::verify::{AUTHENTICATION, KeyResolver, verify_document};

use crate::auth::{Standing, can_read_directory};
use crate::error::{ApiError, ApiResult};
use crate::memberships::RoleMapping;
use crate::routes::AppState;
use accepted::StoreAcceptedIds;

/// Where every `vtn/*` Type URI starts.
const SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// The `vtn/*` Trust Task service: the pieces the shared spine runs with.
pub struct VtnTasks {
    state: AppState,
    verifier: DocumentVerifier,
    accepted: StoreAcceptedIds,
    policy: fn(&str) -> Option<SpecPolicy>,
}

impl VtnTasks {
    pub fn new(state: AppState) -> Self {
        Self {
            verifier: DocumentVerifier {
                resolver: state.network.resolver.clone(),
            },
            accepted: state.accepted.clone(),
            policy: spec_policy_for,
            state,
        }
    }
}

/// The policy each served specification declares: the `vtn/*` family, and `auth/oob/*`
/// (`vti-specs-core`) for browser sign-in.
fn spec_policy_for(type_uri: &str) -> Option<SpecPolicy> {
    vti_specs_vtn::schema_index::spec_policy_for(type_uri)
        .or_else(|| vti_specs_core::schema_index::spec_policy_for(type_uri))
}

impl TrustTaskService for VtnTasks {
    fn spine(&self) -> Spine<'_> {
        Spine::new(&self.policy, &self.verifier, self, &self.accepted, self).with_signer(Some(self))
    }
}

/// Verifies a document's proof with the network's resolver: made by its `issuer`, for
/// `authentication`, over the document as received.
struct DocumentVerifier {
    resolver: Arc<dyn KeyResolver>,
}

#[async_trait::async_trait]
impl ProofVerifier for DocumentVerifier {
    async fn verify(&self, received: &Value, _type_uri: &str) -> Result<String, AppError> {
        let issuer = received
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::Unauthorized("a signed document names no issuer".into()))?;
        verify_document(received, issuer, AUTHENTICATION, self.resolver.as_ref())
            .await
            .map_err(|e| AppError::Unauthorized(format!("Trust Task proof: {e}")))?;
        Ok(issuer.to_string())
    }
}

#[async_trait::async_trait]
impl SpineHooks for VtnTasks {
    async fn recipient(&self) -> Option<String> {
        Some(self.state.network.did().to_string())
    }

    /// `auth/oob/*` is signed by keys made for the exchange: an Ed25519 `did:key`, decided
    /// from the identifier before any proof is read (T21).
    async fn before_proof(
        &self,
        doc: &TrustTask<Value>,
        type_uri: &str,
    ) -> Option<TrustTaskOutcome> {
        vti_oob_server::precheck(doc, type_uri)
    }
}

#[async_trait::async_trait]
impl ResponseSigner for VtnTasks {
    async fn sign_response_document(&self, doc: &mut Value) -> Result<(), AppError> {
        let signed = self
            .state
            .network
            .identity
            .sign_document_for(std::mem::take(doc), AUTHENTICATION)
            .await
            .map_err(|e| AppError::Internal(format!("sign the response: {e}")))?;
        *doc = signed;
        Ok(())
    }
}

impl Dispatcher for VtnTasks {
    fn dispatch<'a>(
        &'a self,
        ctx: &'a ArrivalCtx,
        doc: TrustTask<Value>,
        type_uri: &'a str,
        received: Arc<Value>,
    ) -> BoxFuture<'a, TrustTaskOutcome> {
        Box::pin(async move {
            if vti_oob_server::URIS.contains(&type_uri) {
                let host = oob::VtnOobHost { state: &self.state };
                let signer = ctx.verified_signer.clone().unwrap_or_default();
                if let Some(outcome) =
                    vti_oob_server::dispatch(&host, doc.clone(), type_uri, signer).await
                {
                    return outcome;
                }
            }
            // A browser key a wallet approved signs as its approver, for the reads its
            // delegation covers (`oob::SIGNING_SCOPE`); otherwise the signer is itself.
            let signer = match ctx.verified_signer.as_deref() {
                Some(key) => match oob::delegated_approver(&self.state, key, type_uri).await {
                    Ok(Some(approver)) => Some(approver),
                    Ok(None) => Some(key.to_string()),
                    Err(e) => return refuse(&doc, type_uri, ApiError::Store(e)),
                },
                None => None,
            };
            let call = Call {
                state: &self.state,
                signer,
                received,
            };
            route(&call, &doc, type_uri).await
        })
    }
}

/// One request: who signed it, and the document as it arrived.
struct Call<'a> {
    state: &'a AppState,
    signer: Option<String>,
    received: Arc<Value>,
}

/// Run a handler for task `P`: the payload is held to its schema and read as `L`; the
/// handler's answer is held to `P`'s response schema.
async fn run<P, L, F, Fut>(doc: &TrustTask<Value>, handler: F) -> TrustTaskOutcome
where
    P: RequestPayload + DeserializeOwned,
    P::Response: DeserializeOwned + serde::Serialize,
    L: DeserializeOwned,
    F: FnOnce(L) -> Fut,
    Fut: Future<Output = ApiResult<Value>>,
{
    if let Err(refused) = parse_spec_payload::<P>(doc) {
        return refused;
    }
    let payload: L = match parse_payload(doc) {
        Ok(p) => p,
        Err(refused) => return refused,
    };
    match handler(payload).await {
        Ok(body) => respond::<P::Response>(doc, body),
        Err(e) => refuse(doc, P::TYPE_URI, e),
    }
}

/// `vtn/listings/create` from its Type URI.
fn slug(type_uri: &str) -> &str {
    let path = type_uri.strip_prefix(SPEC_PREFIX).unwrap_or(type_uri);
    path.rsplit_once('/').map_or(path, |(family, _)| family)
}

/// Whether `type_uri`'s specification declares `<slug>:<local>`.
fn declares(type_uri: &str, local: &str) -> bool {
    let code = format!("{}:{local}", slug(type_uri));
    vti_specs_vtn::schema_index::error_codes_for(type_uri)
        .is_some_and(|codes| codes.iter().any(|c| c.code == code))
}

/// An error as the task's refusal.
///
/// A code the handler raises that the task does not declare goes out as `taskFailed` with
/// the code as its reason: never a code the specification does not name.
fn refuse(doc: &TrustTask<Value>, type_uri: &str, err: ApiError) -> TrustTaskOutcome {
    let coded = |local: &str, message: String, details: Option<Value>| {
        if declares(type_uri, local) {
            return reject_with_code(
                doc,
                extended_code(&format!("{}:{local}", slug(type_uri))),
                message,
                details,
            );
        }
        tracing::warn!(type_uri, local, "a refusal code the task does not declare");
        reject_with(
            doc,
            RejectReason::TaskFailed {
                reason: message,
                details: Some(json!({ "reason": local })),
            },
        )
    };
    let failed = |reason: &str, message: String| {
        reject_with(
            doc,
            RejectReason::TaskFailed {
                reason: message,
                details: Some(json!({ "reason": reason })),
            },
        )
    };
    match err {
        ApiError::Coded {
            local,
            message,
            details,
        } => coded(local, message, details),
        ApiError::Vtn(e @ VtnError::InvalidTransition { .. }) => {
            if declares(type_uri, "invalidTransition") {
                coded("invalidTransition", e.to_string(), None)
            } else {
                failed("conflict", e.to_string())
            }
        }
        ApiError::Upstream(message) => {
            if declares(type_uri, "networkRefused") {
                coded("networkRefused", message, None)
            } else {
                failed("upstream", message)
            }
        }
        ApiError::NotFound(m) => app_error_to_reject(doc, &AppError::NotFound(m)),
        e @ (ApiError::Unauthorized | ApiError::Forbidden) => reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: e.to_string(),
            },
        ),
        ApiError::BadRequest(m) => reject_with(doc, RejectReason::MalformedRequest { reason: m }),
        ApiError::Vtn(e @ VtnError::InvalidDid(_)) => reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: e.to_string(),
            },
        ),
        ApiError::Vtn(
            e @ (VtnError::Rejected(_) | VtnError::Credential(_) | VtnError::DataIntegrity(_)),
        ) => failed("rejected", e.to_string()),
        ApiError::Store(e) => app_error_to_reject(doc, &e),
        ApiError::Vtn(e) => app_error_to_reject(doc, &AppError::Internal(e.to_string())),
    }
}

async fn route(call: &Call<'_>, doc: &TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
    use specs::*;
    macro_rules! task {
        ($($module:path => $handler:ident),* $(,)?) => {
            $(
                if type_uri == <$module as trust_tasks_rs::Payload>::TYPE_URI {
                    return run::<$module, _, _, _>(doc, |p| call.$handler(p)).await;
                }
            )*
        };
    }
    task! {
        entries::show::v0_1::Payload => entries_show,
        membership::offer::v0_1::Payload => membership_offer,
        membership::acknowledge::v0_1::Payload => membership_acknowledge,
        membership::repudiate::v0_1::Payload => membership_repudiate,
        groups::register::v0_1::Payload => groups_register,
        relay::deliver::v0_1::Payload => relay_deliver,
        roles::list::v0_1::Payload => roles_list,
        rooms::list::v0_1::Payload => rooms_list,
        rooms::pass::v0_1::Payload => rooms_pass,
        directory::search::v0_1::Payload => directory_search,
        directory::federated::v0_1::Payload => directory_federated,
        directory::summary::v0_1::Payload => directory_summary,
        graph::show::v0_1::Payload => graph_show,
        graph::member::v0_1::Payload => graph_member,
        listings::create::v0_1::Payload => listings_create,
        listings::update::v0_1::Payload => listings_update,
        listings::suspend::v0_1::Payload => listings_suspend,
        listings::reinstate::v0_1::Payload => listings_reinstate,
        listings::remove::v0_1::Payload => listings_remove,
        listings::list::v0_1::Payload => listings_list,
        listings::show::v0_1::Payload => listings_show,
        audit::list::v0_1::Payload => audit_list,
        groups::list::v0_1::Payload => groups_list,
        broadcasts::send::v0_1::Payload => broadcasts_send,
        broadcasts::list::v0_1::Payload => broadcasts_list,
        broadcasts::show::v0_1::Payload => broadcasts_show,
        outbox::list::v0_1::Payload => outbox_list,
        outbox::retry::v0_1::Payload => outbox_retry,
        memberships::list::v0_1::Payload => memberships_list,
        memberships::join::v0_1::Payload => memberships_join,
        memberships::repudiate::v0_1::Payload => memberships_repudiate,
        memberships::leave::v0_1::Payload => memberships_leave,
        memberships::groups::add::v0_1::Payload => memberships_groups_add,
    }
    let served = vti_specs_vtn::schema_index::INDEX
        .iter()
        .map(|e| e.type_uri)
        .filter(|uri| !uri.contains('#'));
    unsupported_type_or_version(doc, type_uri, served, "network")
}

// ------------------------------------------------------------------- payloads

/// A read the directory's visibility governs, optionally with the reader's VMC.
#[derive(Deserialize)]
struct Read {
    #[serde(default)]
    membership: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidRead {
    did: String,
    #[serde(default)]
    membership: Option<Value>,
}

#[derive(Deserialize)]
struct Nothing {}

#[derive(Deserialize)]
struct Acknowledge {
    acknowledgement: Value,
}

#[derive(Deserialize)]
struct Repudiate {
    repudiation: Value,
}

#[derive(Deserialize)]
struct Register {
    role: String,
}

#[derive(Deserialize)]
struct Deliver {
    role: String,
    envelope: Envelope,
}

#[derive(Deserialize)]
struct Pass {
    room: String,
    membership: Value,
    #[serde(default)]
    chain: Vec<ChainLink>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Search {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    kind: Option<EntryKind>,
    #[serde(default)]
    state: Option<EntryState>,
    #[serde(default)]
    members_only: bool,
    #[serde(default)]
    membership: Option<Value>,
}

impl Search {
    fn query(&self) -> DirectoryQuery {
        DirectoryQuery {
            q: self.q.clone(),
            kind: self.kind,
            state: self.state,
            members_only: self.members_only,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphShow {
    #[serde(default)]
    include_exited: bool,
    #[serde(default)]
    membership: Option<Value>,
}

#[derive(Deserialize)]
struct Create {
    did: String,
    kind: EntryKind,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Update {
    did: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Transition {
    did: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct Did {
    did: String,
}

#[derive(Deserialize)]
struct ListEntries {
    #[serde(default)]
    state: Option<EntryState>,
}

#[derive(Deserialize)]
struct Audit {
    #[serde(default)]
    did: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct Role {
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendBroadcast {
    role: String,
    #[serde(default)]
    class: Option<String>,
    subject: String,
    body: String,
    #[serde(default)]
    reply_to: Option<String>,
}

#[derive(Deserialize)]
struct Limit {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct Id {
    id: String,
}

#[derive(Deserialize)]
struct Join {
    url: String,
    network: String,
    roles: Vec<RoleMapping>,
}

#[derive(Deserialize)]
struct UpstreamRepudiate {
    url: String,
    network: String,
}

#[derive(Deserialize)]
struct Upstream {
    network: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupsAdd {
    network: String,
    parent_role: String,
    local_role: String,
}

fn most_recent<T>(mut all: Vec<T>, limit: Option<usize>) -> Vec<T> {
    if let Some(limit) = limit
        && all.len() > limit
    {
        all.drain(..all.len() - limit);
    }
    all
}

// ------------------------------------------------------------------- handlers

impl Call<'_> {
    fn network(&self) -> &crate::network::Network {
        &self.state.network
    }

    /// The signer, for a task whose specification requires a proof.
    fn signer(&self) -> ApiResult<&str> {
        self.signer.as_deref().ok_or(ApiError::Unauthorized)
    }

    fn admin(&self) -> ApiResult<&str> {
        let signer = self.signer()?;
        if self.state.auth.is_admin(signer) {
            Ok(signer)
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// What the signer is here. A presented VMC that does not verify is refused rather than
    /// ignored: the caller should learn why they see less.
    async fn standing(&self, membership: Option<&Value>) -> ApiResult<Standing> {
        let Some(signer) = self.signer.as_deref() else {
            return Ok(Standing::Anyone);
        };
        if self.state.auth.is_admin(signer) {
            return Ok(Standing::Admin);
        }
        if let Some(vmc) = membership {
            let community = self
                .network()
                .verify_member_credential(vmc, signer)
                .await
                .map_err(|e| {
                    tracing::info!(signer, error = %e, "member credential refused");
                    ApiError::Forbidden
                })?;
            return Ok(Standing::MemberByCredential { community });
        }
        Ok(match self.network().store.entry(signer).await? {
            Some(e) if e.state.is_membership() => Standing::MemberEntity,
            Some(e) if e.state == EntryState::Listed => Standing::Listed,
            _ => Standing::Anyone,
        })
    }

    /// The published set is readable by this caller.
    async fn reader(&self, membership: Option<&Value>) -> ApiResult<Standing> {
        let standing = self.standing(membership).await?;
        if can_read_directory(self.state.directory.visibility, &standing) {
            Ok(standing)
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// The signer's own entry, for a task only a listed party sends.
    async fn own_entry(&self, local: &'static str) -> ApiResult<vti_vtn::model::Entry> {
        let signer = self.signer()?;
        self.network()
            .store
            .entry(signer)
            .await?
            .ok_or_else(|| ApiError::coded(local, format!("{signer} is not listed here")))
    }

    // --------------------------------------------- a listed party, toward the network

    async fn entries_show(&self, p: DidRead) -> ApiResult<Value> {
        // A party may always read its own entry.
        if self.signer.as_deref() != Some(p.did.as_str()) {
            self.reader(p.membership.as_ref()).await?;
        }
        let entry = self
            .network()
            .store
            .entry(&p.did)
            .await?
            .filter(|e| e.state.is_published())
            .ok_or_else(|| ApiError::NotFound(format!("no entry for {}", p.did)))?;
        Ok(json!({ "entry": IndexEntry::from_entry(&entry) }))
    }

    async fn membership_offer(&self, _: Nothing) -> ApiResult<Value> {
        let entry = self.own_entry("notListed").await?;
        match entry.state {
            EntryState::Listed => {}
            s if s.is_membership() => {
                return Err(ApiError::coded(
                    "alreadyMember",
                    "this party has already acknowledged its membership",
                ));
            }
            _ => {
                return Err(ApiError::coded(
                    "notListed",
                    "this party's listing is not open to acknowledge",
                ));
            }
        }
        let offer = self.network().offer(&entry.did).await?;
        Ok(json!({ "offer": offer }))
    }

    async fn membership_acknowledge(&self, p: Acknowledge) -> ApiResult<Value> {
        let entry = self.own_entry("notListed").await?;
        // The same acknowledgement again is the same answer.
        if entry.state.is_membership() && entry.ack.as_ref() == Some(&p.acknowledgement) {
            return Ok(json!({ "entry": IndexEntry::from_entry(&entry) }));
        }
        if entry.state != EntryState::Listed {
            return Err(ApiError::coded(
                "notListed",
                "this party's listing is not open to acknowledge",
            ));
        }
        let entry = self
            .network()
            .acknowledge(&entry.did, p.acknowledgement)
            .await
            .map_err(|e| e.presented_as("acknowledgementInvalid"))?;
        Ok(json!({ "entry": IndexEntry::from_entry(&entry) }))
    }

    async fn membership_repudiate(&self, p: Repudiate) -> ApiResult<Value> {
        let entry = self.own_entry("notListed").await?;
        if entry.repudiation.as_ref() == Some(&p.repudiation) {
            return Ok(json!({ "entry": IndexEntry::from_entry(&entry) }));
        }
        let entry = self
            .network()
            .repudiate(&entry.did, p.repudiation)
            .await
            .map_err(|e| e.presented_as("repudiationInvalid"))?;
        Ok(json!({ "entry": IndexEntry::from_entry(&entry) }))
    }

    async fn groups_register(&self, p: Register) -> ApiResult<Value> {
        let entry = self.own_entry("notListed").await?;
        if self.network().role(&p.role).is_none() {
            return Err(ApiError::coded(
                "unknownRole",
                format!("this network defines no role {:?}", p.role),
            ));
        }
        // The registration is the signed request itself, as received.
        let group = self
            .network()
            .register_group(&entry.did, (*self.received).clone())
            .await?;
        Ok(json!({ "group": wire::group(&group) }))
    }

    async fn relay_deliver(&self, p: Deliver) -> ApiResult<Value> {
        let from = self.signer()?;
        let response = self.network().receive(from, &p.role, p.envelope).await?;
        Ok(wire::relay_response(&response))
    }

    async fn roles_list(&self, p: Read) -> ApiResult<Value> {
        // A listed party reads the roles it must register groups for.
        let standing = self.standing(p.membership.as_ref()).await?;
        if standing != Standing::Listed
            && !can_read_directory(self.state.directory.visibility, &standing)
        {
            return Err(ApiError::Forbidden);
        }
        Ok(json!({ "roles": self.network().roles() }))
    }

    async fn rooms_list(&self, p: Read) -> ApiResult<Value> {
        self.reader(p.membership.as_ref()).await?;
        let rooms: Vec<Value> = self.network().rooms().iter().map(wire::room).collect();
        Ok(json!({ "rooms": rooms }))
    }

    async fn rooms_pass(&self, p: Pass) -> ApiResult<Value> {
        let holder = self.signer()?;
        let pass = self
            .network()
            .room_pass(&p.room, holder, &p.membership, &p.chain)
            .await?;
        Ok(json!({ "pass": wire::room_pass(&pass) }))
    }

    // --------------------------------------------- reading the published set

    async fn directory_search(&self, p: Search) -> ApiResult<Value> {
        self.reader(p.membership.as_ref()).await?;
        let entries = self.network().directory(&p.query()).await?;
        Ok(json!({ "entries": entries }))
    }

    async fn directory_federated(&self, p: Search) -> ApiResult<Value> {
        self.reader(p.membership.as_ref()).await?;
        Ok(
            serde_json::to_value(self.network().federated_directory(&p.query()).await?)
                .map_err(VtnError::from)?,
        )
    }

    async fn directory_summary(&self, p: Read) -> ApiResult<Value> {
        if !self.state.directory.show_counts {
            self.reader(p.membership.as_ref()).await?;
        }
        Ok(json!({ "summary": self.network().directory_summary().await? }))
    }

    async fn graph_show(&self, p: GraphShow) -> ApiResult<Value> {
        let standing = self.reader(p.membership.as_ref()).await?;
        if p.include_exited && !standing.is_admin() {
            return Err(ApiError::Forbidden);
        }
        Ok(json!({ "graph": self.network().graph(p.include_exited).await? }))
    }

    async fn graph_member(&self, p: DidRead) -> ApiResult<Value> {
        self.reader(p.membership.as_ref()).await?;
        let graph = self
            .network()
            .member_graph(&p.did)
            .await
            .map_err(|e| match e {
                ApiError::NotFound(m) => ApiError::coded("notMember", m),
                ApiError::Upstream(m) => ApiError::coded("memberUnreachable", m),
                other => other,
            })?;
        Ok(json!({ "graph": graph }))
    }

    // --------------------------------------------- administration

    async fn listings_create(&self, p: Create) -> ApiResult<Value> {
        let admin = self.admin()?;
        let profile = EntryProfile {
            description: p.description,
            url: p.url,
            tags: p.tags.unwrap_or_default(),
        };
        let entry = self
            .network()
            .list(&p.did, p.kind, p.label, profile, admin)
            .await?;
        Ok(json!({ "entry": wire::entry(&entry) }))
    }

    /// A partial update: what the request names changes, and an empty string clears it.
    async fn listings_update(&self, p: Update) -> ApiResult<Value> {
        let admin = self.admin()?;
        let current = self.network().entry(&p.did).await?;
        let set = |new: Option<String>, old: Option<String>| match new {
            Some(v) if v.is_empty() => None,
            Some(v) => Some(v),
            None => old,
        };
        let label = set(p.label, current.label);
        let profile = EntryProfile {
            description: set(p.description, current.profile.description),
            url: set(p.url, current.profile.url),
            tags: p.tags.unwrap_or(current.profile.tags),
        };
        let entry = self
            .network()
            .update_profile(&p.did, label, profile, admin)
            .await?;
        Ok(json!({ "entry": wire::entry(&entry) }))
    }

    async fn listings_suspend(&self, p: Transition) -> ApiResult<Value> {
        let admin = self.admin()?;
        let current = self.network().entry(&p.did).await?;
        let entry = if current.state == EntryState::Suspended {
            current
        } else {
            self.network().suspend(&p.did, p.reason, admin).await?
        };
        Ok(json!({ "entry": wire::entry(&entry) }))
    }

    async fn listings_reinstate(&self, p: Transition) -> ApiResult<Value> {
        let admin = self.admin()?;
        let current = self.network().entry(&p.did).await?;
        let entry = if current.state == EntryState::Acknowledged {
            current
        } else {
            self.network().reinstate(&p.did, p.reason, admin).await?
        };
        Ok(json!({ "entry": wire::entry(&entry) }))
    }

    async fn listings_remove(&self, p: Transition) -> ApiResult<Value> {
        let admin = self.admin()?;
        let current = self.network().entry(&p.did).await?;
        let entry = if current.state == EntryState::Removed {
            current
        } else {
            self.network().remove(&p.did, p.reason, admin).await?
        };
        Ok(json!({ "entry": wire::entry(&entry) }))
    }

    async fn listings_list(&self, p: ListEntries) -> ApiResult<Value> {
        self.admin()?;
        let entries: Vec<_> = self
            .network()
            .entries()
            .await?
            .into_iter()
            .filter(|e| p.state.is_none_or(|s| e.state == s))
            .collect();
        Ok(json!({ "entries": wire::entries(&entries) }))
    }

    async fn listings_show(&self, p: Did) -> ApiResult<Value> {
        self.admin()?;
        Ok(json!({ "entry": wire::entry(&self.network().entry(&p.did).await?) }))
    }

    async fn audit_list(&self, p: Audit) -> ApiResult<Value> {
        self.admin()?;
        let events: Vec<_> = self
            .network()
            .audit()
            .await?
            .into_iter()
            .filter(|e| p.did.as_ref().is_none_or(|d| &e.did == d))
            .collect();
        let events: Vec<Value> = most_recent(events, p.limit)
            .iter()
            .map(wire::audit_event)
            .collect();
        Ok(json!({ "events": events }))
    }

    async fn groups_list(&self, p: Role) -> ApiResult<Value> {
        self.admin()?;
        let groups: Vec<Value> = self
            .network()
            .groups(p.role.as_deref())
            .await?
            .iter()
            .map(wire::group)
            .collect();
        Ok(json!({ "groups": groups }))
    }

    async fn broadcasts_send(&self, p: SendBroadcast) -> ApiResult<Value> {
        let admin = self.admin()?;
        if self.network().role(&p.role).is_none() {
            return Err(ApiError::coded(
                "unknownRole",
                format!("this network defines no role {:?}", p.role),
            ));
        }
        let outgoing = Outgoing {
            role: p.role,
            class: p.class.unwrap_or_else(|| "notice".into()),
            subject: p.subject,
            body: p.body,
            reply_to: p.reply_to,
        };
        let record = self.network().broadcast(outgoing, admin).await?;
        Ok(json!({ "broadcast": wire::broadcast(&record) }))
    }

    async fn broadcasts_list(&self, p: Limit) -> ApiResult<Value> {
        self.admin()?;
        // Newest first.
        let mut all = self.network().broadcasts().await?;
        if let Some(limit) = p.limit {
            all.truncate(limit);
        }
        let all: Vec<Value> = all.iter().map(wire::broadcast).collect();
        Ok(json!({ "broadcasts": all }))
    }

    async fn broadcasts_show(&self, p: Id) -> ApiResult<Value> {
        self.admin()?;
        let record = self.network().broadcast_record(&p.id).await?;
        Ok(json!({ "broadcast": wire::broadcast(&record) }))
    }

    async fn outbox_list(&self, _: Nothing) -> ApiResult<Value> {
        self.admin()?;
        let items: Vec<Value> = self
            .network()
            .outbox()
            .await?
            .iter()
            .map(wire::outbox_item)
            .collect();
        Ok(json!({ "items": items }))
    }

    async fn outbox_retry(&self, _: Nothing) -> ApiResult<Value> {
        self.admin()?;
        Ok(json!({ "attempted": self.network().retry_due(true).await? }))
    }

    // --------------------------------------------- this network as a member of a parent

    async fn memberships_list(&self, _: Nothing) -> ApiResult<Value> {
        self.admin()?;
        let all: Vec<Value> = self
            .network()
            .memberships()
            .await?
            .iter()
            .map(wire::membership)
            .collect();
        Ok(json!({ "memberships": all }))
    }

    async fn memberships_join(&self, p: Join) -> ApiResult<Value> {
        let admin = self.admin()?;
        let membership = self
            .network()
            .join(&p.url, &p.network, p.roles, admin)
            .await?;
        Ok(json!({ "membership": wire::membership(&membership) }))
    }

    async fn memberships_repudiate(&self, p: UpstreamRepudiate) -> ApiResult<Value> {
        let admin = self.admin()?;
        let membership = self
            .network()
            .repudiate_listing(&p.url, &p.network, admin)
            .await?;
        Ok(json!({ "membership": wire::membership(&membership) }))
    }

    async fn memberships_leave(&self, p: Upstream) -> ApiResult<Value> {
        let admin = self.admin()?;
        let membership = self.network().leave(&p.network, admin).await?;
        Ok(json!({ "membership": wire::membership(&membership) }))
    }

    async fn memberships_groups_add(&self, p: GroupsAdd) -> ApiResult<Value> {
        self.admin()?;
        let mapping = RoleMapping {
            parent_role: p.parent_role,
            local_role: p.local_role,
        };
        let membership = self
            .network()
            .add_upstream_group(&p.network, mapping)
            .await?;
        Ok(json!({ "membership": wire::membership(&membership) }))
    }
}
