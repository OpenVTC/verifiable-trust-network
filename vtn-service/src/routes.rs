//! HTTP API and the landing page.
//!
//! **Always public:**
//! - the landing page and the network's profile;
//! - status lists, because verifiers need them, and a bitstring names nobody;
//! - what a listed party signs and sends (acknowledge, repudiate), because its signature is
//!   its authentication.
//!
//! **Governed by `[directory] visibility`:** everything that reveals the published set: the
//! directory, the index, the graph, entries and credentials (see [`can_read_directory`]).
//! In a restricted network a listed party fetches its own offer only when signed in as
//! itself, so probing DIDs does not reveal who is listed.
//!
//! **Admin routes** need an admin session from [`crate::auth`] (the NNM).

use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use vti_vtn::directory::{DirectoryEntry, DirectoryQuery};
use vti_vtn::graph::Graph;
use vti_vtn::index::IndexEntry;
use vti_vtn::model::{Entry, EntryKind, EntryProfile, EntryState, Visibility};
use vti_vtn::status::Purpose;

use vti_vtn::groups::{RegisteredGroup, RoleDef};
use vti_vtn::relay::{Envelope, Outgoing};

use crate::auth::{Auth, Challenge, Principal, Role, SessionGrant};
use crate::broadcast::{BroadcastRecord, RelayResponse};
use crate::config::DirectoryConfig;
use crate::error::{ApiError, ApiResult};
use crate::memberships::{Membership, RoleMapping};
use crate::network::Network;
use crate::store::AuditEvent;

const LANDING_PAGE: &str = include_str!("../web/index.html");

#[derive(Clone)]
pub struct AppState {
    pub network: Arc<Network>,
    pub auth: Arc<Auth>,
    pub directory: DirectoryConfig,
}

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/", get(landing))
        .route("/.well-known/vtn", get(profile))
        .route("/v1/status/{purpose}", get(status_list))
        .route("/v1/directory", get(directory))
        .route("/v1/directory/summary", get(directory_summary))
        .route("/v1/directory/federated", get(federated_directory))
        .route("/v1/index", get(index))
        .route("/v1/graph", get(public_graph))
        .route("/v1/graph/member/{did}", get(member_graph))
        .route("/v1/credentials/{id}", get(credential))
        .route("/v1/entries/{did}", get(public_entry))
        .route("/v1/entries/{did}/offer", get(offer))
        .route("/v1/entries/{did}/acknowledge", post(acknowledge))
        .route("/v1/entries/{did}/repudiate", post(repudiate))
        .route("/v1/entries/{did}/groups", post(register_group))
        .route("/v1/relay/{role}", post(relay_receive))
        .route("/v1/rooms", get(rooms_list))
        .route("/v1/rooms/{id}/pass", post(room_pass))
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/session", get(auth_whoami).post(auth_session))
        .route("/v1/auth/login", post(auth_login_start))
        .route("/v1/auth/login/{id}", get(auth_login_poll));

    let admin = Router::new()
        .route("/v1/admin/entries", get(admin_entries).post(admin_list))
        .route("/v1/admin/entries/{did}", get(admin_entry))
        .route("/v1/admin/entries/{did}/profile", post(admin_profile))
        .route("/v1/admin/entries/{did}/suspend", post(admin_suspend))
        .route("/v1/admin/entries/{did}/reinstate", post(admin_reinstate))
        .route("/v1/admin/entries/{did}/remove", post(admin_remove))
        .route("/v1/admin/graph", get(admin_graph))
        .route("/v1/admin/audit", get(admin_audit))
        .route("/v1/admin/whoami", get(admin_whoami))
        .route("/v1/admin/roles", get(admin_roles))
        .route("/v1/admin/groups", get(admin_groups))
        .route(
            "/v1/admin/broadcasts",
            get(admin_broadcasts).post(admin_broadcast),
        )
        .route("/v1/admin/broadcasts/{id}", get(admin_broadcast_record))
        .route("/v1/admin/outbox", get(admin_outbox))
        .route("/v1/admin/outbox/retry", post(admin_outbox_retry))
        .route(
            "/v1/admin/memberships",
            get(admin_memberships).post(admin_join),
        )
        .route(
            "/v1/admin/memberships/repudiate",
            post(admin_repudiate_listing),
        )
        .route("/v1/admin/memberships/{parent}/leave", post(admin_leave))
        .route(
            "/v1/admin/memberships/{parent}/groups",
            post(admin_upstream_group),
        );

    public.merge(admin).with_state(state)
}

// --------------------------------------------------------------- principals

/// The signed-in principal, if a bearer token was sent.
pub struct MaybePrincipal(pub Option<Principal>);

impl FromRequestParts<AppState> for MaybePrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Some(token) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Ok(MaybePrincipal(None));
        };
        // A token that was sent but is no good is an error, not anonymity: the caller should
        // learn their session ended rather than see a quietly smaller directory.
        Ok(MaybePrincipal(Some(state.auth.principal(token).await?)))
    }
}

/// A signed-in administrator: their DID.
pub struct Admin(pub String);

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        match MaybePrincipal::from_request_parts(parts, state).await?.0 {
            Some(p) if p.role.is_admin() => Ok(Admin(p.did)),
            Some(_) => Err(ApiError::Forbidden),
            None => Err(ApiError::Unauthorized),
        }
    }
}

/// May `who` read the published set under `visibility`?
pub fn can_read_directory(visibility: Visibility, who: Option<&Principal>) -> bool {
    match visibility {
        Visibility::Public => true,
        Visibility::Members => who.is_some_and(|p| p.role.is_admin() || p.role.is_member()),
        Visibility::Admins => who.is_some_and(|p| p.role.is_admin()),
    }
}

fn require_directory(state: &AppState, who: &MaybePrincipal) -> ApiResult<()> {
    if can_read_directory(state.directory.visibility, who.0.as_ref()) {
        Ok(())
    } else if who.0.is_some() {
        Err(ApiError::Forbidden)
    } else {
        Err(ApiError::Unauthorized)
    }
}

// ------------------------------------------------------------------ public

async fn landing() -> Response {
    let mut res = Html(LANDING_PAGE).into_response();
    res.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; \
             frame-ancestors 'none'",
        ),
    );
    res
}

async fn profile(State(s): State<AppState>) -> Json<Value> {
    Json(json!({
        "did": s.network.did(),
        "profile": s.network.profile,
        "roles": s.network.roles(),
        "directory": {
            "visibility": s.directory.visibility,
            "showCounts": s.directory.show_counts,
            "federateDepth": s.directory.federate_depth,
        },
        "links": {
            "directory": "/v1/directory",
            "index": "/v1/index",
            "graph": "/v1/graph",
            "signIn": "/v1/auth/challenge",
        },
    }))
}

async fn status_list(
    State(s): State<AppState>,
    Path(purpose): Path<String>,
) -> ApiResult<Json<Value>> {
    let purpose = match purpose.as_str() {
        "revocation" => Purpose::Revocation,
        "suspension" => Purpose::Suspension,
        other => return Err(ApiError::NotFound(format!("no status list {other}"))),
    };
    Ok(Json(s.network.status_list(purpose).await?))
}

async fn directory(
    State(s): State<AppState>,
    who: MaybePrincipal,
    Query(query): Query<DirectoryQuery>,
) -> ApiResult<Json<Vec<DirectoryEntry>>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.directory(&query).await?))
}

async fn federated_directory(
    State(s): State<AppState>,
    who: MaybePrincipal,
    Query(query): Query<DirectoryQuery>,
) -> ApiResult<Json<crate::federation::FederatedResult>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.federated_directory(&query).await?))
}

async fn directory_summary(
    State(s): State<AppState>,
    who: MaybePrincipal,
) -> ApiResult<Json<Value>> {
    if !s.directory.show_counts {
        require_directory(&s, &who)?;
    }
    Ok(Json(json!(s.network.directory_summary().await?)))
}

async fn index(State(s): State<AppState>, who: MaybePrincipal) -> ApiResult<Json<Value>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.index().await?))
}

async fn public_graph(State(s): State<AppState>, who: MaybePrincipal) -> ApiResult<Json<Graph>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.graph(false).await?))
}

async fn member_graph(
    State(s): State<AppState>,
    who: MaybePrincipal,
    Path(did): Path<String>,
) -> ApiResult<Json<Graph>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.member_graph(&did).await?))
}

async fn credential(
    State(s): State<AppState>,
    who: MaybePrincipal,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.credential(&id).await?))
}

async fn public_entry(
    State(s): State<AppState>,
    who: MaybePrincipal,
    Path(did): Path<String>,
) -> ApiResult<Json<IndexEntry>> {
    // A party may always read its own entry.
    if who.0.as_ref().is_none_or(|p| p.did != did) {
        require_directory(&s, &who)?;
    }
    let entry = s.network.entry(&did).await?;
    if !entry.state.is_published() {
        return Err(ApiError::NotFound(format!("no entry for {did}")));
    }
    Ok(Json(IndexEntry::from_entry(&entry)))
}

async fn offer(
    State(s): State<AppState>,
    who: MaybePrincipal,
    Path(did): Path<String>,
) -> ApiResult<Json<Value>> {
    if s.directory.visibility != Visibility::Public
        && who
            .0
            .as_ref()
            .is_none_or(|p| p.did != did && !p.role.is_admin())
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(Json(s.network.offer(&did).await?))
}

#[derive(Deserialize)]
struct AcknowledgeBody {
    acknowledgement: Value,
}

async fn acknowledge(
    State(s): State<AppState>,
    Path(did): Path<String>,
    Json(body): Json<AcknowledgeBody>,
) -> ApiResult<Json<IndexEntry>> {
    let entry = s.network.acknowledge(&did, body.acknowledgement).await?;
    Ok(Json(IndexEntry::from_entry(&entry)))
}

#[derive(Deserialize)]
struct RepudiateBody {
    repudiation: Value,
}

async fn repudiate(
    State(s): State<AppState>,
    Path(did): Path<String>,
    Json(body): Json<RepudiateBody>,
) -> ApiResult<Json<IndexEntry>> {
    let entry = s.network.repudiate(&did, body.repudiation).await?;
    Ok(Json(IndexEntry::from_entry(&entry)))
}

#[derive(Deserialize)]
struct GroupBody {
    registration: Value,
}

/// A listed party or member registers a group for a role; its signature authenticates it.
async fn register_group(
    State(s): State<AppState>,
    Path(did): Path<String>,
    Json(body): Json<GroupBody>,
) -> ApiResult<Json<RegisteredGroup>> {
    Ok(Json(
        s.network.register_group(&did, body.registration).await?,
    ))
}

#[derive(Deserialize)]
struct RelayBody {
    envelope: Envelope,
}

/// A parent network delivers a broadcast to this network's group for `role`.
async fn relay_receive(
    State(s): State<AppState>,
    Path(role): Path<String>,
    Json(body): Json<RelayBody>,
) -> ApiResult<Json<RelayResponse>> {
    Ok(Json(s.network.receive(&role, body.envelope).await?))
}

/// The network's rooms. Their existence is as visible as the directory.
async fn rooms_list(
    State(s): State<AppState>,
    who: MaybePrincipal,
) -> ApiResult<Json<Vec<crate::rooms::RoomDef>>> {
    require_directory(&s, &who)?;
    Ok(Json(s.network.rooms().to_vec()))
}

/// A person asks for a room pass, proving who they are and presenting their group evidence.
async fn room_pass(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<crate::rooms::PassRequest>,
) -> ApiResult<Json<crate::rooms::RoomPass>> {
    let (holder, _) = s.auth.verify_sign_in(&request.authentication).await?;
    Ok(Json(s.network.room_pass(&id, &holder, &request).await?))
}

// -------------------------------------------------------------------- auth

#[derive(Deserialize)]
struct ChallengeBody {
    did: String,
}

async fn auth_challenge(
    State(s): State<AppState>,
    Json(body): Json<ChallengeBody>,
) -> ApiResult<Json<Challenge>> {
    Ok(Json(s.auth.challenge(&body.did).await?))
}

#[derive(Deserialize)]
struct SessionBody {
    authentication: Value,
    /// A person's membership credential from a member community.
    #[serde(default)]
    membership: Option<Value>,
}

async fn auth_session(
    State(s): State<AppState>,
    Json(body): Json<SessionBody>,
) -> ApiResult<Json<SessionGrant>> {
    let (did, login) = s.auth.verify_sign_in(&body.authentication).await?;
    let role = if s.auth.is_admin(&did) {
        Role::Admin
    } else if let Some(vmc) = &body.membership {
        let community = s
            .network
            .verify_member_credential(vmc, &did)
            .await
            .map_err(|e| {
                tracing::info!(did, error = %e, "member credential refused");
                ApiError::Unauthorized
            })?;
        Role::MemberByCredential { community }
    } else {
        match s.network.entry(&did).await {
            Ok(entry) if entry.state.is_membership() => Role::MemberEntity,
            Ok(entry) if entry.state == EntryState::Listed => Role::Listed,
            _ => return Err(ApiError::Unauthorized),
        }
    };
    let grant = s.auth.open_session(Principal { did, role }).await;
    if let Some(login) = login {
        s.auth.complete_login(&login, &grant).await;
    }
    Ok(Json(grant))
}

/// Start a browser sign-in: the page shows the link, a wallet signs, the page polls.
async fn auth_login_start(State(s): State<AppState>) -> ApiResult<Json<crate::auth::LoginStart>> {
    Ok(Json(s.auth.start_login().await?))
}

#[derive(Deserialize)]
struct PollQuery {
    secret: String,
}

async fn auth_login_poll(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<PollQuery>,
) -> ApiResult<Json<crate::auth::LoginStatus>> {
    Ok(Json(s.auth.poll_login(&id, &q.secret).await?))
}

async fn auth_whoami(who: MaybePrincipal) -> ApiResult<Json<Value>> {
    let p = who.0.ok_or(ApiError::Unauthorized)?;
    Ok(Json(json!({ "did": p.did, "role": p.role })))
}

// ------------------------------------------------------------------- admin

async fn admin_whoami(State(s): State<AppState>, Admin(did): Admin) -> Json<Value> {
    Json(json!({ "did": did, "network": s.network.did() }))
}

#[derive(Deserialize)]
struct ListBody {
    did: String,
    kind: EntryKind,
    #[serde(default)]
    label: Option<String>,
    #[serde(flatten)]
    profile: EntryProfile,
}

async fn admin_list(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Json(body): Json<ListBody>,
) -> ApiResult<Json<Entry>> {
    Ok(Json(
        s.network
            .list(&body.did, body.kind, body.label, body.profile, &admin)
            .await?,
    ))
}

#[derive(Deserialize)]
struct ProfileBody {
    #[serde(default)]
    label: Option<String>,
    #[serde(flatten)]
    profile: EntryProfile,
}

async fn admin_profile(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Path(did): Path<String>,
    Json(body): Json<ProfileBody>,
) -> ApiResult<Json<Entry>> {
    Ok(Json(
        s.network
            .update_profile(&did, body.label, body.profile, &admin)
            .await?,
    ))
}

async fn admin_entries(State(s): State<AppState>, _: Admin) -> ApiResult<Json<Vec<Entry>>> {
    Ok(Json(s.network.entries().await?))
}

async fn admin_entry(
    State(s): State<AppState>,
    _: Admin,
    Path(did): Path<String>,
) -> ApiResult<Json<Entry>> {
    Ok(Json(s.network.entry(&did).await?))
}

#[derive(Deserialize, Default)]
struct ReasonBody {
    #[serde(default)]
    reason: Option<String>,
}

async fn admin_suspend(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Path(did): Path<String>,
    body: Option<Json<ReasonBody>>,
) -> ApiResult<Json<Entry>> {
    let reason = body.unwrap_or_default().0.reason;
    Ok(Json(s.network.suspend(&did, reason, &admin).await?))
}

async fn admin_reinstate(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Path(did): Path<String>,
    body: Option<Json<ReasonBody>>,
) -> ApiResult<Json<Entry>> {
    let reason = body.unwrap_or_default().0.reason;
    Ok(Json(s.network.reinstate(&did, reason, &admin).await?))
}

async fn admin_remove(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Path(did): Path<String>,
    body: Option<Json<ReasonBody>>,
) -> ApiResult<Json<Entry>> {
    let reason = body.unwrap_or_default().0.reason;
    Ok(Json(s.network.remove(&did, reason, &admin).await?))
}

#[derive(Deserialize)]
struct GraphQuery {
    #[serde(default)]
    include_exited: bool,
}

async fn admin_graph(
    State(s): State<AppState>,
    _: Admin,
    Query(q): Query<GraphQuery>,
) -> ApiResult<Json<Graph>> {
    Ok(Json(s.network.graph(q.include_exited).await?))
}

async fn admin_audit(State(s): State<AppState>, _: Admin) -> ApiResult<Json<Vec<AuditEvent>>> {
    Ok(Json(s.network.audit().await?))
}

async fn admin_roles(State(s): State<AppState>, _: Admin) -> Json<Vec<RoleDef>> {
    Json(s.network.roles().to_vec())
}

#[derive(Deserialize)]
struct GroupsQuery {
    #[serde(default)]
    role: Option<String>,
}

async fn admin_groups(
    State(s): State<AppState>,
    _: Admin,
    Query(q): Query<GroupsQuery>,
) -> ApiResult<Json<Vec<RegisteredGroup>>> {
    Ok(Json(s.network.groups(q.role.as_deref()).await?))
}

async fn admin_broadcast(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Json(outgoing): Json<Outgoing>,
) -> ApiResult<Json<BroadcastRecord>> {
    Ok(Json(s.network.broadcast(outgoing, &admin).await?))
}

async fn admin_broadcasts(
    State(s): State<AppState>,
    _: Admin,
) -> ApiResult<Json<Vec<BroadcastRecord>>> {
    Ok(Json(s.network.broadcasts().await?))
}

async fn admin_broadcast_record(
    State(s): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<BroadcastRecord>> {
    Ok(Json(s.network.broadcast_record(&id).await?))
}

async fn admin_memberships(
    State(s): State<AppState>,
    _: Admin,
) -> ApiResult<Json<Vec<Membership>>> {
    Ok(Json(s.network.memberships().await?))
}

#[derive(Deserialize)]
struct JoinBody {
    url: String,
    #[serde(default)]
    roles: Vec<RoleMapping>,
}

async fn admin_join(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Json(body): Json<JoinBody>,
) -> ApiResult<Json<Membership>> {
    Ok(Json(s.network.join(&body.url, body.roles, &admin).await?))
}

#[derive(Deserialize)]
struct UrlBody {
    url: String,
}

async fn admin_repudiate_listing(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Json(body): Json<UrlBody>,
) -> ApiResult<Json<Membership>> {
    Ok(Json(s.network.repudiate_listing(&body.url, &admin).await?))
}

async fn admin_leave(
    State(s): State<AppState>,
    Admin(admin): Admin,
    Path(parent): Path<String>,
) -> ApiResult<Json<Membership>> {
    Ok(Json(s.network.leave(&parent, &admin).await?))
}

async fn admin_upstream_group(
    State(s): State<AppState>,
    _: Admin,
    Path(parent): Path<String>,
    Json(mapping): Json<RoleMapping>,
) -> ApiResult<Json<Membership>> {
    Ok(Json(s.network.add_upstream_group(&parent, mapping).await?))
}

async fn admin_outbox(
    State(s): State<AppState>,
    _: Admin,
) -> ApiResult<Json<Vec<crate::broadcast::OutboxItem>>> {
    Ok(Json(s.network.outbox().await?))
}

async fn admin_outbox_retry(State(s): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    let attempted = s.network.retry_due(true).await?;
    Ok(Json(json!({ "attempted": attempted })))
}
