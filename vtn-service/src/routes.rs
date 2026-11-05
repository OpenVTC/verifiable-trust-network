//! HTTP: the `vtn/*` Trust Task endpoint, and the artifacts fetched by URL.
//!
//! Everything a caller asks of the network is a Trust Task at `POST /v1/trust-tasks`
//! ([`crate::tasks`]). What stays a plain `GET` is only what verifiers and browsers fetch by
//! URL (`docs/trust-tasks.md`):
//!
//! - the landing page, and the network's profile at `/.well-known/vtn`;
//! - status lists, because verifiers dereference `credentialStatus`, and a bitstring names
//!   nobody;
//! - the signed index and credentials by `id`, under `[directory] visibility = "public"`
//!   only. In a restricted network the same credentials are read through
//!   `vtn/entries/show` and `vtn/graph/show`, which carry the reader's signature (A21);
//! - the landing page's wallet sign-in link as a QR code, an image the page shows.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use vti_vtn::model::Visibility;
use vti_vtn::status::Purpose;
use vti_vtn::tasks::TRUST_TASKS_PATH;

use crate::auth::Auth;
use crate::config::DirectoryConfig;
use crate::error::{ApiError, ApiResult};
use crate::network::Network;
use crate::tasks::VtnTasks;
use crate::tasks::accepted::StoreAcceptedIds;
use vti_oob_server::HttpContext;
use vti_trust_task_server::ArrivalCtx;
use vti_trust_task_server::http::TrustTaskService;

const LANDING_PAGE: &str = include_str!("../web/index.html");

#[derive(Clone)]
pub struct AppState {
    pub network: Arc<Network>,
    pub auth: Arc<Auth>,
    pub directory: DirectoryConfig,
    /// The accepted-document-id record every Trust Task is claimed against.
    pub accepted: StoreAcceptedIds,
    /// Browser sign-in settings.
    pub sign_in: crate::config::AuthConfig,
    /// The trust registry membership is projected to, if any (`crate::registry`).
    pub registry: Option<crate::config::RegistryConfig>,
    /// The running projection and the session it asks the registry over, once `vtn serve`
    /// has built them (`vtn/registry/*`).
    pub registry_link: Option<Arc<crate::registry::Link>>,
}

pub fn router(state: AppState) -> Router {
    let artifacts = Router::new()
        .route("/", get(landing))
        .route("/health", get(health))
        .route("/health/ready", get(ready))
        .route("/.well-known/vtn", get(profile))
        .route("/v1/sign-in/qr.svg", get(sign_in_qr))
        .route("/v1/status/{purpose}", get(status_list))
        .route("/v1/index", get(index))
        .route("/v1/credentials/{id}", get(credential))
        .with_state(state.clone());
    let tasks = Arc::new(VtnTasks::new(state));
    artifacts.merge(
        Router::new()
            .route(TRUST_TASKS_PATH, post(trust_task))
            .layer(DefaultBodyLimit::max(tasks.max_body_bytes()))
            .with_state(tasks),
    )
}

/// `POST /v1/trust-tasks`: the document through the spine, with what `auth/oob/request`
/// and `redeem` read from the connection (the browser's address, `User-Agent`, `Origin`
/// and `Host`). No other task reads it.
///
/// The address is the TCP peer's: behind a reverse proxy it is the proxy's, which the
/// per-address limits on pending sign-ins then share.
async fn trust_task(State(tasks): State<Arc<VtnTasks>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, tasks.max_body_bytes()).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().copied();
    let headers = &parts.headers;
    let header = |name: header::HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let address = peer.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ConnectInfo(a)| a.ip());
    let http = HttpContext::new(
        address,
        header(header::USER_AGENT),
        header(header::ORIGIN),
        header(header::HOST),
    );
    HttpContext::scope(http, tasks.spine().receive(&ArrivalCtx::rest(), &body))
        .await
        .into_response()
}

/// The index and credentials are fetched without a signature, so only a public directory
/// serves them.
fn require_public(state: &AppState) -> ApiResult<()> {
    if state.directory.visibility == Visibility::Public {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// `GET /health`: liveness. The process is up and serving; nothing is checked. Only what
/// is public already (the network DID, also at `/.well-known/vtn`), no infrastructure
/// detail, as the VTC's and the VTA's `/health`.
async fn health(State(s): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "did": s.network.did(),
    }))
}

/// `GET /health/ready`: readiness. 200 when the network can answer: its store reads (the
/// identity is loaded before the service starts, or it does not start). 503 otherwise, with
/// the cause in the log, not the answer.
async fn ready(State(s): State<AppState>) -> Response {
    match s.network.store.ping().await {
        Ok(()) => Json(json!({ "status": "ready", "checks": { "store": "ok" } })).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "readiness: the store cannot be read");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable", "checks": { "store": "failed" } })),
            )
                .into_response()
        }
    }
}

async fn landing(State(s): State<AppState>) -> Response {
    let mut res = Html(LANDING_PAGE).into_response();
    if let Ok(policy) = HeaderValue::from_str(&landing_policy(s.registry.as_ref())) {
        res.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    res
}

/// The landing page's CSP. With a trust registry whose query surface is advertised, the
/// page may also reach that origin, so a visitor checks a record with the registry itself
/// rather than taking this network's word for it (the registry must allow this network's
/// origin in its `CORS_ALLOWED_ORIGINS`).
pub fn landing_policy(registry: Option<&crate::config::RegistryConfig>) -> String {
    let registry_origin = registry
        .and_then(|r| r.query_url.as_deref())
        .and_then(crate::registry::origin_of)
        .map(|o| format!(" {o}"))
        .unwrap_or_default();
    format!(
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
         connect-src 'self'{registry_origin}; img-src 'self' data:; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'"
    )
}

async fn profile(State(s): State<AppState>) -> Json<Value> {
    let mut profile = json!({
        "did": s.network.did(),
        "profile": s.network.profile,
        "roles": s.network.roles(),
        "directory": {
            "visibility": s.directory.visibility,
            "showCounts": s.directory.show_counts,
            "federateDepth": s.directory.federate_depth,
        },
        // What the landing page needs for a wallet sign-in (`auth/oob/*`, A13).
        "signIn": {
            "linkHost": s.sign_in.link_host,
            "flow": vti_oob_server::SIGN_IN_FLOW,
            "scope": crate::tasks::oob::SIGNING_SCOPE,
        },
        "links": {
            "trustTasks": TRUST_TASKS_PATH,
            "index": "/v1/index",
            "status": "/v1/status/{purpose}",
        },
    });
    // Where a verifier checks membership without asking this network (A23). Absent when
    // no registry is configured.
    if let Some(registry) = &s.registry {
        profile["trustRegistry"] = crate::registry::profile_json(registry, s.network.did());
    }
    Json(profile)
}

/// Which sign-in request a QR code is for: its id and claim deadline, as
/// `auth/oob/request` answered them.
#[derive(Deserialize)]
struct SignInQr {
    id: String,
    exp: u64,
}

/// `GET /v1/sign-in/qr.svg?id=&exp=`: the trigger link for a sign-in request as a QR code,
/// so a wallet on a phone can scan what the landing page shows on a laptop. The link is
/// built here, from this network's DID and link host, so only this network's sign-in links
/// are drawn. Level M, as the VTC's sign-in code; a link longer than level M holds
/// (VTI-LNK-081) is refused.
async fn sign_in_qr(State(s): State<AppState>, Query(q): Query<SignInQr>) -> Response {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    let well_formed = q.id.len() == 22
        && q.id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !well_formed {
        return (StatusCode::BAD_REQUEST, "not a sign-in request id").into_response();
    }
    let link = vti_oob_server::trigger_link(&s.sign_in.link_host, s.network.did(), &q.id, q.exp);
    if !link.is_ascii() || link.len() > vti_oob_server::MAX_LINK_BYTES_LEVEL_M {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "the sign-in link is too long for a QR code",
        )
            .into_response();
    }
    let Ok(code) = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "the sign-in link does not fit a QR code",
        )
            .into_response();
    };
    let image = code
        .render::<svg::Color>()
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        image,
    )
        .into_response()
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

async fn index(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    require_public(&s)?;
    Ok(Json(s.network.index().await?))
}

async fn credential(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    require_public(&s)?;
    Ok(Json(s.network.credential(&id).await?))
}
