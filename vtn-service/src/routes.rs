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
//!   `vtn/entries/show` and `vtn/graph/show`, which carry the reader's signature (A21).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
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

const LANDING_PAGE: &str = include_str!("../web/index.html");

#[derive(Clone)]
pub struct AppState {
    pub network: Arc<Network>,
    pub auth: Arc<Auth>,
    pub directory: DirectoryConfig,
    /// The accepted-document-id record every Trust Task is claimed against.
    pub accepted: StoreAcceptedIds,
}

pub fn router(state: AppState) -> Router {
    let artifacts = Router::new()
        .route("/", get(landing))
        .route("/.well-known/vtn", get(profile))
        .route("/v1/status/{purpose}", get(status_list))
        .route("/v1/index", get(index))
        .route("/v1/credentials/{id}", get(credential))
        .with_state(state.clone());
    artifacts.merge(vti_trust_task_server::http::routes(Arc::new(
        VtnTasks::new(state),
    )))
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
            "trustTasks": TRUST_TASKS_PATH,
            "index": "/v1/index",
            "status": "/v1/status/{purpose}",
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

async fn index(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    require_public(&s)?;
    Ok(Json(s.network.index().await?))
}

async fn credential(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    require_public(&s)?;
    Ok(Json(s.network.credential(&id).await?))
}
