//! API errors.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use vti_vtn::VtnError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    /// Another network refused or could not be reached.
    #[error("upstream network: {0}")]
    Upstream(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    /// A refusal its task's specification names: `local` is the code after the slug
    /// (`<slug>:<local>`), so one variant serves every task that declares it.
    #[error("{message}")]
    Coded {
        local: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },
    #[error(transparent)]
    Vtn(#[from] VtnError),
    #[error("store error: {0}")]
    Store(#[from] vti_common::error::AppError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Coded { local, .. } => (StatusCode::UNPROCESSABLE_ENTITY, *local),
            ApiError::Vtn(VtnError::InvalidTransition { .. }) => {
                (StatusCode::CONFLICT, "invalid_transition")
            }
            ApiError::Vtn(
                VtnError::Rejected(_) | VtnError::Credential(_) | VtnError::DataIntegrity(_),
            ) => (StatusCode::UNPROCESSABLE_ENTITY, "rejected"),
            ApiError::Vtn(VtnError::InvalidDid(_)) => (StatusCode::BAD_REQUEST, "invalid_did"),
            ApiError::Vtn(_) | ApiError::Store(_) => {
                tracing::error!(error = %self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        (
            status,
            Json(json!({ "error": code, "message": self.to_string() })),
        )
            .into_response()
    }
}

impl ApiError {
    /// A refusal its task's specification declares as `<slug>:<local>`.
    pub fn coded(local: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            local,
            message: message.into(),
            details: None,
        }
    }

    /// [`Self::coded`] with a `details` annex.
    pub fn coded_with(
        local: &'static str,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        ApiError::Coded {
            local,
            message: message.into(),
            details: Some(details),
        }
    }

    /// A rejection of what the caller presented (a credential that does not verify, a
    /// signature that does not match) as the task's own `local` code; anything else as is.
    pub fn presented_as(self, local: &'static str) -> Self {
        match self {
            ApiError::Vtn(
                e @ (VtnError::Rejected(_) | VtnError::Credential(_) | VtnError::DataIntegrity(_)),
            ) => ApiError::coded(local, e.to_string()),
            other => other,
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
