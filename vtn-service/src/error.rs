//! API errors.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use vtn_core::VtnError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
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
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
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

pub type ApiResult<T> = Result<T, ApiError>;
