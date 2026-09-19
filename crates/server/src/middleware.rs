//! Request/response middleware and error handling.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use oid4vc_types::error::{ErrorResponse, Oid4vcError};

/// Wrapper to convert `Oid4vcError` into HTTP responses.
#[allow(dead_code)]
pub struct AppError(pub Oid4vcError);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.http_status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let body = self.0.to_error_response();

        (status, Json(body)).into_response()
    }
}

impl From<Oid4vcError> for AppError {
    fn from(err: Oid4vcError) -> Self {
        Self(err)
    }
}

/// Generic JSON error response helper.
pub fn json_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = ErrorResponse {
        error: error.to_string(),
        error_description: Some(description.to_string()),
        c_nonce: None,
        c_nonce_expires_in: None,
    };

    (status, Json(body)).into_response()
}
