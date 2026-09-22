//! Request extractors.

use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::Response;
use axum::{Form, Json};
use serde::de::DeserializeOwned;

use crate::middleware::json_error;

/// Accepts a body as either `application/x-www-form-urlencoded` or `application/json`.
///
/// OAuth 2.0 (RFC 6749 §4.1.3), PAR (RFC 9126 §2) and OID4VP `direct_post`
/// all specify form encoding, and that is what wallets and the conformance
/// suite send. JSON is accepted as well so the endpoints stay pleasant to
/// drive from `curl`.
///
/// A body with no `Content-Type` is treated as form-encoded, per OAuth's default.
pub struct FormOrJson<T>(pub T);

impl<T, S> FromRequest<S> for FormOrJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"));

        if is_json {
            Json::<T>::from_request(req, state)
                .await
                .map(|Json(value)| Self(value))
                .map_err(|rejection| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        &rejection.body_text(),
                    )
                })
        } else {
            Form::<T>::from_request(req, state)
                .await
                .map(|Form(value)| Self(value))
                .map_err(|rejection| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        &rejection.body_text(),
                    )
                })
        }
    }
}
