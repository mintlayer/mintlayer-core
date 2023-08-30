use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error, Serialize)]
pub enum APIServerWebServerError {
    #[error("Client error: {0}")]
    ClientError(#[from] APIServerWebServerClientError),
    #[error("Server error: {0}")]
    ServerError(#[from] APIServerWebServerServerError),
}

#[allow(dead_code)]
#[derive(Debug, Error, Serialize)]
pub enum APIServerWebServerClientError {
    #[error("Bad request")]
    BadRequest,
}

#[allow(dead_code)]
#[derive(Debug, Error, Serialize)]
pub enum APIServerWebServerServerError {
    #[error("Internal server error")]
    InternalServerError,
}

impl IntoResponse for APIServerWebServerError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            APIServerWebServerError::ClientError(error) => {
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            APIServerWebServerError::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
