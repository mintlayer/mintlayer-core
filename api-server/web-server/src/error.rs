use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error, Serialize)]
pub enum APIServerDaemonError {
    #[error("Client error: {0}")]
    ClientError(#[from] APIServerDaemonClientError),
    #[error("Server error: {0}")]
    ServerError(#[from] APIServerDaemonServerError),
}

#[allow(dead_code)]
#[derive(Debug, Error, Serialize)]
pub enum APIServerDaemonClientError {
    #[error("Bad request")]
    BadRequest,
}

#[allow(dead_code)]
#[derive(Debug, Error, Serialize)]
pub enum APIServerDaemonServerError {
    #[error("Internal server error")]
    InternalServerError,
}

impl IntoResponse for APIServerDaemonError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            APIServerDaemonError::ClientError(error) => {
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            APIServerDaemonError::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
