use crate::metric;
use cadence_macros::statsd_count;
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use log::error;
use solana_pubkey::ParsePubkeyError;
use spr_indexer_api::ParseHashError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PhotonApiError {
    #[error("Validation Error: {0}")]
    ValidationError(String),
    #[error("Invalid Public Key: field '{field}'")]
    InvalidPubkey { field: String },
    #[error("Database Error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    #[error("Record Not Found: {0}")]
    RecordNotFound(String),
    #[error("Record Not Found: Some Rings output leaves were not found for the requested tree")]
    OutputLeafNotFound,
    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),
    #[error("Node is behind {0} slots")]
    StaleSlot(u64),
    #[error("Minimum context slot has not been reached")]
    MinimumContextSlot { context_slot: u64 },
    /// The indexed root is no longer in the chain's root history, so Photon
    /// cannot provide the history entry a client must quote. Retryable.
    #[error("Stale Root: {0}")]
    StaleRoot(String),
}

impl PhotonApiError {
    fn reason(&self) -> &'static str {
        match self {
            Self::ValidationError(_) => "validation_error",
            Self::InvalidPubkey { .. } => "invalid_pubkey",
            Self::DatabaseError(_) => "database_error",
            Self::RecordNotFound(_) => "record_not_found",
            Self::OutputLeafNotFound => "output_leaf_not_found",
            Self::UnexpectedError(_) => "unexpected_error",
            Self::StaleSlot(_) => "stale_slot",
            Self::MinimumContextSlot { .. } => "minimum_context_slot",
            Self::StaleRoot(_) => "stale_root",
        }
    }
}

impl From<PhotonApiError> for ErrorObjectOwned {
    fn from(val: PhotonApiError) -> Self {
        match val {
            PhotonApiError::MinimumContextSlot { context_slot } => ErrorObjectOwned::owned(
                -32016,
                "Minimum context slot has not been reached",
                Some(
                    serde_json::json!({"code": "minimum_context_slot", "contextSlot": context_slot}),
                ),
            ),
            PhotonApiError::ValidationError(_) => {
                metric! {
                    statsd_count!("validation_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::InvalidPubkey { .. } => {
                metric! {
                    statsd_count!("invalid_pubkey_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::RecordNotFound(_) | PhotonApiError::OutputLeafNotFound => {
                metric! {
                    statsd_count!("record_not_found_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::StaleSlot(_) => {
                metric! {
                    statsd_count!("stale_slot_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::StaleRoot(_) => {
                metric! {
                    statsd_count!("stale_root_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::DatabaseError(e) => {
                error!("Internal server database error: {}", e);
                metric! {
                    statsd_count!("internal_database_api_error", 1);
                }
                internal_server_error("database_error")
            }
            PhotonApiError::UnexpectedError(e) => {
                error!("Internal server error: {}", e);
                metric! {
                    statsd_count!("unexpected_api_error", 1);
                }
                internal_server_error("unexpected_error")
            }
        }
    }
}

// The API contract receives parsed input from the user, so if we get a ParseHashError it means
// that the database itself returned an invalid hash.
impl From<ParseHashError> for PhotonApiError {
    fn from(_error: ParseHashError) -> Self {
        PhotonApiError::UnexpectedError("Invalid hash in database".to_string())
    }
}

impl From<ParsePubkeyError> for PhotonApiError {
    fn from(_error: ParsePubkeyError) -> Self {
        PhotonApiError::UnexpectedError("Invalid public key in database".to_string())
    }
}

fn invalid_request(e: PhotonApiError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InvalidRequest.code(),
        e.to_string(),
        Some(serde_json::json!({"code": e.reason()})),
    )
}

fn internal_server_error(code: &'static str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "Internal server error",
        Some(serde_json::json!({"code": code})),
    )
}

#[cfg(test)]
#[path = "error_test.rs"]
mod tests;
