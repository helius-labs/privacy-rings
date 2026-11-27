use super::PhotonApiError;
use jsonrpsee::types::ErrorObjectOwned;

#[test]
fn rpc_failures_preserve_distinct_reasons_and_hide_internal_details() {
    let cases = [
        (
            PhotonApiError::ValidationError("invalid request".into()),
            -32600,
            "validation_error",
        ),
        (
            PhotonApiError::InvalidPubkey {
                field: "tree".into(),
            },
            -32600,
            "invalid_pubkey",
        ),
        (
            PhotonApiError::RecordNotFound("missing proof".into()),
            -32600,
            "record_not_found",
        ),
        (
            PhotonApiError::OutputLeafNotFound,
            -32600,
            "output_leaf_not_found",
        ),
        (PhotonApiError::StaleSlot(3), -32600, "stale_slot"),
        (
            PhotonApiError::MinimumContextSlot { context_slot: 7 },
            -32016,
            "minimum_context_slot",
        ),
        (
            PhotonApiError::StaleRoot("expired root".into()),
            -32600,
            "stale_root",
        ),
        (
            PhotonApiError::DatabaseError(sea_orm::DbErr::Custom("private database detail".into())),
            -32603,
            "database_error",
        ),
        (
            PhotonApiError::UnexpectedError("private internal detail".into()),
            -32603,
            "unexpected_error",
        ),
    ];
    for (failure, rpc_code, reason) in cases {
        let response = ErrorObjectOwned::from(failure);
        let diagnostics: serde_json::Value =
            serde_json::from_str(response.data().expect("structured reason").get())
                .expect("JSON diagnostics");
        assert_eq!(
            (
                response.code(),
                diagnostics.get("code").and_then(serde_json::Value::as_str)
            ),
            (rpc_code, Some(reason))
        );
        assert!(!response.to_string().contains("private"));
        if reason == "minimum_context_slot" {
            assert_eq!(diagnostics.get("contextSlot"), Some(&serde_json::json!(7)));
        }
    }
}
