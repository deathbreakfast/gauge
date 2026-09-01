#![allow(clippy::too_many_arguments)]

//! Spectra schema for `gauge_permission_check_log`, generated via `spectra_schema!`.
#![allow(missing_docs)]

use spectra::spectra_schema;

spectra_schema! {
    GaugePermissionCheckLog {
        store: "gauge",
        table: "gauge_permission_check_log",
        version: "0.1.0",
        description: "One row per permission check attempt (allow/deny/error/no_actor).",
        fields: [
            permission_name: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
            outcome: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
            operation: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
            caller: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
            viewer_key: {
                r#type: String,
                classification: { pii: true, safe_for_console: false },
            },
            error_message: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
        ],
    }
}
