#![allow(clippy::too_many_arguments)]

//! Spectra metric for `gauge_permission_checks`, generated via `spectra_metric!`.
#![allow(missing_docs)]

use spectra::spectra_metric;

spectra_metric! {
    GaugePermissionChecks {
        store: "gauge",
        name: "gauge_permission_checks",
        version: "0.1.0",
        description: "Permission check outcomes. Labels: permission_kind, outcome.",
    }
}
