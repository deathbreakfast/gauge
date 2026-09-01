//! Gauge permission-check Spectra telemetry (UC1 + UC3).
//!
//! [`record_permission_check`] is the choke-point emitter used by
//! [`crate::service::actor_can`] / [`crate::service::user_can`].
//!
//! Set a surface tag with [`PermissionCheckCallerGuard`] (e.g. route-guard
//! server fns). Topic / metric types for consumers live under
//! `crate::spectra_topics` when the `spectra-topics` feature is enabled.

mod events;
mod permission_check;

pub use permission_check::{
    begin_permission_check_capture, coarse_permission_kind, record_permission_check,
    take_permission_check_captures, with_permission_check_caller, CapturedPermissionCheck,
    PermissionCheckCallerGuard, PermissionCheckOutcome, PermissionCheckRecord,
};
