//! Side effects for the permission domain.

/// History append on permission/group mutations (`defer_to_edge`).
#[cfg(feature = "ssr")]
pub mod history_logger;
/// Notifies on permission-request submit and decide.
#[cfg(feature = "ssr")]
pub mod permission_request_notifier;
