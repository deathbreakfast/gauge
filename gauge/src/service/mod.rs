//! Permission domain service layer.
//!
//! This module implements the domain behavior behind `gauge-app` and other
//! runtime callers.
//!
//! ## What it handles
//!
//! - Permission/group/domain CRUD with ownership/super-user authorization.
//! - Principal graph management (users/groups, nested membership, owners).
//! - Runtime access checks (`actor_can`, `user_can`) across direct and inherited grants.
//! - Permission request workflow (create/list/review/decide).
//! - History/audit projection for changed fields and actions.
//!
//! ## Errors
//!
//! Public functions return [`anyhow::Result`]. Classifiable failures use
//! [`GaugeServiceError`] (downcast via [`anyhow::Error::downcast_ref`]). Prefer
//! [`crate::resource_permissions::ResourcePermissionError`] at the host-wiring
//! boundary (`seed_resource_kind_catalog` / `ensure_resource_permission_bundle`).
//! Permission-check outcomes also emit Spectra rows via
//! [`crate::instrumentation`] (allow / deny / error).

mod access;
mod domains;
mod error;
mod groups;
mod helpers;
mod permissions;
mod requests;

/// Privacy-safe [`actor_can`] for `PolicyEvaluator`s — see [`crate::actor_can_raw`].
pub use crate::actor_can_raw::{actor_can_raw, user_can_raw};
pub use access::{actor_can, can_edit_group, can_edit_permission, has_permission, user_can};
pub use domains::{create_domain, get_domain_detail, list_domains};
pub use error::GaugeServiceError;
pub use groups::{
    add_group_member_group, add_group_member_user, add_group_owner_user, create_group,
    delete_group, remove_group_member_group, remove_group_member_user, remove_group_owner_user,
    update_group,
};
pub use permissions::{
    create_permission, delete_permission, get_group_detail, get_permission_detail,
    grant_permission_to_group, grant_permission_to_user, list_groups, list_permissions,
    revoke_permission_from_group, revoke_permission_from_user, update_permission,
};
pub use requests::{
    actor_can_view_history_subject, create_permission_request, decide_permission_request,
    get_permission_request_detail, list_history, list_permission_requests_for_actor,
    list_permission_requests_for_review, MAX_HISTORY_LIST_ROWS, MAX_REQUEST_REASON_CHARS,
};
