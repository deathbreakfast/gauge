//! Permission domain DTO contracts.
//!
//! These types are shared across server functions and UI flows for:
//! - permission/group/domain CRUD payloads,
//! - principal references and assignment displays,
//! - permission request lifecycle rows and decisions,
//! - history/audit diff rendering.

use serde::{Deserialize, Serialize};

/// Kind of principal a permission/group can be assigned to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A single user.
    User,
    /// A permission group (which may itself contain users and nested groups).
    Group,
}

/// Lightweight reference to a principal (user or group) for display in UI lists.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalRefDto {
    /// Whether this principal is a user or a group.
    pub kind: PrincipalKind,
    /// Bare record id of the principal.
    pub id: String,
    /// Display label (name/email) for the principal.
    pub label: String,
}

/// Input for creating a new permission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionCreateInput {
    /// Permission name (unique within its domain).
    pub name: String,
    /// Human-readable description of what the permission grants.
    pub description: String,
    /// Id of the group that owns/administers this permission.
    pub owners_group_id: String,
    /// Id of the permission domain this permission belongs to.
    pub domain_id: String,
}

/// Input for creating a new permission group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionGroupCreateInput {
    /// Group name.
    pub name: String,
    /// Human-readable description of the group's purpose.
    pub description: String,
}

/// Input for creating a new permission domain (taxonomy root).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDomainCreateInput {
    /// Domain name.
    pub name: String,
    /// Human-readable description of the domain.
    pub description: String,
}

/// Permission domain detail view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDomainDetailDto {
    /// Bare record id.
    pub id: String,
    /// Domain name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Full permission detail view, including its allow-list and domain context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDetailDto {
    /// Bare record id.
    pub id: String,
    /// Permission name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// User id of the permission's creator.
    pub created_by_user_id: String,
    /// Id of the group that owns/administers this permission.
    pub owners_group_id: String,
    /// Id of the permission domain this permission belongs to.
    pub domain_id: String,
    /// Display name of the permission domain.
    pub domain_name: String,
    /// Principals currently granted this permission.
    ///
    /// Populated only for editors (owners-group maintainers and Super User).
    /// Empty for every other authenticated reader — an empty list means the
    /// grant graph is withheld, not that nobody holds the permission.
    pub allow_list: Vec<PrincipalRefDto>,
    /// Whether the current actor may submit an access request for this permission.
    pub can_request_access: bool,
}

/// Full permission group detail view, including owners and members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionGroupDetailDto {
    /// Bare record id.
    pub id: String,
    /// Group name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Users who own/administer this group.
    ///
    /// Populated only for group owners and Super User; empty otherwise.
    pub owner_users: Vec<PrincipalRefDto>,
    /// Users and nested groups that are members of this group.
    ///
    /// Populated only for group owners and Super User; empty otherwise.
    pub members: Vec<PrincipalRefDto>,
    /// Whether the current actor may submit an access request to join this group.
    pub can_request_access: bool,
}

/// One field-level change within a [`HistoryEntryDto`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryDiffItemDto {
    /// Name of the field that changed.
    pub field: String,
    /// Value before the change (JSON-encoded).
    pub old_value: serde_json::Value,
    /// Value after the change (JSON-encoded).
    pub new_value: serde_json::Value,
}

/// One audit history row for a permission/group subject.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntryDto {
    /// Bare record id of the history row.
    pub id: String,
    /// Kind of subject this row describes (`"permission"`, `"group"`, …).
    pub subject_kind: String,
    /// Id of the subject this row describes.
    pub subject_id: String,
    /// User id of the actor who made the change, if any (`None` for system actions).
    pub actor_user_id: Option<String>,
    /// Action performed (`"created"`, `"updated"`, `"deleted"`, …).
    pub action: String,
    /// ISO-8601 timestamp of the change.
    pub changed_at: String,
    /// Field-level diffs for this change.
    pub diffs: Vec<HistoryDiffItemDto>,
}

/// What kind of entity a permission request targets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionRequestTargetKind {
    /// The request targets a single permission.
    Permission,
    /// The request targets membership in a group.
    Group,
}

/// Lifecycle status of a permission/group access request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionRequestStatusDto {
    /// Awaiting reviewer decision.
    Pending,
    /// Reviewer approved the request.
    Approved,
    /// Reviewer denied the request.
    Denied,
}

/// Input for submitting a new access request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRequestCreateInput {
    /// Whether the request targets a permission or a group.
    pub target_kind: PermissionRequestTargetKind,
    /// Id of the targeted permission or group.
    pub target_id: String,
    /// Requestor-supplied justification.
    pub reason: String,
}

/// Approve or deny decision for a permission request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionRequestDecision {
    /// Grant the requested permission or group membership.
    Approve,
    /// Reject the request without granting access.
    Deny,
}

/// Input for approving or denying an existing access request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRequestDecisionInput {
    /// Id of the request being decided.
    pub request_id: String,
    /// Approve or deny.
    pub decision: PermissionRequestDecision,
}

/// Row shape for permission request inbox/list views.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRequestRowDto {
    /// Bare record id of the request.
    pub id: String,
    /// Whether the request targets a permission or a group.
    pub target_kind: PermissionRequestTargetKind,
    /// Id of the targeted permission or group.
    pub target_id: String,
    /// Display label of the targeted permission or group.
    pub target_label: String,
    /// User id of the requestor.
    pub requestor_user_id: String,
    /// User id of the reviewer who decided the request, if decided.
    pub approver_user_id: Option<String>,
    /// Requestor-supplied justification.
    pub reason: String,
    /// Current lifecycle status.
    pub status: PermissionRequestStatusDto,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 last-updated timestamp.
    pub updated_at: String,
    /// Whether the current actor may review (approve/deny) this request.
    pub can_review: bool,
}
