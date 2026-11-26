//! Permission domain DTO contracts.
//!
//! These types are shared across server functions and UI flows for:
//! - permission/group/domain CRUD payloads,
//! - principal references and assignment displays,
//! - permission request lifecycle rows and decisions,
//! - history/audit diff rendering.

use serde::{Deserialize, Serialize};

/// Lifecycle of a managed group (one with `managed_by` set), as the managing product reports it.
///
/// Stored as the group's `managed_status` text. An archived group keeps its grants and loses its
/// members, so restoring it in the managing product restores access.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ManagedStatus {
    /// The mirrored thing (a team) is live and the group follows its roster.
    Active,
    /// The mirrored thing is archived; the managing product has emptied the group.
    Archived,
}

impl ManagedStatus {
    /// Stored value: `active` or `archived`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }

    /// Parse a stored `managed_status` value; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }
}

/// Kind of principal a permission/group can be assigned to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalKind {
    /// A single user.
    User,
    /// A permission group (which may itself contain users and nested groups).
    Group,
    /// A Lepton service user (non-human). Only ever a group member.
    ServiceUser,
}

/// Lightweight reference to a principal (user, group, or service user) for display in UI lists.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalRefDto {
    /// Whether this principal is a user, a group, or a service user.
    pub kind: PrincipalKind,
    /// Bare record id of the principal.
    pub id: String,
    /// Display label (name/email) for the principal. A service user's handle.
    pub label: String,
    /// Display label of the owning user. Set only for [`PrincipalKind::ServiceUser`],
    /// and `None` when the service user has no owner or the owner can't be loaded.
    pub owner_label: Option<String>,
}

/// Input for creating a new permission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionCreateInput {
    /// The name people read, for example "Approve payroll runs". Empty means "use the key".
    #[serde(default)]
    pub display_name: String,
    /// The key code checks (`actor_can`), unique across Gauge. It never changes after create.
    /// Empty means the display name in `PascalCase` ("Approve payroll runs" becomes
    /// `ApprovePayrollRuns`).
    pub name: String,
    /// What the permission grants, as Markdown text.
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
    /// The group's purpose, as Markdown text.
    pub description: String,
}

/// Input for creating a new permission domain (taxonomy root).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDomainCreateInput {
    /// Domain name.
    pub name: String,
    /// What the domain covers, as Markdown text.
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
    /// Users who own/administer this taxonomy domain.
    ///
    /// Populated only for domain owners and Super User; empty otherwise.
    /// Always empty for list responses.
    pub owner_users: Vec<PrincipalRefDto>,
    /// Whether this domain was created for a resource permission bundle.
    pub resource_scoped: bool,
}

/// Full permission detail view, including its allow-list and domain context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDetailDto {
    /// Bare record id.
    pub id: String,
    /// Permission key: the name code checks. Never changes after create.
    pub name: String,
    /// The name people read. The key for rows written before display names existed.
    #[serde(default)]
    pub display_name: String,
    /// Description, as Markdown text.
    pub description: String,
    /// User id of the permission's creator.
    ///
    /// Empty for callers without `GaugeAdmin` (list and detail share this DTO).
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

/// A group a service user holds, as listed on the service user's access page.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceUserGroupDto {
    /// Bare record id.
    pub id: String,
    /// Group name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// A permission a service user holds and the group it comes through.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceUserPermissionDto {
    /// Permission name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The group the permission is granted to. `None` for a grant made straight to the service user.
    pub via_group: Option<ServiceUserGroupDto>,
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
    /// The requester withdrew the request while it was pending.
    Withdrawn,
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
    /// When set, the request is for a service user the requestor owns, named by its handle or
    /// id. The requestor must own that active service user, or hold
    /// `lepton.service_user.manage_any`.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
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
    /// Display name of the requester (their profile name or email), so pages never show ids.
    #[serde(default)]
    pub requester_label: String,
    /// User id of who decided the request: the reviewer, or the requester for a withdrawal.
    /// `None` while pending.
    #[serde(default)]
    pub decided_by: Option<String>,
    /// Display name of [`Self::decided_by`].
    #[serde(default)]
    pub decided_by_label: Option<String>,
    /// When the request was approved, denied or withdrawn. `None` while pending, and for
    /// requests decided before this was recorded.
    #[serde(default)]
    pub decided_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The reviewer's reason, on a denied request.
    #[serde(default)]
    pub deny_reason: Option<String>,
    /// The service user the request is for, when filed on behalf of one, with its handle in
    /// [`PrincipalRefDto::label`]. `owner_label` holds the owning user's display label. `None` for a plain user
    /// request.
    #[serde(default)]
    pub on_behalf_of: Option<PrincipalRefDto>,
}

/// A permission, named for people: its id, key and display name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PermissionRef {
    /// Bare record id.
    pub id: String,
    /// The key code checks (`permission.name`).
    pub key: String,
    /// The name people read.
    pub display_name: String,
}

/// A group, by id and name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GroupRef {
    /// Bare record id.
    pub id: String,
    /// Group name.
    pub name: String,
}

/// A principal as pages show it. Same shape as [`PrincipalRefDto`].
pub type PrincipalRef = PrincipalRefDto;

/// Names a user or service user to look up, without a label.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalKey {
    /// [`PrincipalKind::User`] or [`PrincipalKind::ServiceUser`].
    pub kind: PrincipalKind,
    /// Bare user id, or the service user's id.
    pub id: String,
}

/// How a principal comes to hold a permission.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessPath {
    /// The permission's allow list names the principal.
    Direct,
    /// Through groups, outermost first: the group the allow list names, then each nested group
    /// down to the one the principal is a member (or owner) of.
    ThroughGroup(Vec<GroupRef>),
    /// The principal is a Super User, who passes every check.
    SuperUser,
}

/// One principal that passes a permission's check, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HolderRow {
    /// Who holds it.
    pub principal: PrincipalRef,
    /// Display name: a person's profile name or email, a service user's handle.
    pub label: String,
    /// [`PrincipalKind::User`] or [`PrincipalKind::ServiceUser`].
    pub kind: PrincipalKind,
    /// The owning user's label, for a service user.
    pub owner_label: Option<String>,
    /// Every way the principal holds the permission.
    pub paths: Vec<AccessPath>,
    /// When the direct grant was made, when the history has it.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
}

/// What kind of Gauge record a [`RecordRef`] names.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// A permission.
    Permission,
    /// A permission group.
    Group,
    /// A permission domain.
    Domain,
    /// An access request.
    Request,
}

/// A Gauge record, named for people.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RecordRef {
    /// What kind of record it is.
    pub kind: RecordKind,
    /// Bare record id.
    pub id: String,
    /// Its display name (a permission's display name, a group's or domain's name).
    pub label: String,
}

/// One page of a longer list.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page<T> {
    /// The rows on this page.
    pub items: Vec<T>,
    /// Pass this back to get the next page. `None` on the last page.
    pub next_cursor: Option<String>,
}

/// A user or service user Gauge knows, for the People list.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonRow {
    /// Who it is.
    pub principal: PrincipalRef,
    /// Groups they are a member or owner of, directly.
    pub groups: Vec<GroupRef>,
    /// Permissions granted to them directly.
    pub direct_permissions: Vec<PermissionRef>,
}

/// A group a principal belongs to, with who added them and when.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMembership {
    /// The group.
    pub group: GroupRef,
    /// Who added them, when the history has it.
    pub added_by_label: Option<String>,
    /// When they were added, when the history has it.
    pub added_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Everything one person or service user can do in Gauge, and why.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrincipalAccess {
    /// Each permission they hold, with every path to it.
    pub permissions: Vec<(PermissionRef, Vec<AccessPath>)>,
    /// Groups they are directly a member (or owner) of.
    pub groups: Vec<GroupMembership>,
    /// Permissions and groups they own, directly or through an owner group.
    pub owns: Vec<RecordRef>,
    /// Their pending access requests (for a service user, the ones filed for it).
    pub open_requests: Vec<PermissionRequestRowDto>,
}

/// What a change log row is about.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ActivityKind {
    /// A permission was created, edited or deleted.
    Permission,
    /// A permission's allow list changed.
    Grant,
    /// A group was created, edited or deleted, or its owners changed.
    Group,
    /// A group's members changed.
    Membership,
    /// A domain changed.
    Domain,
    /// An access request was filed, decided or withdrawn.
    Request,
}

/// Which change log rows to return. Empty fields match everything.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityFilter {
    /// Only these kinds. Empty means every kind.
    #[serde(default)]
    pub kinds: Vec<ActivityKind>,
    /// Only changes at or after this time.
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Only changes by this user id.
    #[serde(default)]
    pub actor: Option<String>,
    /// Only changes to this record (kind and id; the label is ignored).
    #[serde(default)]
    pub record: Option<RecordRef>,
    /// Only rows whose summary, actor or record name contains this text (any case).
    #[serde(default)]
    pub query: Option<String>,
}

/// One change, in words.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityRow {
    /// When it happened.
    pub at: chrono::DateTime<chrono::Utc>,
    /// Who did it: a display name, or "Gauge" for system changes.
    pub actor_label: String,
    /// What happened, as a sentence by name ("Removed Ravi Menon from the group").
    pub summary: String,
    /// The record it happened to.
    pub record: RecordRef,
    /// What kind of change it is.
    pub kind: ActivityKind,
}
