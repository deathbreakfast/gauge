use chrono::Utc;
use valence::{Model, Valence};

use crate::generated::{PermissionHistory, PermissionRequest, PermissionRequestStatus};
use crate::super_user::actor_is_super_user;
use crate::types::{
    HistoryDiffItemDto, HistoryEntryDto, PermissionRequestCreateInput, PermissionRequestDecision,
    PermissionRequestDecisionInput, PermissionRequestRowDto, PermissionRequestTargetKind,
};

use super::access::{
    actor_can_review_target, can_edit_group, can_edit_permission, permission_allows_user,
    request_target_kind_from_record, request_target_record,
};
use super::groups::add_group_member_user;
use super::helpers::{
    get_group_raw, get_permission_raw, get_request_raw, get_user_by_actor_id, group_has_user,
    map_request_status, record_pk_id, require_model_id, require_user_id, user_id_candidates,
};
use super::permissions::grant_permission_to_user;

/// Matches Valence `MaxLength(2000)` on `permission_request.reason`.
pub const MAX_REQUEST_REASON_CHARS: usize = 2000;

/// Cap for [`list_history`] result rows after ownership filtering.
pub const MAX_HISTORY_LIST_ROWS: usize = 500;

pub async fn request_row_from_model(
    request: &PermissionRequest,
    v: &Valence,
) -> anyhow::Result<PermissionRequestRowDto> {
    let system = v;
    let target = request.target();
    let target_id = valence::extract_id_from_record(target).unwrap_or_default();
    let target_kind = request_target_kind_from_record(target)
        .ok_or_else(|| anyhow::anyhow!("Unsupported request target type"))?;

    let target_label = match target_kind {
        PermissionRequestTargetKind::Permission => get_permission_raw(&target_id, system)
            .await?
            .map_or_else(|| format!("Permission {target_id}"), |p| p.name().clone()),
        PermissionRequestTargetKind::Group => get_group_raw(&target_id, system)
            .await?
            .map_or_else(|| format!("Group {target_id}"), |g| g.name().clone()),
    };

    let approver_user_id = request
        .approver()
        .as_ref()
        .and_then(|t| valence::extract_id_from_record(t).ok());
    let can_review = actor_can_review_target(target, v).await?;

    Ok(PermissionRequestRowDto {
        id: record_pk_id(request.id()),
        target_kind,
        target_id,
        target_label,
        requestor_user_id: valence::extract_id_from_record(request.requestor()).unwrap_or_default(),
        approver_user_id,
        reason: request.reason().clone(),
        status: map_request_status(request.status()),
        created_at: request.created_at().to_rfc3339(),
        updated_at: request.updated_at().to_rfc3339(),
        can_review,
    })
}

/// Submit a new access request for a permission or group; fails if the current
/// actor already has the permission or is already a group member.
pub async fn create_permission_request(
    input: PermissionRequestCreateInput,
    v: &Valence,
) -> anyhow::Result<PermissionRequestRowDto> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let target_record = request_target_record(&input.target_kind, &input.target_id);

    match input.target_kind {
        PermissionRequestTargetKind::Permission => {
            let permission = get_permission_raw(&input.target_id, system)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Permission not found: {}", input.target_id))?;
            if permission_allows_user(&permission, &actor_candidates, system).await? {
                anyhow::bail!("You already have this permission");
            }
        }
        PermissionRequestTargetKind::Group => {
            let group = get_group_raw(&input.target_id, system)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("Permission group not found: {}", input.target_id)
                })?;
            if group_has_user(&group, &actor_candidates, system).await? {
                return Err(super::GaugeServiceError::validation(
                    "You are already a member of this group",
                )
                .into());
            }
        }
    }

    let requestor = get_user_by_actor_id(&actor_user_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Actor user not found: {actor_user_id}"))?;
    let now = Utc::now();
    let reason = input.reason.trim().to_string();
    if reason.is_empty() {
        return Err(super::GaugeServiceError::validation("Reason is required").into());
    }
    if reason.chars().count() > MAX_REQUEST_REASON_CHARS {
        return Err(super::GaugeServiceError::validation(format!(
            "Reason is too long (max {MAX_REQUEST_REASON_CHARS} characters)"
        ))
        .into());
    }
    let request = PermissionRequest::new(
        require_model_id(requestor.id(), "requestor")?,
        None,
        target_record,
        reason,
        PermissionRequestStatus::Pending,
        now,
        now,
    )?;
    let created = PermissionRequest::create(request, system).await?;
    request_row_from_model(&created, v).await
}

/// List the current actor's own access requests, newest first.
pub async fn list_permission_requests_for_actor(
    v: &Valence,
) -> anyhow::Result<Vec<PermissionRequestRowDto>> {
    let actor_user_id = require_user_id(v)?;
    let Some(requestor) = get_user_by_actor_id(&actor_user_id, v).await? else {
        return Ok(Vec::new());
    };
    let lookup = v;
    let rows = PermissionRequest::query(lookup)
        .where_requestor(valence::RecordPredicate::Equals(require_model_id(
            requestor.id(),
            "requestor",
        )?))
        .order_by_created_at(valence::SortDirection::Desc)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(request_row_from_model(&row, v).await?);
    }
    Ok(out)
}

/// List pending access requests the current actor may review. Super users get an
/// empty queue here by design (see inline note) rather than every pending request.
pub async fn list_permission_requests_for_review(
    v: &Valence,
) -> anyhow::Result<Vec<PermissionRequestRowDto>> {
    if actor_is_super_user(v).await? {
        // Super users can still review requests directly, but they should not
        // receive a global review queue by default.
        return Ok(Vec::new());
    }

    let lookup = v;
    let rows = PermissionRequest::query(lookup)
        .where_status(valence::StringPredicate::Equals("PENDING".to_string()))
        .order_by_created_at(valence::SortDirection::Desc)
        .await?;

    let mut out = Vec::new();
    for row in rows {
        if actor_can_review_target(row.target(), v).await? {
            out.push(request_row_from_model(&row, v).await?);
        }
    }
    Ok(out)
}

/// Load a single access request by id, visible only to its requestor, an eligible
/// reviewer, or a super user; `None` if it does not exist.
pub async fn get_permission_request_detail(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionRequestRowDto>> {
    let system = v;
    let Some(request) = get_request_raw(id, system).await? else {
        return Ok(None);
    };

    if actor_is_super_user(v).await? {
        return Ok(Some(request_row_from_model(&request, v).await?));
    }

    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let requestor_user_id =
        valence::extract_id_from_record(request.requestor()).unwrap_or_default();
    let is_requestor = actor_candidates.iter().any(|id| id == &requestor_user_id);
    let can_review = actor_can_review_target(request.target(), v).await?;
    if !is_requestor && !can_review {
        anyhow::bail!("Not authorized to view this request");
    }

    Ok(Some(request_row_from_model(&request, v).await?))
}

/// Approve or deny a pending access request (eligible reviewer or super user only).
/// On approval, grants the permission or adds the requestor to the group.
pub async fn decide_permission_request(
    input: PermissionRequestDecisionInput,
    v: &Valence,
) -> anyhow::Result<PermissionRequestRowDto> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let request = get_request_raw(&input.request_id, system)
        .await?
        .ok_or_else(|| {
            super::GaugeServiceError::not_found("Permission request", &input.request_id)
        })?;

    if !actor_can_review_target(request.target(), v).await? && !actor_is_super_user(v).await? {
        return Err(super::GaugeServiceError::not_authorized("review this request").into());
    }
    if !matches!(request.status(), PermissionRequestStatus::Pending) {
        return Err(
            super::GaugeServiceError::validation("Only pending requests can be reviewed").into(),
        );
    }

    let approver = get_user_by_actor_id(&actor_user_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Actor user not found: {actor_user_id}"))?;
    let new_status = match input.decision {
        PermissionRequestDecision::Approve => PermissionRequestStatus::Approved,
        PermissionRequestDecision::Deny => PermissionRequestStatus::Denied,
    };

    let write = v;
    request
        .get_mutable(write)
        .set_approver(require_model_id(approver.id(), "approver")?)?
        .set_status(new_status)?
        .set_updated_at(Utc::now())?
        .commit()
        .await?;

    if matches!(input.decision, PermissionRequestDecision::Approve) {
        let requestor_user_id =
            valence::extract_id_from_record(request.requestor()).unwrap_or_default();
        let target = request.target();
        let target_id = valence::extract_id_from_record(target).unwrap_or_default();
        match request_target_kind_from_record(target) {
            Some(PermissionRequestTargetKind::Permission) => {
                grant_permission_to_user(&target_id, &requestor_user_id, v).await?;
            }
            Some(PermissionRequestTargetKind::Group) => {
                add_group_member_user(&target_id, &requestor_user_id, v).await?;
            }
            None => anyhow::bail!("Unsupported request target type"),
        }
    }

    let updated = get_request_raw(&input.request_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission request not found after update"))?;
    request_row_from_model(&updated, v).await
}

/// List audit history rows, newest first, optionally filtered by `subject_kind`
/// and/or `subject_id`.
///
/// Thin compatibility over `RecordHistory` rows. Prefer
/// `record_history_leptos::HistoryTimeline` for new UI. Requires an authenticated
/// actor. Non–super-users only see history for subjects they can edit.
pub async fn list_history(
    v: &Valence,
    subject_kind: Option<String>,
    subject_id: Option<String>,
) -> anyhow::Result<Vec<HistoryEntryDto>> {
    let _actor_user_id = require_user_id(v)?;
    let lookup = v;
    let rows = PermissionHistory::query(lookup)
        .order_by_changed_at(valence::SortDirection::Desc)
        .await?;
    let is_super = actor_is_super_user(v).await?;
    let mut out = Vec::with_capacity(rows.len().min(MAX_HISTORY_LIST_ROWS));
    for row in rows {
        let source = row.source();
        let row_kind = source.table();
        let row_subject_id = source.id().to_string();
        if let Some(ref want_kind) = subject_kind {
            if row_kind != want_kind.as_str() {
                continue;
            }
        }
        if let Some(ref want) = subject_id {
            if row_subject_id != *want {
                continue;
            }
        }
        if !is_super && !actor_can_view_history_subject(row_kind, &row_subject_id, v).await? {
            continue;
        }

        let field = row.field_name().clone();
        let old_s = row.old_value().clone();
        let new_s = row.new_value().clone();
        let action = match field.as_str() {
            "created" => "create".to_string(),
            "deleted" => "delete".to_string(),
            "name" | "description" | "owners_group" | "domain" => "update".to_string(),
            other => other.to_string(),
        };
        let diffs = vec![HistoryDiffItemDto {
            field: field.clone(),
            old_value: if old_s.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(old_s)
            },
            new_value: if new_s.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(new_s)
            },
        }];

        out.push(HistoryEntryDto {
            id: record_pk_id(row.id()),
            subject_kind: row_kind.to_string(),
            subject_id: row_subject_id,
            actor_user_id: row.actor().map(|a| a.id().to_string()),
            action,
            changed_at: row.changed_at().to_rfc3339(),
            diffs,
        });
        if out.len() >= MAX_HISTORY_LIST_ROWS {
            break;
        }
    }
    Ok(out)
}

/// `true` when the actor may view history for `subject_kind`/`subject_id`.
///
/// Matches edit authorization: permission owners (via owners group) or group
/// owners, plus super users. Used by timeline fetches so AUTHENTICATED parent
/// Read does not widen history beyond can-edit.
pub async fn actor_can_view_history_subject(
    subject_kind: &str,
    subject_id: &str,
    v: &Valence,
) -> anyhow::Result<bool> {
    let system = v;
    match subject_kind {
        "permission" => {
            let Some(permission) = get_permission_raw(subject_id, system).await? else {
                return Ok(false);
            };
            can_edit_permission(&permission, v).await
        }
        "permission_group" => {
            let Some(group) = get_group_raw(subject_id, system).await? else {
                return Ok(false);
            };
            can_edit_group(&group, v).await
        }
        _ => Ok(false),
    }
}
