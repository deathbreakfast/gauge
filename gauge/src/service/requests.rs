use chrono::Utc;
use lepton::generated::{ServiceUserAccount, ServiceUserAccountStatus};
use lepton_identity::service_users::{ServiceUserHandle, ServiceUserId};
use valence::{Model, RecordId, Valence};

use crate::generated::{
    PermissionHistory, PermissionRequest, PermissionRequestStatus, PermissionServiceUserPrincipal,
};
use crate::service_users::access::{service_user_decision, service_user_in_group};
use crate::service_users::SERVICE_USER_PRINCIPAL_TABLE;
use crate::super_user::actor_is_super_user;
use crate::types::{
    HistoryDiffItemDto, HistoryEntryDto, PermissionRequestCreateInput, PermissionRequestDecision,
    PermissionRequestDecisionInput, PermissionRequestRowDto, PermissionRequestTargetKind,
    PrincipalKind, PrincipalRefDto,
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
use super::permissions::{grant_permission_to_service_user, grant_permission_to_user};
use super::service_user_members::{
    add_group_member_service_user_via_request, ensure_service_user_principal,
};

/// Matches Valence `MaxLength(2000)` on `permission_request.reason`.
pub const MAX_REQUEST_REASON_CHARS: usize = 2000;

/// Cap for [`list_history`] rows loaded from Valence and returned after ownership filtering.
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

    let on_behalf_of = match request.on_behalf_of().as_ref() {
        Some(principal) => on_behalf_of_ref(principal, v).await?,
        None => None,
    };

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
        on_behalf_of,
    })
}

/// Build the display reference for a request's `on_behalf_of` service user: its handle as the
/// label. Control-plane raw reads, so the request's named service user resolves for the target's
/// maintainer deciding it, not only for the owner who filed it.
async fn on_behalf_of_ref(
    principal: &RecordId,
    v: &Valence,
) -> anyhow::Result<Option<PrincipalRefDto>> {
    let Some(row) =
        crate::actor_can_raw::raw_get_json(SERVICE_USER_PRINCIPAL_TABLE, principal.id(), v).await?
    else {
        return Ok(None);
    };
    let principal: PermissionServiceUserPrincipal = serde_json::from_value(row)?;
    let service_user_id =
        valence::extract_id_from_record(principal.service_user()).unwrap_or_default();
    if service_user_id.is_empty() {
        return Ok(None);
    }
    let Some(account_row) =
        crate::actor_can_raw::raw_get_json("service_user_account", &service_user_id, v).await?
    else {
        return Ok(None);
    };
    let account: ServiceUserAccount = serde_json::from_value(account_row)?;
    Ok(Some(PrincipalRefDto {
        kind: PrincipalKind::ServiceUser,
        id: service_user_id,
        label: account.handle().clone(),
        owner_label: None,
    }))
}

/// Resolve a `permission_request.on_behalf_of` principal record to the service user it names.
fn service_user_from_on_behalf_of(principal: &RecordId) -> anyhow::Result<ServiceUserId> {
    ServiceUserId::parse(principal.id()).map_err(|_| {
        anyhow::anyhow!(
            "request on_behalf_of names an invalid service user principal: {}",
            principal.id()
        )
    })
}

/// Resolve an `on_behalf_of` input (a service user's handle or id) to its id. Raw reads only;
/// the ownership gate is the typed load the caller runs next.
async fn resolve_on_behalf_of_service_user(
    raw: &str,
    v: &Valence,
) -> anyhow::Result<ServiceUserId> {
    let trimmed = raw.trim();
    if let Ok(id) = ServiceUserId::parse(trimmed) {
        return Ok(id);
    }
    let handle = ServiceUserHandle::normalize(trimmed).map_err(|_| {
        super::GaugeServiceError::validation("That service user handle or id is not valid")
    })?;
    let backend = v
        .backend_for_table("service_user_account")
        .map_err(|e| anyhow::anyhow!("resolve service_user_account backend: {e}"))?;
    let rows = backend
        .execute_compiled_query(&valence::__internal::CompiledQuery {
            query_string: "SELECT * FROM service_user_account WHERE handle_key = $key".to_string(),
            params: vec![("key".to_string(), serde_json::json!(handle.key()))],
        })
        .await
        .map_err(|e| anyhow::anyhow!("query service user by handle: {e}"))?;
    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| super::GaugeServiceError::validation("No service user with that handle"))?;
    let account: ServiceUserAccount = serde_json::from_value(row)?;
    let id = account
        .id()
        .and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap_or_default();
    ServiceUserId::parse(&id)
        .map_err(|_| anyhow::anyhow!("service user row has an invalid id: {id}"))
}

/// Resolve an `on_behalf_of` input and confirm the actor may request for it: the typed load
/// succeeds only for the owner or a manage-any holder, and the service user must be active.
async fn resolve_owned_active_service_user(
    raw: &str,
    v: &Valence,
) -> anyhow::Result<ServiceUserId> {
    let service_user = resolve_on_behalf_of_service_user(raw, v).await?;
    let account = ServiceUserAccount::get(service_user.as_str(), v, valence::use_!(r"When a user **files an access request on behalf of a service user**, we **load that service user** to confirm they own it (or may manage every service user) and that it is active. Only the owner's own check uses it; nothing about the service user is shown."))
        .await?
        .ok_or_else(|| {
            super::GaugeServiceError::validation(
                "You can only request access for a service user you own",
            )
        })?;
    if account.status() != &ServiceUserAccountStatus::Active {
        return Err(super::GaugeServiceError::validation(
            "That service user is paused; resume it before requesting access for it",
        )
        .into());
    }
    Ok(service_user)
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

    // When the request is for a service user, the actor must own that active service user (or
    // hold manage-any); the "already has / already a member" checks then run against the service
    // user rather than the actor, and the request is stored naming its principal.
    let on_behalf_of = match input.on_behalf_of.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => Some(resolve_owned_active_service_user(raw, v).await?),
        _ => None,
    };

    match input.target_kind {
        PermissionRequestTargetKind::Permission => {
            let permission = get_permission_raw(&input.target_id, system)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Permission not found: {}", input.target_id))?;
            if let Some(service_user) = &on_behalf_of {
                if service_user_decision(v, service_user, permission.name())
                    .await?
                    .allowed()
                {
                    return Err(super::GaugeServiceError::validation(
                        "That service user already has this permission",
                    )
                    .into());
                }
            } else if permission_allows_user(&permission, &actor_candidates, system).await? {
                anyhow::bail!("You already have this permission");
            }
        }
        PermissionRequestTargetKind::Group => {
            let group = get_group_raw(&input.target_id, system)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("Permission group not found: {}", input.target_id)
                })?;
            if let Some(service_user) = &on_behalf_of {
                if service_user_in_group(v, &input.target_id, service_user).await? {
                    return Err(super::GaugeServiceError::validation(
                        "That service user is already a member of this group",
                    )
                    .into());
                }
            } else if group_has_user(&group, &actor_candidates, system).await? {
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
    let on_behalf_of_record = match &on_behalf_of {
        Some(service_user) => {
            // The owner can see the service user here, so record its principal now; the
            // approving maintainer then adds it without needing to see the service user.
            let principal = ensure_service_user_principal(service_user, system).await?;
            Some(require_model_id(principal.id(), "on_behalf_of")?)
        }
        None => None,
    };
    let request = PermissionRequest::new(
        require_model_id(requestor.id(), "requestor")?,
        None,
        target_record,
        reason,
        PermissionRequestStatus::Pending,
        now,
        now,
        on_behalf_of_record,
    )?;
    let created = PermissionRequest::create(request, system, valence::use_!(r"When **Gauge permissions** needs to persist work, we **save Permission Request** so the next step in that feature can continue with the latest values. People and services allowed for **Gauge permissions** use this data for that workflow—not as a general export of unrelated personal fields.")).await?;
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
    let rows = PermissionRequest::query(lookup, valence::use_!(r"In **Gauge permissions**, we **list Permission Request** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
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
    let rows = PermissionRequest::query(lookup, valence::use_!(r"In **Gauge permissions**, we **list Permission Request** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
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
        .get_mutable(write, valence::use_!(r"In **Gauge permissions**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **Gauge permissions** use the updated data; this is not a public export of unrelated fields."))
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
        let on_behalf_of = request
            .on_behalf_of()
            .as_ref()
            .map(|principal| service_user_from_on_behalf_of(principal))
            .transpose()?;
        match request_target_kind_from_record(target) {
            Some(PermissionRequestTargetKind::Permission) => match &on_behalf_of {
                Some(service_user) => {
                    grant_permission_to_service_user(&target_id, service_user, v).await?;
                }
                None => grant_permission_to_user(&target_id, &requestor_user_id, v).await?,
            },
            Some(PermissionRequestTargetKind::Group) => match &on_behalf_of {
                Some(service_user) => {
                    add_group_member_service_user_via_request(&target_id, service_user, v).await?;
                }
                None => add_group_member_user(&target_id, &requestor_user_id, v).await?,
            },
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
///
/// Hard-caps the Valence query at [`MAX_HISTORY_LIST_ROWS`]. When both
/// `subject_kind` and `subject_id` are set, filters `source` in the query so
/// ownership checks never scan the full table.
pub async fn list_history(
    v: &Valence,
    subject_kind: Option<String>,
    subject_id: Option<String>,
) -> anyhow::Result<Vec<HistoryEntryDto>> {
    let _actor_user_id = require_user_id(v)?;
    let lookup = v;
    let mut query =
        PermissionHistory::query(lookup, valence::use_!(r"In **Gauge permissions**, we **list Permission History** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors.")).order_by_changed_at(valence::SortDirection::Desc);
    if let (Some(ref want_kind), Some(ref want_id)) = (&subject_kind, &subject_id) {
        if !want_kind.is_empty() && !want_id.is_empty() {
            query = query.where_source(valence::RecordPredicate::Equals(valence::RecordId::new(
                want_kind.as_str(),
                want_id.as_str(),
            )));
        }
    }
    #[allow(clippy::cast_possible_truncation)] // MAX_HISTORY_LIST_ROWS is 500
    let rows = query.limit(MAX_HISTORY_LIST_ROWS as u32).await?;
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
