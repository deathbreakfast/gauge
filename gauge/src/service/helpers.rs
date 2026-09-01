use chrono::Utc;
use valence::{Model, RecordId, Valence};

use crate::generated::{
    Permission, PermissionDomain, PermissionGroup, PermissionGroupPrincipal, PermissionRequest,
    PermissionRequestStatus, PermissionUserPrincipal,
};
use crate::super_user::actor_is_super_user;
use crate::types::{
    HistoryDiffItemDto, PermissionRequestStatusDto, PrincipalKind, PrincipalRefDto,
};

pub fn current_user_id(v: &Valence) -> Option<String> {
    v.actor().user_id().map(ToString::to_string)
}

pub fn user_id_candidates(user_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    out.push(user_id.to_string());
    if let Some((_, key)) = user_id.split_once(':') {
        out.push(key.to_string());
    }
    out.sort();
    out.dedup();
    out
}

pub fn canonical_user_id(user_id: &str) -> String {
    user_id
        .split_once(':')
        .map_or_else(|| user_id.to_string(), |(_, key)| key.to_string())
}

pub async fn get_user_by_actor_id(
    user_id: &str,
    system: &Valence,
) -> anyhow::Result<Option<lepton::generated::User>> {
    let lookup = system;
    for candidate in user_id_candidates(user_id) {
        if let Some(user) = lepton::generated::User::get(&candidate, lookup).await? {
            return Ok(Some(user));
        }
    }
    Ok(None)
}

pub fn record_pk_id(opt: Option<&valence::RecordId>) -> String {
    opt.and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap_or_default()
}

/// Require a persisted model id. Missing ids are invariant failures, not panics.
pub fn require_model_id(
    id: Option<&RecordId>,
    what: &str,
) -> Result<RecordId, super::GaugeServiceError> {
    id.cloned().ok_or_else(|| {
        super::GaugeServiceError::invariant(format!("{what} id missing after persist"))
    })
}

pub async fn require_raw_record(table: &str, id: &str, v: &Valence) -> anyhow::Result<()> {
    if id.is_empty() {
        anyhow::bail!("{table} id is required");
    }
    let backend = v
        .backend_for_table(table)
        .map_err(|e| anyhow::anyhow!("resolve backend for {table}: {e}"))?;
    let row = backend
        .get_record(table, id)
        .await
        .map_err(|e| anyhow::anyhow!("read {table}: {e}"))?;
    if row.is_none() {
        anyhow::bail!(
            "{} not found: {}",
            match table {
                "permission_domain" => "Permission domain",
                "permission_group" => "Owner group",
                other => other,
            },
            id
        );
    }
    Ok(())
}

/// Load all rows from a table via the raw backend.
///
/// Prefer [`permissions_named`] / [`groups_named`] (predicate queries) on hot
/// paths. Use this for list-all admin surfaces where a full scan is intentional.
/// Typed `Model::query` can drop trait fields (`name`) on some MEM/read-cache
/// paths; callers that need complete documents after a list scan decode here.
pub async fn raw_table_rows(table: &str, v: &Valence) -> anyhow::Result<Vec<serde_json::Value>> {
    let backend = v
        .backend_for_table(table)
        .map_err(|e| anyhow::anyhow!("resolve backend for {table}: {e}"))?;
    let rows = backend
        .execute_compiled_query(&valence::__internal::CompiledQuery {
            query_string: format!("SELECT * FROM {table}"),
            params: vec![],
        })
        .await
        .map_err(|e| anyhow::anyhow!("scan {table}: {e}"))?;
    Ok(rows)
}

/// Look up permissions by exact name (indexed predicate — not a full table scan).
pub async fn permissions_named(name: &str, v: &Valence) -> anyhow::Result<Vec<Permission>> {
    use valence::StringPredicate;

    Permission::query(v)
        .where_name(StringPredicate::Equals(name.to_string()))
        .await
        .map_err(|e| anyhow::anyhow!("query permission by name: {e}"))
}

/// Look up groups by exact name (indexed predicate — not a full table scan).
pub async fn groups_named(name: &str, v: &Valence) -> anyhow::Result<Vec<PermissionGroup>> {
    use valence::StringPredicate;

    PermissionGroup::query(v)
        .where_name(StringPredicate::Equals(name.to_string()))
        .await
        .map_err(|e| anyhow::anyhow!("query permission_group by name: {e}"))
}

pub async fn get_permission_raw(id: &str, v: &Valence) -> anyhow::Result<Option<Permission>> {
    let backend = v
        .backend_for_table("permission")
        .map_err(|e| anyhow::anyhow!("resolve permission backend: {e}"))?;
    match backend
        .get_record("permission", id)
        .await
        .map_err(|e| anyhow::anyhow!("read permission: {e}"))?
    {
        None => Ok(None),
        Some(row) => Ok(Some(
            serde_json::from_value(row).map_err(|e| anyhow::anyhow!("decode permission: {e}"))?,
        )),
    }
}

pub async fn get_group_raw(id: &str, v: &Valence) -> anyhow::Result<Option<PermissionGroup>> {
    let backend = v
        .backend_for_table("permission_group")
        .map_err(|e| anyhow::anyhow!("resolve permission_group backend: {e}"))?;
    match backend
        .get_record("permission_group", id)
        .await
        .map_err(|e| anyhow::anyhow!("read permission_group: {e}"))?
    {
        None => Ok(None),
        Some(row) => {
            Ok(Some(serde_json::from_value(row).map_err(|e| {
                anyhow::anyhow!("decode permission_group: {e}")
            })?))
        }
    }
}

pub async fn get_request_raw(id: &str, v: &Valence) -> anyhow::Result<Option<PermissionRequest>> {
    let backend = v
        .backend_for_table("permission_request")
        .map_err(|e| anyhow::anyhow!("resolve permission_request backend: {e}"))?;
    match backend
        .get_record("permission_request", id)
        .await
        .map_err(|e| anyhow::anyhow!("read permission_request: {e}"))?
    {
        None => Ok(None),
        Some(row) => {
            Ok(Some(serde_json::from_value(row).map_err(|e| {
                anyhow::anyhow!("decode permission_request: {e}")
            })?))
        }
    }
}

pub async fn get_domain_raw(id: &str, v: &Valence) -> anyhow::Result<Option<PermissionDomain>> {
    let backend = v
        .backend_for_table("permission_domain")
        .map_err(|e| anyhow::anyhow!("resolve permission_domain backend: {e}"))?;
    match backend
        .get_record("permission_domain", id)
        .await
        .map_err(|e| anyhow::anyhow!("read permission_domain: {e}"))?
    {
        None => Ok(None),
        Some(row) => {
            Ok(Some(serde_json::from_value(row).map_err(|e| {
                anyhow::anyhow!("decode permission_domain: {e}")
            })?))
        }
    }
}

pub fn user_principal_id(user_id: &str) -> String {
    format!("user:{}", canonical_user_id(user_id))
}

pub fn group_principal_id(group_id: &str) -> String {
    format!("permission_group:{group_id}")
}

pub fn principal_kind_from_record(r: &RecordId) -> Option<PrincipalKind> {
    match r.table() {
        "permission_user_principal" => Some(PrincipalKind::User),
        "permission_group_principal" => Some(PrincipalKind::Group),
        _ => None,
    }
}

pub async fn get_user_principal_raw(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionUserPrincipal>> {
    let backend = v
        .backend_for_table("permission_user_principal")
        .map_err(|e| anyhow::anyhow!("resolve permission_user_principal backend: {e}"))?;
    match backend
        .get_record("permission_user_principal", id)
        .await
        .map_err(|e| anyhow::anyhow!("read permission_user_principal: {e}"))?
    {
        None => Ok(None),
        Some(row) => Ok(Some(serde_json::from_value(row).map_err(|e| {
            anyhow::anyhow!("decode permission_user_principal: {e}")
        })?)),
    }
}

pub async fn get_group_principal_raw(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionGroupPrincipal>> {
    let backend = v
        .backend_for_table("permission_group_principal")
        .map_err(|e| anyhow::anyhow!("resolve permission_group_principal backend: {e}"))?;
    match backend
        .get_record("permission_group_principal", id)
        .await
        .map_err(|e| anyhow::anyhow!("read permission_group_principal: {e}"))?
    {
        None => Ok(None),
        Some(row) => Ok(Some(serde_json::from_value(row).map_err(|e| {
            anyhow::anyhow!("decode permission_group_principal: {e}")
        })?)),
    }
}

pub async fn ensure_user_principal(
    user_id: &str,
    system: &Valence,
) -> anyhow::Result<PermissionUserPrincipal> {
    let lookup = system;
    let user = lepton::generated::User::get(user_id, lookup)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found: {user_id}"))?;
    let user_thing = user
        .id()
        .ok_or_else(|| anyhow::anyhow!("User id missing: {user_id}"))?
        .clone();
    let principal_id = user_principal_id(user_id);
    if let Some(existing) = get_user_principal_raw(&principal_id, lookup).await? {
        return Ok(existing);
    }

    let principal = PermissionUserPrincipal::new(user_thing, canonical_user_id(user_id))?;
    Ok(PermissionUserPrincipal::upsert(&principal_id, principal, lookup).await?)
}

pub async fn ensure_group_principal(
    group_id: &str,
    system: &Valence,
) -> anyhow::Result<PermissionGroupPrincipal> {
    let lookup = system;
    let group = get_group_raw(group_id, lookup)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    let group_thing = group
        .id()
        .ok_or_else(|| anyhow::anyhow!("Permission group id missing: {group_id}"))?
        .clone();
    let principal_id = group_principal_id(group_id);
    if let Some(existing) = get_group_principal_raw(&principal_id, lookup).await? {
        return Ok(existing);
    }

    let principal = PermissionGroupPrincipal::new(group_thing, group_id.to_string())?;
    Ok(PermissionGroupPrincipal::upsert(&principal_id, principal, lookup).await?)
}

pub async fn principal_ref_from_record(
    rid: &RecordId,
    v: &Valence,
) -> anyhow::Result<Option<PrincipalRefDto>> {
    let system = v;
    let principal_id = rid.id().to_string();
    if principal_id.is_empty() {
        return Ok(None);
    }

    match principal_kind_from_record(rid) {
        Some(PrincipalKind::User) => {
            let Some(principal) = get_user_principal_raw(&principal_id, system).await? else {
                return Ok(None);
            };
            let user_id = valence::extract_id_from_record(principal.user()).unwrap_or_default();
            if user_id.is_empty() {
                return Ok(None);
            }
            let lookup = v;
            let label = match lepton::generated::User::get(&user_id, lookup).await? {
                Some(u) => match u.primary_email() {
                    Some(pid) => {
                        let bare = valence::extract_id_from_record(pid).unwrap_or_default();
                        lepton::generated::AccountEmail::get(&bare, lookup)
                            .await?
                            .map_or_else(|| user_id.clone(), |email| email.address().clone())
                    }
                    None => user_id.clone(),
                },
                None => user_id.clone(),
            };
            Ok(Some(PrincipalRefDto {
                kind: PrincipalKind::User,
                id: user_id,
                label,
            }))
        }
        Some(PrincipalKind::Group) => {
            let Some(principal) = get_group_principal_raw(&principal_id, system).await? else {
                return Ok(None);
            };
            let group_id = valence::extract_id_from_record(principal.group()).unwrap_or_default();
            if group_id.is_empty() {
                return Ok(None);
            }
            let label = get_group_raw(&group_id, system)
                .await?
                .map_or_else(|| group_id.clone(), |g| g.name().clone());
            Ok(Some(PrincipalRefDto {
                kind: PrincipalKind::Group,
                id: group_id,
                label,
            }))
        }
        None => Ok(None),
    }
}

pub const fn map_request_status(status: &PermissionRequestStatus) -> PermissionRequestStatusDto {
    match status {
        PermissionRequestStatus::Pending => PermissionRequestStatusDto::Pending,
        PermissionRequestStatus::Approved => PermissionRequestStatusDto::Approved,
        PermissionRequestStatus::Denied => PermissionRequestStatusDto::Denied,
    }
}

pub fn require_user_id(v: &Valence) -> anyhow::Result<String> {
    current_user_id(v).ok_or_else(|| anyhow::anyhow!("Authenticated user required"))
}

pub fn redact_user_principal_label(
    reference: PrincipalRefDto,
    reveal_email: bool,
) -> PrincipalRefDto {
    if reveal_email || reference.kind != PrincipalKind::User {
        return reference;
    }
    PrincipalRefDto {
        label: reference.id.clone(),
        ..reference
    }
}

pub async fn require_actor_controls_owner_group(group_id: &str, v: &Valence) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    if actor_is_super_user(v).await? {
        return Ok(());
    }
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let Some(group) = get_group_raw(group_id, system).await? else {
        anyhow::bail!("Owner group not found: {group_id}");
    };
    if !group_has_owner_user(&group, &actor_candidates, system).await? {
        anyhow::bail!("Not authorized to use owner group: {group_id}");
    }
    Ok(())
}

pub async fn resolve_or_create_default_owner_group(
    user_id: &str,
    system: &Valence,
) -> anyhow::Result<PermissionGroup> {
    let normalized_user_id = canonical_user_id(user_id);
    let group_id = format!("owner_group_{normalized_user_id}");
    if let Some(existing) = get_group_raw(&group_id, system).await? {
        return Ok(existing);
    }

    let now = Utc::now();
    let group = PermissionGroup::new(
        format!("{user_id} Owners"),
        Some("Default owner group for permission creation".to_string()),
        now,
        now,
    )?;
    let created = PermissionGroup::upsert(&group_id, group, system).await?;
    if let Some(user) = get_user_by_actor_id(user_id, system).await? {
        let principal = ensure_user_principal(&record_pk_id(user.id()), system).await?;
        created
            .relate_to_owner_record(&require_model_id(principal.id(), "principal")?, system)
            .await?;
        let principal = ensure_user_principal(&record_pk_id(user.id()), system).await?;
        created
            .relate_to_member_record(&require_model_id(principal.id(), "principal")?, system)
            .await?;
    }
    Ok(created)
}

pub async fn persist_history_entry(
    v: &Valence,
    subject_kind: &str,
    subject_id: String,
    _action: &str,
    actor_user_id: Option<String>,
    fields: Vec<HistoryDiffItemDto>,
) -> anyhow::Result<()> {
    use crate::side_effects::history_logger::append_history_row;
    use record_history::{history_edge_added, history_edge_removed, history_field_changed};

    let source = RecordId::new(subject_kind, &subject_id);
    let actor = actor_user_id.map(|uid| {
        let bare = valence::ownership::normalize_record_id_for_ownership(&uid);
        RecordId::new("user", bare)
    });

    for item in fields {
        let old_s = json_to_history_string(&item.old_value);
        let new_s = json_to_history_string(&item.new_value);
        let parts = if old_s.is_empty() && !new_s.is_empty() {
            history_edge_added(&item.field, &new_s)
        } else if !old_s.is_empty() && new_s.is_empty() {
            history_edge_removed(&item.field, &old_s)
        } else {
            history_field_changed(&item.field, &old_s, &new_s)
        };
        append_history_row(source.clone(), parts, actor.clone(), v).await?;
    }
    Ok(())
}

fn json_to_history_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Parse legacy blob-shaped `diff_json` into field diffs (pre-RecordHistory rows).
#[allow(dead_code)]
pub fn parse_history_diffs(diff_json: &serde_json::Value) -> Vec<HistoryDiffItemDto> {
    if let Some(items) = diff_json.get("fields").and_then(|v| v.as_array()) {
        return items
            .iter()
            .map(|item| HistoryDiffItemDto {
                field: item
                    .get("field")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                old_value: item
                    .get("old_value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                new_value: item
                    .get("new_value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            })
            .collect();
    }

    let before = diff_json.get("before").and_then(|v| v.as_object());
    let after = diff_json.get("after").and_then(|v| v.as_object());
    let mut keys = std::collections::BTreeSet::new();
    if let Some(map) = before {
        keys.extend(map.keys().cloned());
    }
    if let Some(map) = after {
        keys.extend(map.keys().cloned());
    }

    keys.into_iter()
        .filter_map(|field| {
            let old_value = before
                .and_then(|m| m.get(&field))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let new_value = after
                .and_then(|m| m.get(&field))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            if old_value == new_value {
                None
            } else {
                Some(HistoryDiffItemDto {
                    field,
                    old_value,
                    new_value,
                })
            }
        })
        .collect()
}

pub async fn group_has_user(
    group: &PermissionGroup,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![group.clone()];

    while let Some(current) = queue.pop() {
        let current_id = record_pk_id(current.id());
        if !visited.insert(current_id) {
            continue;
        }

        for owner in current.get_owners_record_ids(v).await? {
            let owner_id = owner.id().to_string();
            match principal_kind_from_record(&owner) {
                Some(PrincipalKind::User) => {
                    if let Some(principal) = get_user_principal_raw(&owner_id, v).await? {
                        let principal_user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &principal_user_id) {
                            return Ok(true);
                        }
                    }
                }
                Some(PrincipalKind::Group) => {
                    if let Some(principal) = get_group_principal_raw(&owner_id, v).await? {
                        let group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(child) = get_group_raw(&group_id, v).await? {
                            queue.push(child);
                        }
                    }
                }
                None => {}
            }
        }

        // New trait-targeted principal membership path.
        for member in current.get_members_record_ids(v).await? {
            let member_id = member.id().to_string();
            match principal_kind_from_record(&member) {
                Some(PrincipalKind::User) => {
                    if let Some(principal) = get_user_principal_raw(&member_id, v).await? {
                        let principal_user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &principal_user_id) {
                            return Ok(true);
                        }
                    }
                }
                Some(PrincipalKind::Group) => {
                    if let Some(principal) = get_group_principal_raw(&member_id, v).await? {
                        let group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(child) = get_group_raw(&group_id, v).await? {
                            queue.push(child);
                        }
                    }
                }
                None => {}
            }
        }
    }

    Ok(false)
}

pub async fn group_has_owner_user(
    group: &PermissionGroup,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![group.clone()];
    while let Some(current) = queue.pop() {
        let current_id = record_pk_id(current.id());
        if !visited.insert(current_id) {
            continue;
        }
        for owner in current.get_owners_record_ids(v).await? {
            let owner_id = owner.id().to_string();
            match principal_kind_from_record(&owner) {
                Some(PrincipalKind::User) => {
                    if let Some(principal) = get_user_principal_raw(&owner_id, v).await? {
                        let principal_user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &principal_user_id) {
                            return Ok(true);
                        }
                    }
                }
                Some(PrincipalKind::Group) => {
                    if let Some(principal) = get_group_principal_raw(&owner_id, v).await? {
                        let group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(nested_owner_group) = get_group_raw(&group_id, v).await? {
                            queue.push(nested_owner_group);
                        }
                    }
                }
                None => {}
            }
        }
    }
    Ok(false)
}
