//! Reusable privacy policy rules for permission-domain Valence schemas.

use async_trait::async_trait;
use std::any::Any;
use valence::{Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, Valence};

use crate::generated::{
    Permission, PermissionGroup, PermissionGroupPrincipal, PermissionUserPrincipal,
};
use crate::super_user::SUPER_USER_GROUP_ID;

/// Privacy policy allowing group update/delete for owners, including owners
/// inherited transitively through nested owner groups.
#[derive(Debug, Clone)]
pub struct GroupOwnerRecursive;

#[async_trait]
impl PolicyEvaluator for GroupOwnerRecursive {
    fn name(&self) -> &'static str {
        "perm::GROUP_OWNER_RECURSIVE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Allow group update/delete for recursive owners")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> valence::Result<bool> {
        let actor = actor_from_context(actor)?;
        group_owner_recursive(op, record, &actor, v).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Privacy policy allowing permission update/delete for the permission's owners
/// group, including owners inherited transitively through nested owner groups.
#[derive(Debug, Clone)]
pub struct PermissionOwnerRecursive;

#[async_trait]
impl PolicyEvaluator for PermissionOwnerRecursive {
    fn name(&self) -> &'static str {
        "perm::PERMISSION_OWNER_RECURSIVE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Allow permission update/delete for recursive owners")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> valence::Result<bool> {
        let actor = actor_from_context(actor)?;
        permission_owner_recursive(op, record, &actor, v).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Shared [`GroupOwnerRecursive`] instance for use in schema `privacy_policies` declarations.
pub const GROUP_OWNER_RECURSIVE: GroupOwnerRecursive = GroupOwnerRecursive;
/// Shared [`PermissionOwnerRecursive`] instance for use in schema `privacy_policies` declarations.
pub const PERMISSION_OWNER_RECURSIVE: PermissionOwnerRecursive = PermissionOwnerRecursive;
/// Shared [`RequestTargetMaintainer`] instance for permission-request decide updates.
pub const REQUEST_TARGET_MAINTAINER: RequestTargetMaintainer = RequestTargetMaintainer;
/// Shared [`SuperUserGroupMember`] instance for use in schema `privacy_policies` declarations.
pub const SUPER_USER_GROUP_MEMBER: SuperUserGroupMember = SuperUserGroupMember;

/// Allow permission-request **update** (decide) when the actor maintains the request target.
#[derive(Debug, Clone)]
pub struct RequestTargetMaintainer;

#[async_trait]
impl PolicyEvaluator for RequestTargetMaintainer {
    fn name(&self) -> &'static str {
        "perm::REQUEST_TARGET_MAINTAINER"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Allow request decide when actor maintains the target permission or group")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> valence::Result<bool> {
        let actor = actor_from_context(actor)?;
        if actor.is_system() {
            return Ok(true);
        }
        if !matches!(op, PrivacyOperation::Update) {
            return Ok(false);
        }
        let user_ids = actor_candidates(&actor);
        if user_ids.is_empty() {
            return Ok(false);
        }
        let Some(target) = record.get("target") else {
            return Ok(false);
        };
        let Some((table, id)) = target_table_and_id(target) else {
            return Ok(false);
        };
        match table.as_str() {
            "permission" => {
                let Some(row) = raw_get_json("permission", &id, v).await.map_err(|e| {
                    Error::Privacy(format!(
                        "Policy request target permission lookup failed: {e}"
                    ))
                })?
                else {
                    return Ok(false);
                };
                let permission: Permission = serde_json::from_value(row).map_err(|e| {
                    Error::Privacy(format!("Policy request target permission decode: {e}"))
                })?;
                let owners_group_id =
                    valence::extract_id_from_record(permission.owners_group()).unwrap_or_default();
                if owners_group_id.is_empty() {
                    return Ok(false);
                }
                let Some(row) = raw_get_json("permission_group", &owners_group_id, v)
                    .await
                    .map_err(|e| {
                        Error::Privacy(format!("Policy request target owners_group failed: {e}"))
                    })?
                else {
                    return Ok(false);
                };
                let owners_group: PermissionGroup = serde_json::from_value(row).map_err(|e| {
                    Error::Privacy(format!("Policy request target owners_group decode: {e}"))
                })?;
                group_has_recursive_owner(&owners_group, &user_ids, v)
                    .await
                    .map_err(|e| Error::Privacy(format!("Policy request target recursion: {e}")))
            }
            "permission_group" => {
                let Some(row) = raw_get_json("permission_group", &id, v)
                    .await
                    .map_err(|e| {
                        Error::Privacy(format!("Policy request target group lookup failed: {e}"))
                    })?
                else {
                    return Ok(false);
                };
                let group: PermissionGroup = serde_json::from_value(row).map_err(|e| {
                    Error::Privacy(format!("Policy request target group decode: {e}"))
                })?;
                group_has_recursive_owner(&group, &user_ids, v)
                    .await
                    .map_err(|e| Error::Privacy(format!("Policy request target recursion: {e}")))
            }
            _ => Ok(false),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn target_table_and_id(target: &serde_json::Value) -> Option<(String, String)> {
    if let Some(s) = target.as_str() {
        let (table, id) = s.split_once(':')?;
        return Some((table.to_string(), id.to_string()));
    }
    let obj = target.as_object()?;
    let table = obj
        .get("table")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)?;
    let id = if let Some(s) = obj.get("id").and_then(|v| v.as_str()) {
        s.to_string()
    } else {
        obj.get("id")
            .and_then(|v| v.as_object())
            .and_then(|inner| inner.get("String"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string)?
    };
    Some((table, id))
}

/// Privacy policy allowing access for any actor in the hard-coded Super User group
/// (see [`crate::super_user`]), including membership inherited through nested groups.
#[derive(Debug, Clone)]
pub struct SuperUserGroupMember;

#[async_trait]
impl PolicyEvaluator for SuperUserGroupMember {
    fn name(&self) -> &'static str {
        "perm::SUPER_USER_GROUP_MEMBER"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Allow actors in the hard-coded Super User group")
    }

    async fn evaluate(
        &self,
        _op: PrivacyOperation,
        _record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> valence::Result<bool> {
        let actor = actor_from_context(actor)?;
        actor_in_super_user_group(&actor, v).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn actor_from_context(actor: &dyn ActorContext) -> valence::Result<Actor> {
    serde_json::from_value(actor.actor_json().clone())
        .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))
}

fn actor_candidates(actor: &Actor) -> Vec<String> {
    let mut out = Vec::new();
    let Some(user_id) = actor.user_id() else {
        return out;
    };
    out.push(user_id.to_string());
    if let Some((_, id)) = user_id.split_once(':') {
        out.push(id.to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn model_pk_id(opt: Option<&valence::RecordId>) -> String {
    opt.and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap_or_default()
}

fn record_id(record: &serde_json::Value) -> Option<String> {
    if let Some(id) = record.get("id").and_then(|v| v.as_str()) {
        if let Some((_, bare)) = id.split_once(':') {
            return Some(bare.to_string());
        }
        return Some(id.to_string());
    }

    if let Some(obj) = record.get("id").and_then(|v| v.as_object()) {
        if let Some(thing_id) = obj.get("id") {
            if let Some(s) = thing_id.as_str() {
                return Some(s.to_string());
            }
            if let Some(inner) = thing_id.as_object() {
                if let Some(s) = inner.get("String").and_then(|v| v.as_str()) {
                    return Some(s.to_string());
                }
                if let Some(n) = inner.get("Number").and_then(serde_json::Value::as_i64) {
                    return Some(n.to_string());
                }
            }
        }
        if let Some(s) = obj.get("String").and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }

    None
}

async fn raw_get_json(
    table: &str,
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<serde_json::Value>> {
    let backend = v
        .backend_for_table(table)
        .map_err(|e| anyhow::anyhow!("resolve {table} backend: {e}"))?;
    backend
        .get_record(table, id)
        .await
        .map_err(|e| anyhow::anyhow!("read {table}: {e}"))
}

async fn group_has_recursive_owner(
    group: &PermissionGroup,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    // Raw backend walks — same as service `group_has_owner_user` — so policy
    // evaluation does not re-enter typed privacy for principal hops.
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![group.clone()];

    while let Some(current) = queue.pop() {
        let current_id = model_pk_id(current.id());
        if !visited.insert(current_id) {
            continue;
        }

        for owner in current.get_owners_record_ids(v).await? {
            let owner_id = owner.id().to_string();
            match owner.table() {
                "permission_user_principal" => {
                    if let Some(row) =
                        raw_get_json("permission_user_principal", &owner_id, v).await?
                    {
                        let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                        let owner_user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &owner_user_id) {
                            return Ok(true);
                        }
                    }
                }
                "permission_group_principal" => {
                    if let Some(row) =
                        raw_get_json("permission_group_principal", &owner_id, v).await?
                    {
                        let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                        let owner_group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(row) =
                            raw_get_json("permission_group", &owner_group_id, v).await?
                        {
                            let owner_group: PermissionGroup = serde_json::from_value(row)?;
                            queue.push(owner_group);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(false)
}

async fn group_owner_recursive(
    op: PrivacyOperation,
    record: &serde_json::Value,
    actor: &Actor,
    v: &Valence,
) -> valence::Result<bool> {
    if actor.is_system() {
        return Ok(true);
    }
    if !matches!(op, PrivacyOperation::Update | PrivacyOperation::Delete) {
        return Ok(false);
    }

    let user_ids = actor_candidates(actor);
    if user_ids.is_empty() {
        return Ok(false);
    }
    let Some(group_id) = record_id(record) else {
        return Ok(false);
    };

    let Some(row) = raw_get_json("permission_group", &group_id, v)
        .await
        .map_err(|e| Error::Privacy(format!("Policy lookup failed for group {group_id}: {e}")))?
    else {
        return Ok(false);
    };
    let group: PermissionGroup = serde_json::from_value(row)
        .map_err(|e| Error::Privacy(format!("Policy group decode failed for {group_id}: {e}")))?;

    group_has_recursive_owner(&group, &user_ids, v)
        .await
        .map_err(|e| Error::Privacy(format!("Policy recursion failed for group {group_id}: {e}")))
}

async fn permission_owner_recursive(
    op: PrivacyOperation,
    record: &serde_json::Value,
    actor: &Actor,
    v: &Valence,
) -> valence::Result<bool> {
    if actor.is_system() {
        return Ok(true);
    }
    if !matches!(op, PrivacyOperation::Update | PrivacyOperation::Delete) {
        return Ok(false);
    }

    let user_ids = actor_candidates(actor);
    if user_ids.is_empty() {
        return Ok(false);
    }
    let Some(permission_id) = record_id(record) else {
        return Ok(false);
    };

    let Some(row) = raw_get_json("permission", &permission_id, v)
        .await
        .map_err(|e| {
            Error::Privacy(format!(
                "Policy lookup failed for permission {permission_id}: {e}"
            ))
        })?
    else {
        return Ok(false);
    };
    let permission: Permission = serde_json::from_value(row).map_err(|e| {
        Error::Privacy(format!(
            "Policy permission decode failed for {permission_id}: {e}"
        ))
    })?;

    let owners_group_id =
        valence::extract_id_from_record(permission.owners_group()).unwrap_or_default();
    if owners_group_id.is_empty() {
        return Ok(false);
    }
    let Some(row) = raw_get_json("permission_group", &owners_group_id, v)
        .await
        .map_err(|e| {
            Error::Privacy(format!(
                "Policy owners_group lookup failed for permission {permission_id}: {e}"
            ))
        })?
    else {
        return Ok(false);
    };
    let owners_group: PermissionGroup = serde_json::from_value(row).map_err(|e| {
        Error::Privacy(format!(
            "Policy owners_group decode failed for permission {permission_id}: {e}"
        ))
    })?;

    group_has_recursive_owner(&owners_group, &user_ids, v)
        .await
        .map_err(|e| {
            Error::Privacy(format!(
                "Policy recursion failed for permission {permission_id}: {e}"
            ))
        })
}

async fn actor_in_super_user_group(actor: &Actor, v: &Valence) -> valence::Result<bool> {
    if actor.is_system() {
        return Ok(true);
    }
    let user_ids = actor_candidates(actor);
    if user_ids.is_empty() {
        return Ok(false);
    }

    let system = v;
    // Raw read: typed get can drop trait fields under in-memory backends.
    let backend = system
        .backend_for_table("permission_group")
        .map_err(|e| Error::Privacy(format!("Policy super-group backend resolve failed: {e}")))?;
    let Some(row) = backend
        .get_record("permission_group", SUPER_USER_GROUP_ID)
        .await
        .map_err(|e| Error::Privacy(format!("Policy super-group lookup failed: {e}")))?
    else {
        return Ok(false);
    };
    let group: PermissionGroup = serde_json::from_value(row)
        .map_err(|e| Error::Privacy(format!("Policy super-group decode failed: {e}")))?;

    group_has_recursive_member(&group, &user_ids, system)
        .await
        .map_err(|e| Error::Privacy(format!("Policy super-group recursion failed: {e}")))
}

async fn group_has_recursive_member(
    group: &PermissionGroup,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    // Raw walks only — typed PermissionGroup::get re-enters SUPER_USER always_allow
    // and stack-overflows.
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![group.clone()];

    while let Some(current) = queue.pop() {
        let current_id = model_pk_id(current.id());
        if !visited.insert(current_id) {
            continue;
        }

        for owner in current.get_owners_record_ids(v).await? {
            let owner_id = owner.id().to_string();
            match owner.table() {
                "permission_user_principal" => {
                    if let Some(row) =
                        raw_get_json("permission_user_principal", &owner_id, v).await?
                    {
                        let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                        let owner_user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &owner_user_id) {
                            return Ok(true);
                        }
                    }
                }
                "permission_group_principal" => {
                    if let Some(row) =
                        raw_get_json("permission_group_principal", &owner_id, v).await?
                    {
                        let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                        let owner_group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(row) =
                            raw_get_json("permission_group", &owner_group_id, v).await?
                        {
                            queue.push(serde_json::from_value(row)?);
                        }
                    }
                }
                _ => {}
            }
        }

        for member in current.get_members_record_ids(v).await? {
            let member_table = member.table();
            let member_id = member.id().to_string();
            if member_id.is_empty() {
                continue;
            }
            match member_table {
                "permission_user_principal" => {
                    if let Some(row) =
                        raw_get_json("permission_user_principal", &member_id, v).await?
                    {
                        let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                        let user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &user_id) {
                            return Ok(true);
                        }
                    }
                }
                "permission_group_principal" => {
                    if let Some(row) =
                        raw_get_json("permission_group_principal", &member_id, v).await?
                    {
                        let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                        let group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(row) = raw_get_json("permission_group", &group_id, v).await? {
                            queue.push(serde_json::from_value(row)?);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(false)
}
