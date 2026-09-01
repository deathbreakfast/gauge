//! Super-user capability checks and bootstrap helpers.
//!
//! Resolves the singleton Super User permission group and related membership
//! scripts used by Chronon ops and runtime bypass checks.

use chrono::Utc;
use std::collections::HashSet;
use valence::{Model, StringPredicate, Valence};

use crate::generated::{PermissionGroup, PermissionGroupPrincipal, PermissionUserPrincipal};

/// Display name of the hard-coded, singleton Super User permission group.
pub const SUPER_USER_GROUP_NAME: &str = "Super User";

/// Well-known record id for the singleton Super User permission group.
///
/// Super-user checks must resolve this id only. Duplicate groups that reuse
/// [`SUPER_USER_GROUP_NAME`] must not grant privileges (see GA-04).
pub const SUPER_USER_GROUP_ID: &str = "super_user_group";

fn canonical_user_id(user_id: &str) -> String {
    user_id
        .split_once(':')
        .map_or_else(|| user_id.to_string(), |(_, key)| key.to_string())
}

fn user_principal_id(user_id: &str) -> String {
    format!("user:{}", canonical_user_id(user_id))
}

fn principal_kind_label(r: &valence::RecordId) -> Option<&'static str> {
    match r.table() {
        "permission_user_principal" => Some("user"),
        "permission_group_principal" => Some("group"),
        _ => None,
    }
}

async fn ensure_user_principal(
    user: &lepton::generated::User,
    system: &Valence,
) -> anyhow::Result<PermissionUserPrincipal> {
    let user_id = valence::extract_id_from_record(
        user.id()
            .ok_or_else(|| anyhow::anyhow!("user id missing after persist"))?,
    )?;
    let principal_id = user_principal_id(&user_id);
    if let Some(existing) = PermissionUserPrincipal::get(&principal_id, system).await? {
        return Ok(existing);
    }
    let principal = PermissionUserPrincipal::new(
        user.id()
            .ok_or_else(|| anyhow::anyhow!("user id missing after persist"))?
            .clone(),
        canonical_user_id(&user_id),
    )?;
    Ok(PermissionUserPrincipal::upsert(&principal_id, principal, system).await?)
}

/// `true` when the request actor is a system actor or a (possibly transitive) member
/// of the well-known [`SUPER_USER_GROUP_ID`] group.
///
/// Membership in any other group that happens to be named [`SUPER_USER_GROUP_NAME`]
/// is ignored (fail closed against duplicate-name privilege escalation).
pub async fn actor_is_super_user(v: &Valence) -> anyhow::Result<bool> {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(crate::touch_schema_inventory);

    if v.actor().is_system() {
        return Ok(true);
    }
    let Some(actor_user_id) = v.actor().user_id() else {
        return Ok(false);
    };
    let mut user_ids = vec![actor_user_id.to_string()];
    if let Some((_, bare)) = actor_user_id.split_once(':') {
        user_ids.push(bare.to_string());
    }
    user_ids.sort();
    user_ids.dedup();

    let system = v.with_actor(valence::Actor::System {
        operation: "permission_actor_is_super_user".to_string(),
    });
    let Some(group) = load_super_user_group_raw(&system).await? else {
        return Ok(false);
    };
    group_has_recursive_member(&group, &user_ids, &system).await
}

async fn load_super_user_group_raw(system: &Valence) -> anyhow::Result<Option<PermissionGroup>> {
    get_group_raw(SUPER_USER_GROUP_ID, system).await
}

/// Get or create the singleton Super User group at [`SUPER_USER_GROUP_ID`].
///
/// Duplicate rows that reuse [`SUPER_USER_GROUP_NAME`] under other ids are logged and
/// ignored; only the well-known id is authoritative.
pub async fn ensure_super_user_group(system: &Valence) -> anyhow::Result<PermissionGroup> {
    if let Some(existing) = load_super_user_group_raw(system).await? {
        warn_duplicate_super_user_name_groups(system).await?;
        return Ok(existing);
    }

    let now = Utc::now();
    let created = PermissionGroup::upsert(
        SUPER_USER_GROUP_ID,
        PermissionGroup::new(
            SUPER_USER_GROUP_NAME.to_string(),
            Some("Hard-coded singleton super-user group".to_string()),
            now,
            now,
        )?,
        system,
    )
    .await?;
    warn_duplicate_super_user_name_groups(system).await?;
    Ok(created)
}

async fn warn_duplicate_super_user_name_groups(system: &Valence) -> anyhow::Result<()> {
    let groups = PermissionGroup::query(system)
        .where_name(StringPredicate::Equals(SUPER_USER_GROUP_NAME.to_string()))
        .await?;
    let foreign = groups
        .iter()
        .filter(|g| {
            g.id()
                .and_then(|id| valence::extract_id_from_record(id).ok())
                .as_deref()
                != Some(SUPER_USER_GROUP_ID)
        })
        .count();
    if foreign > 0 {
        log::warn!(
            "Ignoring {foreign} duplicate '{SUPER_USER_GROUP_NAME}' permission group(s); only '{SUPER_USER_GROUP_ID}' is authoritative for super-user checks."
        );
    }
    Ok(())
}

/// Idempotently add every `owner` / `super_admin` account member to the Super User group.
///
/// This is used by the [`sync_super_user_membership_roles`](crate::scripts::sync_super_user_membership_roles)
/// Chronon job (scheduled) so membership stays aligned without relying on the one-shot
/// `ensure_super_user_group` bootstrap script.
pub async fn resync_eligible_super_user_group_members(system: &Valence) -> anyhow::Result<()> {
    let group = ensure_super_user_group(system).await?;
    sync_eligible_roles_into_super_group(system, &group).await
}

async fn sync_eligible_roles_into_super_group(
    system: &Valence,
    super_group: &PermissionGroup,
) -> anyhow::Result<()> {
    let role_memberships = lepton::generated::AccountMembership::query(system)
        .where_role(StringPredicate::Equals("owner".to_string()))
        .union(
            lepton::generated::AccountMembership::query(system)
                .where_role(StringPredicate::Equals("super_admin".to_string())),
        )
        .await?;

    for membership in role_memberships {
        let user = membership.get_user(system).await?;
        ensure_user_in_super_group(super_group, &user, system).await?;
    }

    Ok(())
}

/// Backwards-compatible name for [`resync_eligible_super_user_group_members`].
pub async fn seed_super_user_members_from_roles(
    system: &Valence,
    super_group: &PermissionGroup,
) -> anyhow::Result<()> {
    sync_eligible_roles_into_super_group(system, super_group).await
}

/// Add the user with the given `email` to `super_group` as both owner and member.
/// Errors if no user matches `email`.
pub async fn seed_super_user_member_by_email(
    system: &Valence,
    super_group: &PermissionGroup,
    email: &str,
) -> anyhow::Result<()> {
    let email_rows = lepton::generated::AccountEmail::query(system)
        .where_address(StringPredicate::Equals(email.to_string()))
        .await?;
    if email_rows.is_empty() {
        anyhow::bail!("no user found for email {email}");
    }
    for row in email_rows {
        let Some(email_id) = row.id().cloned() else {
            continue;
        };
        let Some(user) = lepton::generated::User::query(system)
            .where_primary_email(valence::RecordPredicate::Equals(email_id))
            .first()
            .await?
        else {
            continue;
        };
        ensure_user_in_super_group(super_group, &user, system).await?;
    }
    Ok(())
}

async fn ensure_user_in_super_group(
    super_group: &PermissionGroup,
    user: &lepton::generated::User,
    system: &Valence,
) -> anyhow::Result<()> {
    let owner_ids: HashSet<String> = super_group
        .get_owners_record_ids(system)
        .await?
        .into_iter()
        .filter_map(|rid| {
            if principal_kind_label(&rid) != Some("user") {
                return None;
            }
            Some(rid.id().to_string())
        })
        .collect();
    let principal = ensure_user_principal(user, system).await?;
    let owner_principal_id = valence::extract_id_from_record(
        principal
            .id()
            .ok_or_else(|| anyhow::anyhow!("principal id missing after persist"))?,
    )?;
    if !owner_ids.contains(&owner_principal_id) {
        super_group
            .relate_to_owner_record(
                principal
                    .id()
                    .ok_or_else(|| anyhow::anyhow!("principal id missing after persist"))?,
                system,
            )
            .await?;
    }

    let member_ids: HashSet<String> = super_group
        .get_members_record_ids(system)
        .await?
        .into_iter()
        .map(|rid| rid.id().to_string())
        .collect();
    let principal = ensure_user_principal(user, system).await?;
    let principal_id = valence::extract_id_from_record(
        principal
            .id()
            .ok_or_else(|| anyhow::anyhow!("principal id missing after persist"))?,
    )?;
    if !member_ids.contains(&principal_id) {
        super_group
            .relate_to_member_record(
                principal
                    .id()
                    .ok_or_else(|| anyhow::anyhow!("principal id missing after persist"))?,
                system,
            )
            .await?;
    }

    Ok(())
}

async fn get_user_principal_raw(
    id: &str,
    system: &Valence,
) -> anyhow::Result<Option<PermissionUserPrincipal>> {
    let backend = system
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

async fn get_group_principal_raw(
    id: &str,
    system: &Valence,
) -> anyhow::Result<Option<PermissionGroupPrincipal>> {
    let backend = system
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

async fn get_group_raw(id: &str, system: &Valence) -> anyhow::Result<Option<PermissionGroup>> {
    let backend = system
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

async fn group_has_recursive_member(
    group: &PermissionGroup,
    user_ids: &[String],
    system: &Valence,
) -> anyhow::Result<bool> {
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![group.clone()];
    while let Some(current) = queue.pop() {
        let current_id = valence::extract_id_from_record(
            current
                .id()
                .ok_or_else(|| anyhow::anyhow!("group id missing after persist"))?,
        )?;
        if !visited.insert(current_id) {
            continue;
        }

        for owner in current.get_owners_record_ids(system).await? {
            let owner_id = owner.id().to_string();
            match principal_kind_label(&owner) {
                Some("user") => {
                    if let Some(principal) = get_user_principal_raw(&owner_id, system).await? {
                        let owner_user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &owner_user_id) {
                            return Ok(true);
                        }
                    }
                }
                Some("group") => {
                    if let Some(principal) = get_group_principal_raw(&owner_id, system).await? {
                        let nested_group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(nested) = get_group_raw(&nested_group_id, system).await? {
                            queue.push(nested);
                        }
                    }
                }
                _ => {}
            }
        }
        for member in current.get_members_record_ids(system).await? {
            let member_table = member.table();
            let member_id = member.id().to_string();
            if member_id.is_empty() {
                continue;
            }
            match member_table {
                "permission_user_principal" => {
                    if let Some(principal) = get_user_principal_raw(&member_id, system).await? {
                        let user_id =
                            valence::extract_id_from_record(principal.user()).unwrap_or_default();
                        if user_ids.iter().any(|id| id == &user_id) {
                            return Ok(true);
                        }
                    }
                }
                "permission_group_principal" => {
                    if let Some(principal) = get_group_principal_raw(&member_id, system).await? {
                        let group_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(nested) = get_group_raw(&group_id, system).await? {
                            queue.push(nested);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(false)
}
