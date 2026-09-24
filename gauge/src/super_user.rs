//! Super-user capability checks and bootstrap helpers.
//!
//! Resolves the singleton Super User permission group and related membership
//! scripts used by Chronon ops and runtime bypass checks.
//!
//! # Actor elevation (SM-25)
//!
//! [`actor_is_super_user`] walks the well-known Super User group graph under the
//! **request** Valence with raw backend reads (same shape as
//! [`crate::actor_can_raw`]). It must not rebind to `Actor::System` mid-request.
//! That path is for membership evaluation only — never for TOTP step-up, grant
//! mutations, or vault material.
//!
//! Chronon scripts in [`crate::scripts`] start as System from their job context
//! (not a session elevate). TM-SEC-06 / `tests/no_elevate_path_gate.rs` forbids
//! `with_actor(Actor::System …)` outside its allowlist; this module is not on
//! that list.

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
    if let Some(existing) = PermissionUserPrincipal::get(&principal_id, system, valence::use_!(r"In **Gauge permissions**, we **load Permission User Principal** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await? {
        return Ok(existing);
    }
    let principal = PermissionUserPrincipal::new(
        user.id()
            .ok_or_else(|| anyhow::anyhow!("user id missing after persist"))?
            .clone(),
        canonical_user_id(&user_id),
    )?;
    Ok(PermissionUserPrincipal::upsert(&principal_id, principal, system, valence::use_!(r"When **Gauge permissions** needs to persist work, we **save Permission User Principal** so the next step in that feature can continue with the latest values. People and services allowed for **Gauge permissions** use this data for that workflow—not as a general export of unrelated personal fields.")).await?)
}

/// `true` when the request actor is a system actor or a (possibly transitive) member
/// of the well-known [`SUPER_USER_GROUP_ID`] group.
///
/// Membership in any other group that happens to be named [`SUPER_USER_GROUP_NAME`]
/// is ignored (fail closed against duplicate-name privilege escalation).
///
/// Uses raw backend reads under the **session** Valence (no mid-request System elevate).
/// Typed `PermissionGroup::get` would re-enter privacy; raw walks match
/// [`crate::actor_can_raw`] and the Super User policy evaluator.
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

    // Raw membership walk under the request Valence — no System rebind.
    let Some(group) = load_super_user_group_raw(v).await? else {
        return Ok(false);
    };
    group_has_recursive_member(&group, &user_ids, v).await
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
        valence::use_!(r"When **Gauge permissions** needs to persist work, we **save Permission Group** so the next step in that feature can continue with the latest values. People and services allowed for **Gauge permissions** use this data for that workflow—not as a general export of unrelated personal fields."),
    )
    .await?;
    warn_duplicate_super_user_name_groups(system).await?;
    Ok(created)
}

async fn warn_duplicate_super_user_name_groups(system: &Valence) -> anyhow::Result<()> {
    let groups = PermissionGroup::query(system, valence::use_!(r"In **Gauge permissions**, we **list Permission Group** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
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
    let role_memberships = lepton::generated::AccountMembership::query(system, valence::use_!(r"In **Gauge permissions**, we **list Account Membership** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
        .where_role(StringPredicate::Equals("owner".to_string()))
        .union(
            lepton::generated::AccountMembership::query(system, valence::use_!(r"In **Gauge permissions**, we **list Account Membership** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
                .where_role(StringPredicate::Equals("super_admin".to_string())),
        )
        .await?;

    for membership in role_memberships {
        let user = membership
            .get_user(
                system,
                valence::use_!(r#"When Gauge **syncs Super User members from account roles**, we **follow each membership’s user link** so eligible owners and super-admins can be added to the Super User group. Operators see the updated Super User membership list."#),
            )
            .await?;
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

/// Counts from a best-effort multi-email Super User seed pass.
///
/// Hosts log these fields (never the email list) after boot bootstrap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SuperUserSeedStats {
    /// Number of email addresses supplied to the seed call.
    pub configured: usize,
    /// Addresses that resolved to a Lepton user and were ensured as members.
    pub seeded: usize,
    /// Addresses with no matching Lepton user (safe to retry after signup).
    pub missing_user: usize,
    /// Addresses that failed for another reason (Valence / relate errors).
    pub failed: usize,
}

/// Add the user with the given `email` to `super_group` as both owner and member.
///
/// # Errors
///
/// Returns when no Lepton user matches `email`, or when principal / relate writes fail.
pub async fn seed_super_user_member_by_email(
    system: &Valence,
    super_group: &PermissionGroup,
    email: &str,
) -> anyhow::Result<()> {
    let email_rows = lepton::generated::AccountEmail::query(system, valence::use_!(r"In **Gauge permissions**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
        .where_address(StringPredicate::Equals(email.to_string()))
        .await?;
    if email_rows.is_empty() {
        anyhow::bail!("no user found for email {email}");
    }
    for row in email_rows {
        let Some(email_id) = row.id().cloned() else {
            continue;
        };
        let Some(user) = lepton::generated::User::query(system, valence::use_!(r"In **Gauge permissions**, we **list User** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors."))
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

/// Idempotently seed every address in `emails` into `super_group`.
///
/// Missing users increment [`SuperUserSeedStats::missing_user`] and do not abort the
/// batch (host boot can restart after signup). Other failures increment `failed`.
///
/// # Errors
///
/// This helper does not return soft missing-user failures. It only returns when a
/// caller-supplied invariant breaks before the loop (today: never — always `Ok`).
///
/// # Example
///
/// ```rust,ignore
/// use gauge::super_user::{
///     ensure_super_user_group, seed_super_user_members_from_emails,
/// };
///
/// let group = ensure_super_user_group(system).await?;
/// let stats = seed_super_user_members_from_emails(
///     system,
///     &group,
///     &["ops@example.com".into()],
/// )
/// .await?;
/// assert_eq!(stats.configured, 1);
/// ```
pub async fn seed_super_user_members_from_emails(
    system: &Valence,
    super_group: &PermissionGroup,
    emails: &[String],
) -> anyhow::Result<SuperUserSeedStats> {
    let mut stats = SuperUserSeedStats {
        configured: emails.len(),
        ..SuperUserSeedStats::default()
    };
    for email in emails {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            stats.missing_user += 1;
            continue;
        }
        match seed_super_user_member_by_email(system, super_group, trimmed).await {
            Ok(()) => stats.seeded += 1,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("no user found for email") {
                    stats.missing_user += 1;
                } else {
                    stats.failed += 1;
                    log::warn!("[gauge] super_user email seed failed (details redacted)");
                }
            }
        }
    }
    Ok(stats)
}

async fn ensure_user_in_super_group(
    super_group: &PermissionGroup,
    user: &lepton::generated::User,
    system: &Valence,
) -> anyhow::Result<()> {
    let owner_ids: HashSet<String> = super_group
        .get_owners_record_ids(system, valence::use_!(r#"When **Gauge** needs the **owners of a permission group**, we **follow the owner edges** so the product can show owners on the group detail or decide who may edit. Editors see that list; access checks use it only to allow or deny."#))
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
        valence::use_!(r#"When an operator **adds a group owner** in **Gauge**, we **write the owner edge** from the permission group to that principal so later checks know who can approve and edit. Operators see the updated owners on the group detail."#),
    )
            .await?;
    }

    let member_ids: HashSet<String> = super_group
        .get_members_record_ids(system, valence::use_!(r#"When **Gauge** needs the **members of a permission group**, we **follow the member edges** so the product can show members on the group detail or decide who inherits grants. Editors see that list; access checks use it only to allow or deny."#))
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
        valence::use_!(r#"When an operator **adds a group member** in **Gauge**, we **write the member edge** so that principal inherits the group's grants. Operators see the updated members on the group detail."#),
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
    match valence::get_record(backend.as_ref(), "permission_user_principal", id, valence::use_!(r#"When **Gauge** needs a **permission control-plane row by id**, we **read that record from storage** so the service can continue with the right domain, group, permission, or principal. The app uses the row for that workflow."#))
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
    match valence::get_record(backend.as_ref(), "permission_group_principal", id, valence::use_!(r#"When **Gauge** needs a **permission control-plane row by id**, we **read that record from storage** so the service can continue with the right domain, group, permission, or principal. The app uses the row for that workflow."#))
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
    match valence::get_record(backend.as_ref(), "permission_group", id, valence::use_!(r#"When **Gauge** needs a **permission control-plane row by id**, we **read that record from storage** so the service can continue with the right domain, group, permission, or principal. The app uses the row for that workflow."#))
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

        for owner in current.get_owners_record_ids(system, valence::use_!(r#"When **Gauge** needs the **owners of a permission group**, we **follow the owner edges** so the product can show owners on the group detail or decide who may edit. Editors see that list; access checks use it only to allow or deny."#)).await? {
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
        for member in current.get_members_record_ids(system, valence::use_!(r#"When **Gauge** needs the **members of a permission group**, we **follow the member edges** so the product can show members on the group detail or decide who inherits grants. Editors see that list; access checks use it only to allow or deny."#)).await? {
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
