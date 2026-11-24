//! Every user who holds a named permission, for fan-out (notifications, digests).

use std::collections::{BTreeSet, HashSet};

use valence::{RecordId, Valence};

use crate::actor_can_raw::{model_pk_id, permissions_named_raw, raw_get_json};
use crate::generated::{PermissionGroup, PermissionGroupPrincipal, PermissionUserPrincipal};
use crate::service_users::GAUGE_LIST_PERMISSION_HOLDERS;
use crate::super_user::actor_is_super_user;

use super::access::can_edit_permission;
use super::helpers::canonical_user_id;
use super::GaugeServiceError;

/// Bare user ids of everyone who holds `permission_name`, directly or through groups.
///
/// A user holds the permission when it is granted straight to them, or to a group they
/// own or are a member of, at any depth of nested groups (the same rule as
/// [`crate::service::user_can`]). Service users on the grant graph are not listed, and a
/// grant to a team is not expanded into its members, since a roster is only as visible as
/// the reader's own access to it. The ids
/// come back sorted, without duplicates and without the `user:` table prefix. A blank or
/// unknown name gives an empty list.
///
/// Every read is a raw backend read on `v`; nothing elevates to System.
///
/// # Who may call it
///
/// - A System actor, for jobs that started as System.
/// - A registered service user that holds [`GAUGE_LIST_PERMISSION_HOLDERS`] (seeded with the
///   [`crate::service_users::PERMISSION_HOLDER_READERS_GROUP_ID`] group), while it is active.
/// - A super user, or a user who can edit every permission with that name.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for anyone else, including anonymous callers and
/// built-in service users. Backend read and decode failures are returned as they are.
pub async fn list_permission_holders(
    v: &Valence,
    permission_name: &str,
) -> anyhow::Result<Vec<String>> {
    let permission_name = permission_name.trim();
    let permissions = permissions_named_raw(permission_name, v).await?;
    if !may_list_holders(v, &permissions).await? {
        return Err(GaugeServiceError::not_authorized("list_permission_holders").into());
    }

    let mut holders = BTreeSet::new();
    let mut groups = Vec::new();
    for permission in &permissions {
        for principal in permission.get_allowed_principals_record_ids(v, valence::use_!(r"When a **service** needs **everyone who holds a permission** (for example to notify them), **Gauge** **follows the allowed-principal edges** to find the users and groups it is granted to. The service uses the ids to reach those people; nothing else is shown.")).await? {
            collect_principal(&principal, v, &mut holders, &mut groups).await?;
        }
    }

    let mut visited = HashSet::new();
    while let Some(group) = groups.pop() {
        if !visited.insert(model_pk_id(group.id())) {
            continue;
        }
        let owners = group.get_owners_record_ids(v, valence::use_!(r"When a **service** needs **everyone who holds a permission**, **Gauge** **follows a holding group's owner edges**, because group owners hold what the group holds. The service uses the ids to reach those people; nothing else is shown.")).await?;
        let members = group.get_members_record_ids(v, valence::use_!(r"When a **service** needs **everyone who holds a permission**, **Gauge** **follows a holding group's member edges**, including nested groups. The service uses the ids to reach those people; nothing else is shown.")).await?;
        for principal in owners.iter().chain(&members) {
            collect_principal(principal, v, &mut holders, &mut groups).await?;
        }
    }

    Ok(holders.into_iter().collect())
}

/// System, a service user holding the lookup permission, a super user, or an editor of
/// every permission row with the name.
async fn may_list_holders(
    v: &Valence,
    permissions: &[crate::generated::Permission],
) -> anyhow::Result<bool> {
    let actor = v.actor();
    if actor.is_system() {
        return Ok(true);
    }
    if let Some(service_user) = lepton_identity::service_users::ServiceUserId::from_actor(actor) {
        let decision = crate::service_users::access::service_user_decision(
            v,
            &service_user,
            GAUGE_LIST_PERMISSION_HOLDERS,
        )
        .await;
        crate::service_users::access::log_decision(GAUGE_LIST_PERMISSION_HOLDERS, &decision);
        return decision.map(crate::service_users::access::ServiceUserDecision::allowed);
    }
    if actor.user_id().is_none() {
        return Ok(false);
    }
    if actor_is_super_user(v).await? {
        return Ok(true);
    }
    if permissions.is_empty() {
        return Ok(false);
    }
    for permission in permissions {
        if !can_edit_permission(permission, v).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Add a user principal's id to `holders`, or queue the group behind a group principal.
async fn collect_principal(
    principal: &RecordId,
    v: &Valence,
    holders: &mut BTreeSet<String>,
    groups: &mut Vec<PermissionGroup>,
) -> anyhow::Result<()> {
    let principal_id = principal.id().to_string();
    match principal.table() {
        "permission_user_principal" => {
            if let Some(row) = raw_get_json("permission_user_principal", &principal_id, v).await? {
                let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                let user_id = valence::extract_id_from_record(principal.user()).unwrap_or_default();
                if !user_id.is_empty() {
                    holders.insert(canonical_user_id(&user_id));
                }
            }
        }
        "permission_group_principal" => {
            if let Some(row) = raw_get_json("permission_group_principal", &principal_id, v).await? {
                let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                let group_id =
                    valence::extract_id_from_record(principal.group()).unwrap_or_default();
                if let Some(row) = raw_get_json("permission_group", &group_id, v).await? {
                    groups.push(serde_json::from_value(row)?);
                }
            }
        }
        // Service users are not people; they never receive a holder fan-out.
        _ => {}
    }
    Ok(())
}
