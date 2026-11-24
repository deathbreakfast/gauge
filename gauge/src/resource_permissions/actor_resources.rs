//! Which resources of a kind the caller can act on, in one call.

use std::collections::BTreeSet;

use valence::Valence;

use super::kinds::{domain_id, permission_name, ResourceAction, ResourceKindDescriptor};
use crate::generated::PermissionDomain;

/// Raw ids of the resources of `kind` on which the actor on `v` holds any of `actions`.
///
/// Use it to build a candidate list without one check per row, for example the
/// organizations a user may pick in a "New team" form (`[Edit, Maintain]`). Grants count
/// the same way as in [`crate::service::actor_can`]: direct grants, grants through groups
/// at any depth (umbrella groups included), and grants to a team the actor is on.
///
/// - System actors and super users get every resource of the kind that has a bundle.
/// - A registered service user gets the resources it holds an action on through its groups
///   or direct grants, while active.
/// - Anonymous callers and built-in service users get an empty list, as does an empty
///   `actions` slice.
///
/// Ids come back sorted and without duplicates. Only resources with a permission bundle
/// ([`ensure_resource_permission_bundle`](super::ensure_resource_permission_bundle)) are
/// candidates. Each candidate still costs one permission lookup per action, served from the
/// request's permission cache when the host has one; the gain is a single call and a single
/// super-user check.
///
/// ```ignore
/// use gauge::resource_permissions::{actor_resource_ids_with_any, ResourceAction};
///
/// let editable = actor_resource_ids_with_any(
///     &v,
///     ORGANIZATION_KIND,
///     &[ResourceAction::Edit, ResourceAction::Maintain],
/// )
/// .await?;
/// ```
///
/// # Errors
///
/// Backend read and decode failures, and permission-check failures, are returned as they
/// are.
pub async fn actor_resource_ids_with_any(
    v: &Valence,
    kind: impl Into<ResourceKindDescriptor>,
    actions: &[ResourceAction],
) -> anyhow::Result<Vec<String>> {
    let kind = kind.into();
    if actions.is_empty() {
        return Ok(Vec::new());
    }
    let actor = v.actor();
    let service_user = lepton_identity::service_users::ServiceUserId::from_actor(actor);
    let user_id = actor.user_id().map(ToString::to_string);
    if !actor.is_system() && service_user.is_none() && user_id.is_none() {
        return Ok(Vec::new());
    }

    let candidates = resource_ids_of_kind(&kind, v).await?;
    if actor.is_system() {
        return Ok(candidates.into_iter().collect());
    }

    let mut out = Vec::new();
    if let Some(service_user) = service_user {
        for resource_id in candidates {
            for action in actions {
                let name = permission_name(kind, &resource_id, *action);
                let decision =
                    crate::service_users::access::service_user_decision(v, &service_user, &name)
                        .await?;
                if decision.allowed() {
                    out.push(resource_id);
                    break;
                }
            }
        }
        return Ok(out);
    }

    let Some(user_id) = user_id else {
        return Ok(Vec::new());
    };
    if crate::super_user::actor_is_super_user(v).await? {
        return Ok(candidates.into_iter().collect());
    }
    for resource_id in candidates {
        for action in actions {
            let name = permission_name(kind, &resource_id, *action);
            if crate::service::user_can(v, &user_id, &name).await? {
                out.push(resource_id);
                break;
            }
        }
    }
    Ok(out)
}

/// Raw resource ids of every bundle domain that belongs to `kind`.
///
/// A domain belongs to the kind only when its id is exactly the one [`domain_id`] builds
/// from its stored raw id, so kinds whose prefixes overlap (`gluon_app`, `gluon_app_set`)
/// don't pick up each other's rows.
async fn resource_ids_of_kind(
    kind: &ResourceKindDescriptor,
    v: &Valence,
) -> anyhow::Result<BTreeSet<String>> {
    let backend = v
        .backend_for_table("permission_domain")
        .map_err(|e| anyhow::anyhow!("resolve permission_domain backend: {e}"))?;
    let rows = backend
        .execute_compiled_query(&valence::__internal::CompiledQuery {
            query_string: "SELECT * FROM permission_domain WHERE resource_scoped = $scoped"
                .to_string(),
            params: vec![("scoped".to_string(), serde_json::json!(true))],
        })
        .await
        .map_err(|e| anyhow::anyhow!("query resource-scoped permission_domain (raw): {e}"))?;
    let mut out = BTreeSet::new();
    for row in rows {
        let domain: PermissionDomain = serde_json::from_value(row)
            .map_err(|e| anyhow::anyhow!("decode permission_domain (raw): {e}"))?;
        let Some(resource_id) = domain.resource_id().filter(|id| !id.is_empty()) else {
            continue;
        };
        let row_id = crate::actor_can_raw::model_pk_id(domain.id());
        if row_id == domain_id(*kind, resource_id) {
            out.insert(resource_id.clone());
        }
    }
    Ok(out)
}
