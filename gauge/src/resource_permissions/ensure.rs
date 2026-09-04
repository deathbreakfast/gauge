//! Ensure a per-resource Gauge permission domain, owners group, and action permissions.

use std::collections::HashMap;

use chrono::Utc;
use log::{debug, info};
use valence::{Actor, Model, RecordId, StringPredicate, Valence};

use crate::generated::{Permission, PermissionDomain, PermissionGroup, PermissionUserPrincipal};

use super::default_groups::grant_named_permission_to_group;
use super::error::ResourcePermissionError;
use super::kinds::{
    domain_id, normalize_id_fragment, owners_group_id, permission_name, permission_record_id,
    ResourceAction, ResourceKindDescriptor,
};
use super::spec::{ResourcePermissionBundle, ResourcePermissionSpec};

fn as_system(v: &Valence, operation: &str) -> Valence {
    v.with_actor(Actor::System {
        operation: operation.to_string(),
    })
}

fn canonical_user_id(user_id: &str) -> String {
    user_id
        .strip_prefix("user:")
        .unwrap_or(user_id)
        .trim()
        .to_string()
}

fn map_err(
    kind: &ResourceKindDescriptor,
    resource_id: &str,
    operation: &str,
    source: impl Into<anyhow::Error>,
) -> ResourcePermissionError {
    ResourcePermissionError::service(kind.prefix, resource_id, operation, source)
}

async fn ensure_user_principal(
    system: &Valence,
    user_id: &str,
) -> Result<PermissionUserPrincipal, ResourcePermissionError> {
    let uid = canonical_user_id(user_id);
    let user = lepton::generated::User::get(&uid, system)
        .await
        .map_err(|e| ResourcePermissionError::service("user", &uid, "get_user", e))?
        .ok_or_else(|| {
            ResourcePermissionError::service(
                "user",
                &uid,
                "user_missing",
                anyhow::anyhow!("User not found: {uid}"),
            )
        })?;
    let user_thing = user.id().cloned().ok_or_else(|| {
        ResourcePermissionError::service(
            "user",
            &uid,
            "user_id_missing",
            anyhow::anyhow!("User id missing: {uid}"),
        )
    })?;
    let principal_id = format!("user:{uid}");
    if let Some(existing) = PermissionUserPrincipal::get(&principal_id, system)
        .await
        .map_err(|e| ResourcePermissionError::service("user", &uid, "get_principal", e))?
    {
        return Ok(existing);
    }
    let principal = PermissionUserPrincipal::new(user_thing, uid.clone())
        .map_err(|e| ResourcePermissionError::service("user", &uid, "new_principal", e))?;
    PermissionUserPrincipal::upsert(&principal_id, principal, system)
        .await
        .map_err(|e| ResourcePermissionError::service("user", &uid, "upsert_principal", e))
}

async fn add_owner_user(
    system: &Valence,
    group_id: &str,
    user_id: &str,
) -> Result<(), ResourcePermissionError> {
    let group = PermissionGroup::get(group_id, system)
        .await
        .map_err(|e| ResourcePermissionError::service("owners", group_id, "get_group", e))?
        .ok_or_else(|| {
            ResourcePermissionError::service(
                "owners",
                group_id,
                "group_missing",
                anyhow::anyhow!("owners group missing"),
            )
        })?;
    let principal = ensure_user_principal(system, user_id).await?;
    let pid = principal.id().cloned().ok_or_else(|| {
        ResourcePermissionError::service(
            "owners",
            group_id,
            "principal_id_missing",
            anyhow::anyhow!("principal id missing"),
        )
    })?;
    match group.relate_to_owner_record(&pid, system).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("duplicate") || msg.contains("unique") || msg.contains("already") {
                Ok(())
            } else {
                Err(ResourcePermissionError::service(
                    "owners",
                    group_id,
                    "relate_owner",
                    e,
                ))
            }
        }
    }
}

async fn ensure_permission_row(
    system: &Valence,
    kind: &ResourceKindDescriptor,
    resource_id: &str,
    action: ResourceAction,
    domain_rid: &RecordId,
    owners_group_id: &str,
    display_name: &str,
) -> Result<String, ResourcePermissionError> {
    let name = permission_name(kind, resource_id, action);
    let perm_id = permission_record_id(kind, resource_id, action);

    if Permission::query(system)
        .where_name(StringPredicate::Equals(name.clone()))
        .limit(1)
        .first()
        .await
        .map_err(|e| map_err(kind, resource_id, "query_permission", e))?
        .is_some()
    {
        return Ok(name);
    }

    if Permission::get(&perm_id, system)
        .await
        .map_err(|e| map_err(kind, resource_id, "get_permission", e))?
        .is_some()
    {
        return Ok(name);
    }

    let now = Utc::now();
    let permission = Permission::new(
        RecordId::new("user", "system"),
        RecordId::new("permission_group", owners_group_id),
        domain_rid.clone(),
        name.clone(),
        Some(format!(
            "{action} on {display} ({resource})",
            action = action.as_str(),
            display = display_name,
            resource = resource_id
        )),
        now,
        now,
    )
    .map_err(|e| map_err(kind, resource_id, "new_permission", e))?;
    Permission::upsert(&perm_id, permission, system)
        .await
        .map_err(|e| map_err(kind, resource_id, "upsert_permission", e))?;
    Ok(name)
}

fn umbrella_grants(kind: &ResourceKindDescriptor, action: ResourceAction) -> Vec<&'static str> {
    if kind.umbrella == super::kinds::UmbrellaPolicy::None {
        return Vec::new();
    }
    let g = kind.groups;
    match action {
        ResourceAction::View => {
            if g.editors == g.operators {
                vec![g.viewers, g.operators]
            } else {
                vec![g.viewers, g.editors, g.operators]
            }
        }
        ResourceAction::Edit => {
            if g.editors == g.operators {
                vec![g.operators]
            } else {
                vec![g.editors, g.operators]
            }
        }
        ResourceAction::Delete | ResourceAction::Reveal => vec![g.operators],
        ResourceAction::Maintain => Vec::new(), // owners group only
    }
}

async fn ensure_domain(
    system: &Valence,
    kind: &ResourceKindDescriptor,
    resource_id: &str,
    dom_id: &str,
    display: &str,
) -> Result<RecordId, ResourcePermissionError> {
    let domain = if let Some(existing) = PermissionDomain::get(dom_id, system)
        .await
        .map_err(|e| map_err(kind, resource_id, "get_domain", e))?
    {
        debug!("[permission] domain existing id={dom_id}");
        existing
    } else {
        let now = Utc::now();
        let d = PermissionDomain::new(
            true,
            Some(resource_id.to_string()),
            display.to_string(),
            Some(format!("Resource permissions for {display}")),
            now,
            now,
        )
        .map_err(|e| map_err(kind, resource_id, "new_domain", e))?;
        let created = PermissionDomain::upsert(dom_id, d, system)
            .await
            .map_err(|e| map_err(kind, resource_id, "upsert_domain", e))?;
        debug!("[permission] domain created id={dom_id}");
        created
    };
    domain.id().cloned().ok_or_else(|| {
        map_err(
            kind,
            resource_id,
            "domain_id_missing",
            anyhow::anyhow!("domain id missing"),
        )
    })
}

async fn ensure_owners_group(
    system: &Valence,
    kind: &ResourceKindDescriptor,
    resource_id: &str,
    own_id: &str,
    display: &str,
    maintainer: &str,
) -> Result<(), ResourcePermissionError> {
    if PermissionGroup::get(own_id, system)
        .await
        .map_err(|e| map_err(kind, resource_id, "get_owners_group", e))?
        .is_none()
    {
        let now = Utc::now();
        let group = PermissionGroup::new(
            format!("{display} owners"),
            Some("Maintain ACL owners for this resource".to_string()),
            now,
            now,
        )
        .map_err(|e| map_err(kind, resource_id, "new_owners_group", e))?;
        PermissionGroup::upsert(own_id, group, system)
            .await
            .map_err(|e| map_err(kind, resource_id, "upsert_owners_group", e))?;
    }
    add_owner_user(system, own_id, maintainer).await
}

async fn grant_action_to_umbrellas(
    system: &Valence,
    kind: &ResourceKindDescriptor,
    resource_id: &str,
    action: ResourceAction,
    owners_group_id: &str,
    perm_name: &str,
) -> Result<(), ResourcePermissionError> {
    // Owners / maintainer group always receives every action on this resource.
    grant_named_permission_to_group(system, owners_group_id, perm_name).await?;
    if action == ResourceAction::Maintain {
        return Ok(());
    }
    for group_id in umbrella_grants(kind, action) {
        // Soft: group may be missing if host skipped catalog seed; skip with debug.
        if PermissionGroup::get(group_id, system)
            .await
            .map_err(|e| map_err(kind, resource_id, "get_umbrella", e))?
            .is_none()
        {
            debug!("[permission] skip grant missing group={group_id} permission={perm_name}");
            continue;
        }
        grant_named_permission_to_group(system, group_id, perm_name).await?;
    }
    Ok(())
}

/// Idempotently ensure a Gauge permission domain, owners group, and action permissions
/// for one resource.
///
/// # Errors
///
/// Returns [`ResourcePermissionError::MissingMaintainer`] when `maintainer_actor` is empty,
/// [`ResourcePermissionError::InvalidResourceId`] when `resource_id` normalizes empty,
/// or [`ResourcePermissionError::GaugeService`] on Valence/Gauge failures.
///
/// Hosts should call [`super::seed_resource_kind_catalog`] (or product `create_initial_*`) before
/// product create paths so umbrella groups exist to receive grants.
///
/// `spec.kind` accepts a [`super::ResourceKind`] or a
/// [`ResourceKindDescriptor`], so a product that owns a kind Gauge has no variant for
/// passes its own descriptor here.
pub async fn ensure_resource_permission_bundle<K>(
    v: &Valence,
    spec: ResourcePermissionSpec<K>,
) -> Result<ResourcePermissionBundle, ResourcePermissionError>
where
    K: Into<ResourceKindDescriptor>,
{
    let ResourcePermissionSpec {
        kind,
        resource_id,
        display_name,
        actions,
        maintainer_actor,
    } = spec;
    let kind = kind.into();
    let resource_id = resource_id.trim().to_string();
    if normalize_id_fragment(&resource_id).is_empty() {
        return Err(ResourcePermissionError::InvalidResourceId {
            kind: kind.prefix.to_string(),
        });
    }
    let maintainer = canonical_user_id(&maintainer_actor);
    if maintainer.is_empty() {
        return Err(ResourcePermissionError::MissingMaintainer {
            kind: kind.prefix.to_string(),
            resource_id: resource_id.clone(),
        });
    }

    let system = as_system(v, "ensure_resource_permission_bundle");
    let dom_id = domain_id(kind, &resource_id);
    let own_id = owners_group_id(kind, &resource_id);
    let display = if display_name.trim().is_empty() {
        format!("{} {resource_id}", kind.display_label)
    } else {
        display_name.trim().to_string()
    };
    let actions = if actions.is_empty() {
        kind.default_actions()
    } else {
        actions
    };

    info!(
        "[permission] ensure_resource_permission_bundle start kind={} resource_id={}",
        kind.prefix, resource_id
    );

    let domain_rid = ensure_domain(&system, &kind, &resource_id, &dom_id, &display).await?;
    ensure_owners_group(&system, &kind, &resource_id, &own_id, &display, &maintainer).await?;

    let mut permission_names = HashMap::new();
    for action in actions {
        let name = ensure_permission_row(
            &system,
            &kind,
            &resource_id,
            action,
            &domain_rid,
            &own_id,
            &display,
        )
        .await?;
        grant_action_to_umbrellas(&system, &kind, &resource_id, action, &own_id, &name).await?;
        permission_names.insert(action.as_str().to_string(), name);
    }

    info!(
        "[permission] ensure_resource_permission_bundle ok kind={} resource_id={}",
        kind.prefix, resource_id
    );

    Ok(ResourcePermissionBundle {
        domain_id: dom_id,
        owners_group_id: own_id,
        permission_names,
    })
}

/// Idempotently tear down the Gauge ACL bundle for one resource.
///
/// Deletes per-resource permissions, then the owners group, then the domain —
/// the order required by `on_delete: Restrict` edges from permission → domain /
/// `owners_group`. Allowed-principal M2M edges cascade with the permission rows.
///
/// Never touches shared user principals, umbrella groups (`neutrino.secret.*`,
/// `gluon.app.*`, …), or the catalog Create* permission.
///
/// A never-ensured resource (no domain / no perms) returns `Ok` so control-plane
/// resources that skipped ensure still delete cleanly.
///
/// Runs as System internally: `permission_domain` delete is Super-User-only.
///
/// # Errors
///
/// [`ResourcePermissionError::InvalidResourceId`] when `resource_id` normalizes
/// empty, or [`ResourcePermissionError::GaugeService`] on Valence failures.
/// Physically apply a deletion DAG in wave order.
///
/// `Model::delete` only queues work and marks `pending_deletion`. Bundle teardown must
/// remove Restrict blockers in the same call (permissions before owners group before
/// domain), so we compute the DAG and call [`valence::apply_deletion_node`] here —
/// the same apply path host deletion workers use.
async fn delete_entity_now(
    table: &str,
    id: &str,
    system: &Valence,
    kind: &ResourceKindDescriptor,
    resource_id: &str,
    operation: &str,
) -> Result<(), ResourcePermissionError> {
    // Use the literal primary key. Do **not** call `normalize_record_id_for_ownership`:
    // group-principal ids are `permission_group:{group_id}`, and normalize would strip the
    // `permission_group:` prefix because that table exists in the schema registry.
    let record_id = id.trim();
    let exists = valence::query::QueryCore::get_record_json(table, record_id, system)
        .await
        .map_err(|e| map_err(kind, resource_id, operation, e))?;
    if exists.is_none() {
        valence::read_cache::invalidate(table, record_id);
        return Ok(());
    }

    let dag = valence::deletion::dag::DeletionDag::compute(table, record_id, system)
        .await
        .map_err(|e| map_err(kind, resource_id, operation, e))?;
    if !dag.restrict_violations.is_empty() {
        return Err(map_err(
            kind,
            resource_id,
            operation,
            anyhow::anyhow!(
                "delete restricted by schema connections: {:?}",
                dag.restrict_violations
            ),
        ));
    }
    valence::check_dag_delete_privacy(&dag, system)
        .await
        .map_err(|e| map_err(kind, resource_id, operation, e))?;

    let max_d = dag.nodes.iter().map(|n| n.depth).max().unwrap_or(0);
    for d in (0..=max_d).rev() {
        for wave in 0u8..=2 {
            for node in &dag.nodes {
                if node.depth == d && node.action.wave_order() == wave {
                    valence::apply_deletion_node(node, system)
                        .await
                        .map_err(|e| map_err(kind, resource_id, operation, e))?;
                    valence::read_cache::invalidate(&node.table, &node.record_id);
                }
            }
        }
    }
    Ok(())
}

async fn delete_permission_group_row(
    system: &Valence,
    own_id: &str,
    kind: &ResourceKindDescriptor,
    resource_id: &str,
) -> Result<(), ResourcePermissionError> {
    let record_id = own_id.trim();
    if valence::query::QueryCore::get_record_json("permission_group", record_id, system)
        .await
        .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?
        .is_none()
    {
        return Ok(());
    }
    let backend = system
        .backend_for_table("permission_group")
        .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?;
    let endpoint = valence::RecordId::new("permission_group", record_id);
    for edge in [
        "permission_group_owner_principal",
        "permission_group_member_principal",
    ] {
        for to in backend
            .get_edge_targets(&endpoint, edge)
            .await
            .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?
        {
            system
                .unrelate_edge(edge, &endpoint, &to)
                .await
                .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?;
        }
        for from in backend
            .get_edge_sources(&endpoint, edge)
            .await
            .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?
        {
            system
                .unrelate_edge(edge, &from, &endpoint)
                .await
                .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?;
        }
    }
    backend
        .delete_record("permission_group", record_id)
        .await
        .map_err(|e| map_err(kind, resource_id, "delete_owners_group", e))?;
    valence::read_cache::invalidate("permission_group", record_id);
    Ok(())
}

/// Tear down a per-resource permission bundle (permissions → owners group → domain).
///
/// Idempotent: a never-ensured or already-removed resource returns `Ok(())`. Never
/// touches shared user principals, umbrella groups, or catalog `Create*` permissions.
///
/// Runs as System internally because `permission_domain` delete is Super-User-only
/// (same elevation pattern as [`ensure_resource_permission_bundle`]). Physical
/// deletes apply the Valence deletion DAG in Restrict-legal order inside this
/// call so blockers are gone before the next step.
///
/// # Errors
///
/// Returns [`ResourcePermissionError::InvalidResourceId`] when `resource_id`
/// normalizes empty, or [`ResourcePermissionError::GaugeService`] when a Valence
/// Restrict violation or backend failure blocks a step.
pub async fn delete_resource_permission_bundle(
    v: &Valence,
    kind: impl Into<ResourceKindDescriptor>,
    resource_id: &str,
) -> Result<(), ResourcePermissionError> {
    let kind = kind.into();
    let resource_id = resource_id.trim().to_string();
    if normalize_id_fragment(&resource_id).is_empty() {
        return Err(ResourcePermissionError::InvalidResourceId {
            kind: kind.prefix.to_string(),
        });
    }

    let system = as_system(v, "delete_resource_permission_bundle");
    let dom_id = domain_id(kind, &resource_id);
    let own_id = owners_group_id(kind, &resource_id);

    info!(
        "[permission] delete_resource_permission_bundle start kind={} resource_id={}",
        kind.prefix, resource_id
    );

    for &action in kind.actions {
        let perm_id = permission_record_id(kind, &resource_id, action);
        let name = permission_name(kind, &resource_id, action);
        let mut ids = std::collections::HashSet::new();
        ids.insert(perm_id);
        if let Some(by_name) = Permission::query(&system)
            .where_name(StringPredicate::Equals(name))
            .limit(1)
            .first()
            .await
            .map_err(|e| map_err(&kind, &resource_id, "query_permission_for_delete", e))?
        {
            if let Some(id) = by_name
                .id()
                .and_then(|r| valence::extract_id_from_record(r).ok())
            {
                ids.insert(id);
            }
        }
        for id in ids {
            delete_entity_now(
                "permission",
                &id,
                &system,
                &kind,
                &resource_id,
                "delete_permission",
            )
            .await?;
            debug!("[permission] deleted permission id={id}");
        }
    }

    // Owners-group principal row Restrict-blocks group delete — remove it first.
    let owners_principal_id = format!("permission_group:{own_id}");
    delete_entity_now(
        "permission_group_principal",
        &owners_principal_id,
        &system,
        &kind,
        &resource_id,
        "delete_owners_principal",
    )
    .await?;

    delete_permission_group_row(&system, &own_id, &kind, &resource_id).await?;
    debug!("[permission] deleted owners group id={own_id}");

    delete_entity_now(
        "permission_domain",
        &dom_id,
        &system,
        &kind,
        &resource_id,
        "delete_domain",
    )
    .await?;
    debug!("[permission] deleted domain id={dom_id}");

    info!(
        "[permission] delete_resource_permission_bundle ok kind={} resource_id={}",
        kind.prefix, resource_id
    );
    Ok(())
}
