use valence::Actor;
use valence::Model;
use valence::RecordId;
use valence::Valence;

use crate::generated::{
    Permission, PermissionGroup, PermissionGroupPrincipal, PermissionUserPrincipal,
};

fn canonical_user_id(user_id: &str) -> String {
    user_id
        .split_once(':')
        .map_or_else(|| user_id.to_string(), |(_, key)| key.to_string())
}

fn user_principal_id(user_id: &str) -> String {
    format!("user:{}", canonical_user_id(user_id))
}

fn group_principal_id(group_id: &str) -> String {
    format!("permission_group:{group_id}")
}

async fn ensure_user_principal(user_id: &str, system: &Valence) -> anyhow::Result<RecordId> {
    let user = lepton::generated::User::get(user_id, system, valence::use_!(r"In **Gauge permissions**, we **load User** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found during migration: {user_id}"))?;
    let user_record = user
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("user id missing after persist"))?;
    let principal_id = user_principal_id(user_id);
    if PermissionUserPrincipal::get(&principal_id, system, valence::use_!(r"In **Gauge permissions**, we **load Permission User Principal** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await?
        .is_none()
    {
        let principal = PermissionUserPrincipal::new(user_record, canonical_user_id(user_id))?;
        PermissionUserPrincipal::upsert(&principal_id, principal, system, valence::use_!(r"When **Gauge permissions** needs to persist work, we **save Permission User Principal** so the next step in that feature can continue with the latest values. People and services allowed for **Gauge permissions** use this data for that workflow—not as a general export of unrelated personal fields.")).await?;
    }
    Ok(RecordId::new(
        "permission_user_principal",
        principal_id.as_str(),
    ))
}

async fn ensure_group_principal(group_id: &str, system: &Valence) -> anyhow::Result<RecordId> {
    let group = PermissionGroup::get(group_id, system, valence::use_!(r"In **Gauge permissions**, we **load Permission Group** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("Permission group not found during migration: {group_id}")
        })?;
    let group_record = group
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group id missing after persist"))?;
    let principal_id = group_principal_id(group_id);
    if PermissionGroupPrincipal::get(&principal_id, system, valence::use_!(r"In **Gauge permissions**, we **load Permission Group Principal** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await?
        .is_none()
    {
        let principal = PermissionGroupPrincipal::new(group_record, group_id.to_string())?;
        PermissionGroupPrincipal::upsert(&principal_id, principal, system, valence::use_!(r"When **Gauge permissions** needs to persist work, we **save Permission Group Principal** so the next step in that feature can continue with the latest values. People and services allowed for **Gauge permissions** use this data for that workflow—not as a general export of unrelated personal fields.")).await?;
    }
    Ok(RecordId::new(
        "permission_group_principal",
        principal_id.as_str(),
    ))
}

async fn ensure_edge(
    edge_table: &str,
    from: &RecordId,
    to: &RecordId,
    system: &Valence,
) -> anyhow::Result<()> {
    let existing = system
        .get_many_to_many_target_record_ids(from, edge_table, valence::use_!(r"When the **principal-connection migration** runs, we **list existing edge targets** for a permission or group so legacy links can be copied onto unified principal edges. Operators who run the migration use this."))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let already = existing
        .iter()
        .any(|t| t.table() == to.table() && t.id() == to.id());
    if !already {
        system
            .relate_edge(edge_table, from, to, valence::use_!(r"When the **principal-connection migration** runs, we **write a unified principal edge** so Gauge can use the new allow, owner, and member model. Operators who run the migration use this."))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

async fn list_permission_record_ids(system: &Valence) -> anyhow::Result<Vec<RecordId>> {
    let rows = Permission::query(system, valence::use_!(r"In **Gauge permissions**, we **list Permission** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors.")).await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.id().cloned())
        .collect())
}

async fn list_group_record_ids(system: &Valence) -> anyhow::Result<Vec<RecordId>> {
    let rows = PermissionGroup::query(system, valence::use_!(r"In **Gauge permissions**, we **list Permission Group** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors.")).await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.id().cloned())
        .collect())
}

async fn migrate_user_edges_from(
    sources: &[RecordId],
    source_edge_table: &str,
    target_edge_table: &str,
    system: &Valence,
) -> anyhow::Result<()> {
    for from in sources {
        let targets = system
            .get_many_to_many_target_record_ids(from, source_edge_table, valence::use_!(r"When the **principal-connection migration** runs, we **list existing edge targets** for a permission or group so legacy links can be copied onto unified principal edges. Operators who run the migration use this."))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for out in targets {
            if out.table() != "user" {
                continue;
            }
            let out_id = out.id().to_string();
            if out_id.is_empty() {
                continue;
            }
            let principal_record = ensure_user_principal(&out_id, system).await?;
            ensure_edge(target_edge_table, from, &principal_record, system).await?;
        }
    }
    Ok(())
}

async fn migrate_group_edges_from(
    sources: &[RecordId],
    source_edge_table: &str,
    target_edge_table: &str,
    system: &Valence,
) -> anyhow::Result<()> {
    for from in sources {
        let targets = system
            .get_many_to_many_target_record_ids(from, source_edge_table, valence::use_!(r"When the **principal-connection migration** runs, we **list existing edge targets** for a permission or group so legacy links can be copied onto unified principal edges. Operators who run the migration use this."))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for out in targets {
            if out.table() != "permission_group" {
                continue;
            }
            let out_id = out.id().to_string();
            if out_id.is_empty() {
                continue;
            }
            let principal_record = ensure_group_principal(&out_id, system).await?;
            ensure_edge(target_edge_table, from, &principal_record, system).await?;
        }
    }
    Ok(())
}

/// Run the principal-connection migration against an existing [`Valence`].
///
/// Used by the Chronon script entrypoint and by integration tests that already
/// hold a harness `Valence` (without building a `ScriptContext`).
///
/// Walks permission/group records and copies legacy per-kind edges onto the
/// unified `*_principal` edges via Valence graph APIs (works for `InMemory` and
/// Surreal backends alike).
pub async fn migrate_permission_principal_connections_with_valence(
    valence: &Valence,
) -> anyhow::Result<()> {
    let system = valence.with_actor(Actor::System {
        operation: "migrate_permission_principal_connections".to_string(),
    });

    let permissions = list_permission_record_ids(&system).await?;
    let groups = list_group_record_ids(&system).await?;

    migrate_user_edges_from(
        &permissions,
        "permission_allowed_user",
        "permission_allowed_principal",
        &system,
    )
    .await?;
    migrate_group_edges_from(
        &permissions,
        "permission_allowed_group",
        "permission_allowed_principal",
        &system,
    )
    .await?;
    migrate_user_edges_from(
        &groups,
        "permission_group_owner_user",
        "permission_group_owner_principal",
        &system,
    )
    .await?;
    migrate_user_edges_from(
        &groups,
        "permission_group_member_user",
        "permission_group_member_principal",
        &system,
    )
    .await?;
    migrate_group_edges_from(
        &groups,
        "permission_group_member_group",
        "permission_group_member_principal",
        &system,
    )
    .await?;

    Ok(())
}

/// Chronon script (run-once) that migrates legacy per-kind principal connection
/// edges (e.g. `permission_allowed_user`) onto the unified `*_principal` edges.
#[chronon_coordinator_macros::script(
    name = "migrate_permission_principal_connections",
    default_job(job = "migrate-permission-principals", run_once)
)]
pub async fn migrate_permission_principal_connections(
    ctx: Box<dyn chronon_core::ScriptContext>,
) -> anyhow::Result<()> {
    let valence = chronon_valence_identity::valence_from_context(&*ctx)?;
    migrate_permission_principal_connections_with_valence(&valence).await
}
