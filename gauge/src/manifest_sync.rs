//! Idempotent sync of enum-first permission manifests into Valence tables.
//!
//! Creates an auto-managed owners group per app and inserts missing domain /
//! permission rows only. Crate-root teaching:
//! [App permission manifest sync](crate#app-permission-manifest-sync).

use chrono::Utc;
use valence::{Actor, Model, RecordId, StringPredicate, Valence};

use crate::generated::{Permission, PermissionDomain, PermissionGroup};

/// One app's full permission manifest: its domains and the permissions within each.
#[derive(Clone, Debug)]
pub struct PermissionManifestInput {
    /// Stable app identifier, used to derive the auto-managed owners group id.
    pub app_id: String,
    /// Permission domains declared by this app.
    pub domains: Vec<PermissionDomainInput>,
}

/// One permission domain (taxonomy root) and its permissions, as declared by an app.
#[derive(Clone, Debug)]
pub struct PermissionDomainInput {
    /// Stable domain key, normalized into the Valence record id.
    pub key: String,
    /// Human-readable domain name.
    pub name: String,
    /// Human-readable domain description.
    pub description: String,
    /// Permissions declared within this domain.
    pub permissions: Vec<PermissionInput>,
}

/// One named permission declared by an app's manifest.
#[derive(Clone, Debug)]
pub struct PermissionInput {
    /// Permission name (unique within its domain).
    pub name: String,
    /// Human-readable description of what the permission grants.
    pub description: String,
}

/// Counts of rows created vs. already-existing during a manifest sync run.
#[derive(Clone, Debug, Default)]
pub struct ManifestSyncStats {
    /// Number of permission domains newly created.
    pub domains_created: usize,
    /// Number of permission domains that already existed (no-op).
    pub domains_existing: usize,
    /// Number of permissions newly created.
    pub permissions_created: usize,
    /// Number of permissions that already existed by name (no-op).
    pub permissions_existing: usize,
}

fn as_system(v: &Valence, operation: &str) -> Valence {
    v.with_actor(Actor::System {
        operation: operation.to_string(),
    })
}

fn normalized_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::normalized_id;

    #[test]
    fn normalized_id_lowercases_and_replaces_non_alnum() {
        assert_eq!(normalized_id("Counter.Admin"), "counter_admin");
        assert_eq!(normalized_id("already_ok"), "already_ok");
        assert_eq!(normalized_id("A B"), "a_b");
    }
}

async fn ensure_domain(
    domain: &PermissionDomainInput,
    system: &Valence,
    stats: &mut ManifestSyncStats,
) -> anyhow::Result<PermissionDomain> {
    let domain_id = normalized_id(&domain.key);
    // No-change fast path: existing domain → zero writes (boot preflight stays cheap).
    if let Some(existing) = PermissionDomain::get(&domain_id, system).await? {
        stats.domains_existing += 1;
        return Ok(existing);
    }

    let now = Utc::now();
    let created = PermissionDomain::new(
        false,
        None,
        domain.name.clone(),
        if domain.description.trim().is_empty() {
            None
        } else {
            Some(domain.description.clone())
        },
        now,
        now,
    )?;
    let persisted = PermissionDomain::upsert(&domain_id, created, system).await?;
    stats.domains_created += 1;
    Ok(persisted)
}

async fn ensure_owner_group(app_id: &str, system: &Valence) -> anyhow::Result<PermissionGroup> {
    let group_id = format!("manifest_{}_owners", normalized_id(app_id));
    if let Some(existing) = PermissionGroup::get(&group_id, system).await? {
        return Ok(existing);
    }

    let now = Utc::now();
    let group = PermissionGroup::new(
        format!("{app_id} Manifest Owners"),
        Some("Auto-managed owners group for enum-first permission manifests".to_string()),
        now,
        now,
    )?;
    let persisted = PermissionGroup::upsert(&group_id, group, system).await?;
    Ok(persisted)
}

async fn permission_exists_by_name(name: &str, system: &Valence) -> anyhow::Result<bool> {
    let records = Permission::query(system)
        .where_name(StringPredicate::Equals(name.to_string()))
        .await?;
    Ok(!records.is_empty())
}

async fn ensure_permission(
    app_id: &str,
    domain: &PermissionDomain,
    owners_group: &PermissionGroup,
    permission: &PermissionInput,
    system: &Valence,
    stats: &mut ManifestSyncStats,
) -> anyhow::Result<()> {
    // No-change fast path: permission already exists by name → zero writes.
    if permission_exists_by_name(&permission.name, system).await? {
        stats.permissions_existing += 1;
        return Ok(());
    }

    let created_by = RecordId::new("user", "system");
    let owners_group_thing = owners_group
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("owners group id missing after persist"))?;
    let domain_thing = domain
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("domain id missing after persist"))?;
    let permission_id = format!(
        "{}_{}_{}",
        normalized_id(app_id),
        normalized_id(&domain.name().clone()),
        normalized_id(&permission.name)
    );

    let now = Utc::now();
    let record = Permission::new(
        created_by,
        owners_group_thing,
        domain_thing,
        permission.name.clone(),
        if permission.description.trim().is_empty() {
            None
        } else {
            Some(permission.description.clone())
        },
        now,
        now,
    )?;
    Permission::upsert(&permission_id, record, system).await?;
    stats.permissions_created += 1;
    Ok(())
}

/// Sync permission manifests into domain/permission tables.
///
/// Existing domains (by normalized key) and permissions (by name) are left
/// untouched; only missing rows are created. Returns aggregate
/// [`ManifestSyncStats`].
///
/// # Errors
///
/// Returns `anyhow::Error` when Valence create or lookup fails while ensuring
/// the owners group, a domain, or a permission row.
pub async fn sync_permission_manifests(
    v: &Valence,
    manifests: &[PermissionManifestInput],
) -> anyhow::Result<ManifestSyncStats> {
    let system = as_system(v, "permission_sync_manifest");
    let mut stats = ManifestSyncStats::default();

    for manifest in manifests {
        let owners_group = ensure_owner_group(&manifest.app_id, &system).await?;
        for domain in &manifest.domains {
            let persisted_domain = ensure_domain(domain, &system, &mut stats).await?;
            for permission in &domain.permissions {
                ensure_permission(
                    &manifest.app_id,
                    &persisted_domain,
                    &owners_group,
                    permission,
                    &system,
                    &mut stats,
                )
                .await?;
            }
        }
    }

    Ok(stats)
}
