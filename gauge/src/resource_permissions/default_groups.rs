//! Host wiring: seed resource-kind catalogs (default groups and coarse Create* perms).

use chrono::Utc;
use log::{debug, info};
use valence::{Actor, Model, RecordId, StringPredicate, Valence};

use crate::generated::{Permission, PermissionDomain, PermissionGroup, PermissionGroupPrincipal};

use super::error::ResourcePermissionError;
use super::kinds::{ResourceKind, ResourceKindDescriptor};

fn as_system(v: &Valence, operation: &str) -> Valence {
    v.with_actor(Actor::System {
        operation: operation.to_string(),
    })
}

fn map_err(
    kind: &str,
    resource_id: &str,
    operation: &str,
    source: impl Into<anyhow::Error>,
) -> ResourcePermissionError {
    ResourcePermissionError::service(kind, resource_id, operation, source)
}

async fn ensure_standalone_group(
    system: &Valence,
    group_id: &str,
    display_name: &str,
    description: &str,
) -> Result<(), ResourcePermissionError> {
    if PermissionGroup::get(group_id, system)
        .await
        .map_err(|e| map_err("bootstrap", "", "get_group", e))?
        .is_some()
    {
        debug!("[permission] default_groups group_id={group_id} outcome=existing");
        return Ok(());
    }
    let now = Utc::now();
    let group = PermissionGroup::new(
        display_name.to_string(),
        Some(description.to_string()),
        now,
        now,
    )
    .map_err(|e| map_err("bootstrap", "", "new_group", e))?;
    PermissionGroup::upsert(group_id, group, system)
        .await
        .map_err(|e| map_err("bootstrap", "", "upsert_group", e))?;
    info!("[permission] default_groups group_id={group_id} outcome=created");
    Ok(())
}

async fn ensure_group_principal(
    system: &Valence,
    group_id: &str,
) -> Result<PermissionGroupPrincipal, ResourcePermissionError> {
    let group = PermissionGroup::get(group_id, system)
        .await
        .map_err(|e| map_err("bootstrap", group_id, "get_group", e))?
        .ok_or_else(|| {
            ResourcePermissionError::service(
                "bootstrap",
                group_id,
                "group_missing",
                anyhow::anyhow!("permission group {group_id} not found"),
            )
        })?;
    let group_thing = group.id().cloned().ok_or_else(|| {
        ResourcePermissionError::service(
            "bootstrap",
            group_id,
            "group_id_missing",
            anyhow::anyhow!("permission group id missing"),
        )
    })?;
    let principal_id = format!("permission_group:{group_id}");
    if let Some(p) = PermissionGroupPrincipal::get(&principal_id, system)
        .await
        .map_err(|e| map_err("bootstrap", group_id, "get_group_principal", e))?
    {
        return Ok(p);
    }
    let principal = PermissionGroupPrincipal::new(group_thing, group_id.to_string())
        .map_err(|e| map_err("bootstrap", group_id, "new_group_principal", e))?;
    PermissionGroupPrincipal::upsert(&principal_id, principal, system)
        .await
        .map_err(|e| map_err("bootstrap", group_id, "upsert_group_principal", e))
}

pub(super) async fn grant_named_permission_to_group(
    system: &Valence,
    group_id: &str,
    permission_name: &str,
) -> Result<(), ResourcePermissionError> {
    let Some(perm) = Permission::query(system)
        .where_name(StringPredicate::Equals(permission_name.to_string()))
        .limit(1)
        .first()
        .await
        .map_err(|e| map_err("bootstrap", group_id, "query_permission", e))?
    else {
        return Err(ResourcePermissionError::service(
            "bootstrap",
            group_id,
            "permission_missing",
            anyhow::anyhow!("permission {permission_name} not found"),
        ));
    };

    let principal = ensure_group_principal(system, group_id).await?;
    let pid = principal.id().cloned().ok_or_else(|| {
        ResourcePermissionError::service(
            "bootstrap",
            group_id,
            "principal_id_missing",
            anyhow::anyhow!("principal id missing"),
        )
    })?;

    match perm.relate_to_allowed_principal_record(&pid, system).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("duplicate") || msg.contains("unique") || msg.contains("already") {
                Ok(())
            } else {
                Err(map_err("bootstrap", group_id, "grant_permission", e))
            }
        }
    }
}

struct CoarseCreateSpec<'a> {
    domain_id: &'a str,
    domain_name: &'a str,
    domain_description: &'a str,
    permission_id: &'a str,
    permission_name: &'a str,
    permission_description: &'a str,
    owners_group_id: &'a str,
}

async fn ensure_coarse_create_permission(
    system: &Valence,
    spec: CoarseCreateSpec<'_>,
) -> Result<(), ResourcePermissionError> {
    ensure_standalone_group(
        system,
        spec.owners_group_id,
        &format!("{} owners", spec.domain_name),
        "Owners for coarse create permission catalog",
    )
    .await?;

    if PermissionDomain::get(spec.domain_id, system)
        .await
        .map_err(|e| map_err("bootstrap", "", "get_domain", e))?
        .is_none()
    {
        let now = Utc::now();
        let domain = PermissionDomain::new(
            false,
            None,
            spec.domain_name.to_string(),
            Some(spec.domain_description.to_string()),
            now,
            now,
        )
        .map_err(|e| map_err("bootstrap", "", "new_domain", e))?;
        PermissionDomain::upsert(spec.domain_id, domain, system)
            .await
            .map_err(|e| map_err("bootstrap", "", "upsert_domain", e))?;
    }

    if Permission::get(spec.permission_id, system)
        .await
        .map_err(|e| map_err("bootstrap", "", "get_permission", e))?
        .is_some()
    {
        return Ok(());
    }

    // Idempotent by name as well.
    if Permission::query(system)
        .where_name(StringPredicate::Equals(spec.permission_name.to_string()))
        .limit(1)
        .first()
        .await
        .map_err(|e| map_err("bootstrap", "", "query_create_perm", e))?
        .is_some()
    {
        return Ok(());
    }

    let now = Utc::now();
    let permission = Permission::new(
        RecordId::new("user", "system"),
        RecordId::new("permission_group", spec.owners_group_id),
        RecordId::new("permission_domain", spec.domain_id),
        spec.permission_name.to_string(),
        Some(spec.permission_description.to_string()),
        now,
        now,
    )
    .map_err(|e| map_err("bootstrap", "", "new_create_permission", e))?;
    Permission::upsert(spec.permission_id, permission, system)
        .await
        .map_err(|e| map_err("bootstrap", "", "upsert_create_permission", e))?;
    Ok(())
}

/// Default umbrella group ids for a resource kind (viewers / editors / operators / creators).
///
/// Const-constructible so a [`ResourceKindDescriptor`] can name its groups inline.
/// Setting `editors` equal to `operators` collapses the two umbrellas, which is how
/// Neutrino secrets avoid a standing edit-only group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KindDefaultGroups {
    /// Coarse create group id.
    pub creators: &'static str,
    /// View umbrella.
    pub viewers: &'static str,
    /// Edit (+ View) umbrella.
    pub editors: &'static str,
    /// Delete (+ Edit + View) umbrella; for secrets also Reveal.
    pub operators: &'static str,
}

impl ResourceKind {
    /// Platform default group ids for this kind (`gluon.app.creators`, …).
    #[must_use]
    pub const fn default_groups(self) -> KindDefaultGroups {
        match self {
            Self::GluonApp => KindDefaultGroups {
                creators: "gluon.app.creators",
                viewers: "gluon.app.viewers",
                editors: "gluon.app.editors",
                operators: "gluon.app.operators",
            },
            Self::GluonAppSet => KindDefaultGroups {
                creators: "gluon.app_set.creators",
                viewers: "gluon.app_set.viewers",
                editors: "gluon.app_set.editors",
                operators: "gluon.app_set.operators",
            },
            Self::NeutrinoSecret => KindDefaultGroups {
                creators: "neutrino.secret.creators",
                viewers: "neutrino.secret.viewers",
                editors: "neutrino.secret.operators",
                operators: "neutrino.secret.operators",
            },
            Self::NucleusStack => KindDefaultGroups {
                creators: "nucleus.stack.creators",
                viewers: "nucleus.stack.viewers",
                editors: "nucleus.stack.editors",
                operators: "nucleus.stack.operators",
            },
        }
    }

    /// Coarse create permission name for this kind.
    #[must_use]
    pub const fn create_permission_name(self) -> &'static str {
        match self {
            Self::GluonApp => "CreateGluonApplications",
            Self::GluonAppSet => "CreateGluonAppSets",
            Self::NeutrinoSecret => "CreateNeutrinoSecrets",
            Self::NucleusStack => "CreateNucleusStacks",
        }
    }
}

/// Ensure default groups and the coarse `Create*` permission for one resource kind.
///
/// Call once per kind during **host wiring** (with Valence Gauge schemas registered),
/// before product create/seal APIs. Idempotent. Product crates typically wrap this
/// (e.g. Gluon’s `create_initial_gluon_groups`) with the kind’s domain ids.
///
/// `kind` takes a [`ResourceKind`], a [`ResourceKindDescriptor`], or a reference to
/// one, so a product that declares its own kind seeds it through this same call.
pub async fn seed_resource_kind_catalog(
    v: &Valence,
    kind: impl Into<ResourceKindDescriptor>,
    domain_id: &str,
    domain_name: &str,
    create_perm_id: &str,
) -> Result<(), ResourcePermissionError> {
    let kind = kind.into();
    let label = kind.display_label;
    let system = as_system(v, &format!("seed_resource_kind_catalog:{label}"));
    info!("[permission] seed_resource_kind_catalog kind={label} domain_id={domain_id}");
    let g = kind.groups;
    let create_name = kind.create_permission;

    ensure_standalone_group(
        &system,
        g.creators,
        &format!("{label} creators"),
        &format!("May create new {label} resources"),
    )
    .await?;
    ensure_standalone_group(
        &system,
        g.viewers,
        &format!("{label} viewers"),
        &format!("View umbrella for {label}"),
    )
    .await?;
    if g.editors != g.operators {
        ensure_standalone_group(
            &system,
            g.editors,
            &format!("{label} editors"),
            &format!("Edit umbrella for {label}"),
        )
        .await?;
    }
    ensure_standalone_group(
        &system,
        g.operators,
        &format!("{label} operators"),
        &format!("Operator umbrella for {label}"),
    )
    .await?;

    let owners = format!("{domain_id}_owners");
    ensure_coarse_create_permission(
        &system,
        CoarseCreateSpec {
            domain_id,
            domain_name,
            domain_description: &format!("Coarse create catalog for {label}"),
            permission_id: create_perm_id,
            permission_name: create_name,
            permission_description: &format!("Create new {label} resources"),
            owners_group_id: &owners,
        },
    )
    .await?;

    grant_named_permission_to_group(&system, g.creators, create_name).await?;
    Ok(())
}
