use chrono::Utc;
use valence::{Model, Valence};

use crate::generated::PermissionDomain;
use crate::super_user::actor_is_super_user;
use crate::types::{PermissionDomainCreateInput, PermissionDomainDetailDto, PrincipalKind};

use super::access::can_edit_domain;
use super::helpers::{
    domain_has_owner_user, ensure_user_principal, get_domain_raw, get_user_by_actor_id,
    principal_ref_from_record, raw_table_rows, record_pk_id, redact_user_principal_label,
    require_model_id, require_user_id, user_id_candidates,
};

fn domain_to_list_detail(domain: &PermissionDomain) -> PermissionDomainDetailDto {
    PermissionDomainDetailDto {
        id: record_pk_id(domain.id()),
        name: domain.name().clone(),
        description: domain.description().cloned().unwrap_or_default(),
        owner_users: Vec::new(),
        resource_scoped: *domain.resource_scoped(),
    }
}

/// Create a new taxonomy permission domain. Requires an authenticated actor and
/// attaches that actor as the first owner.
pub async fn create_domain(
    input: PermissionDomainCreateInput,
    v: &Valence,
) -> anyhow::Result<PermissionDomain> {
    let actor_user_id = require_user_id(v)?;
    let now = Utc::now();
    let domain = PermissionDomain::new(
        false,
        None,
        input.name,
        if input.description.trim().is_empty() {
            None
        } else {
            Some(input.description)
        },
        now,
        now,
    )?;
    let system = v;
    let created = PermissionDomain::create(domain, system, valence::use_!(r"When **Gauge permissions** needs to persist work, we **save Permission Domain** so the next step in that feature can continue with the latest values. People and services allowed for **Gauge permissions** use this data for that workflow—not as a general export of unrelated personal fields.")).await?;

    let lookup = v;
    if let Some(user) = get_user_by_actor_id(&actor_user_id, lookup).await? {
        let principal = ensure_user_principal(&record_pk_id(user.id()), lookup).await?;
        let principal_id = require_model_id(principal.id(), "principal")?;
        created
            .relate_to_owner_record(&principal_id, lookup, valence::use_!(r"When an operator **creates a permission domain** in **Gauge**, we **write the owner edge** from the domain to that principal so later checks know who can rename and delete it. Operators see the updated owners on the domain detail."))
            .await?;
    }

    Ok(created)
}

/// Update a taxonomy domain's name/description (owner or Super User only).
pub async fn update_domain(
    id: &str,
    name: String,
    description: String,
    v: &Valence,
) -> anyhow::Result<PermissionDomain> {
    let _actor_user_id = require_user_id(v)?;
    let system = v;
    let existing = get_domain_raw(id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission domain", id))?;
    if *existing.resource_scoped() {
        return Err(super::GaugeServiceError::validation(
            "Cannot rename a resource-scoped permission domain",
        )
        .into());
    }
    if !can_edit_domain(&existing, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit domain").into());
    }

    let next_name = name.trim().to_string();
    if next_name.is_empty() {
        return Err(super::GaugeServiceError::validation("Domain name is required").into());
    }
    let desc = if description.trim().is_empty() {
        None
    } else {
        Some(description)
    };
    let mut builder = existing
        .get_mutable(v, valence::use_!(r"In **Gauge permissions**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **Gauge permissions** use the updated data; this is not a public export of unrelated fields."))
        .set_name(next_name)?
        .set_updated_at(Utc::now())?;
    builder = match desc {
        Some(d) => builder.set_description(d)?,
        None => builder,
    };
    Ok(builder.commit().await?)
}

/// Delete a taxonomy domain (owner or Super User only). Rejects resource-scoped domains.
pub async fn delete_domain(id: &str, v: &Valence) -> anyhow::Result<()> {
    let _actor_user_id = require_user_id(v)?;
    let system = v;
    let existing = get_domain_raw(id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission domain", id))?;
    if *existing.resource_scoped() {
        return Err(super::GaugeServiceError::validation(
            "Cannot delete a resource-scoped permission domain from the taxonomy UI",
        )
        .into());
    }
    if !can_edit_domain(&existing, v).await? {
        return Err(super::GaugeServiceError::not_authorized("delete domain").into());
    }
    PermissionDomain::delete(
        id,
        v,
        valence::use_!(r"When an operator **deletes a permission domain** in **Gauge**, we **remove the domain row** so it no longer appears in the taxonomy catalog. Operators use this path from the domain detail page."),
    )
    .await?;
    Ok(())
}

/// Add `user_id` as an owner of `domain_id` (owner or Super User only).
pub async fn add_domain_owner_user(
    domain_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let _actor_user_id = require_user_id(v)?;
    let system = v;
    let domain = get_domain_raw(domain_id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission domain", domain_id))?;
    if *domain.resource_scoped() {
        return Err(super::GaugeServiceError::validation(
            "Cannot change owners on a resource-scoped permission domain",
        )
        .into());
    }
    if !can_edit_domain(&domain, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit domain ownership").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    domain
        .relate_to_owner_record(&require_model_id(principal.id(), "principal")?, system, valence::use_!(r"When an operator **adds a domain owner** in **Gauge**, we **write the owner edge** from the permission domain to that principal so later checks know who can rename and delete it. Operators see the updated owners on the domain detail."))
        .await?;
    Ok(())
}

/// Remove `user_id` as an owner of `domain_id`; fails if it would remove the last owner.
pub async fn remove_domain_owner_user(
    domain_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let domain = get_domain_raw(domain_id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission domain", domain_id))?;
    if *domain.resource_scoped() {
        return Err(super::GaugeServiceError::validation(
            "Cannot change owners on a resource-scoped permission domain",
        )
        .into());
    }
    if !domain_has_owner_user(&domain, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit domain ownership").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    let owner_ids = domain
        .get_owners_record_ids(system, valence::use_!(r"When **Gauge** needs the **owners of a permission domain**, we **follow the owner edges** so the product can show owners on the domain detail or decide who may edit. Editors see that list; access checks use it only to allow or deny."))
        .await?
        .into_iter()
        .map(|rid| rid.id().to_string())
        .collect::<Vec<_>>();
    let target_principal_id =
        valence::extract_id_from_record(&require_model_id(principal.id(), "principal")?)
            .unwrap_or_default();
    let target_is_owner = owner_ids.iter().any(|id| id == &target_principal_id);
    if target_is_owner && owner_ids.len() <= 1 {
        return Err(super::GaugeServiceError::validation(
            "Cannot remove the last owner from a domain",
        )
        .into());
    }

    domain
        .unrelate_from_owner_record(&require_model_id(principal.id(), "principal")?, system, valence::use_!(r"When an operator **removes a domain owner** in **Gauge**, we **delete the owner edge** so that principal no longer counts as an owner for renames and deletes. Operators see the updated owners on the domain detail."))
        .await?;
    Ok(())
}

/// Load a single permission domain by id, or `None` if it does not exist.
/// Owners are returned only for editors (domain owners and Super User).
pub async fn get_domain_detail(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionDomainDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    let Some(domain) = get_domain_raw(id, v).await? else {
        return Ok(None);
    };

    let reveal_sensitive = can_edit_domain(&domain, v).await?;
    let mut owner_users = Vec::new();
    if reveal_sensitive {
        let mut owner_seen = std::collections::HashSet::new();
        for owner in domain
            .get_owners_record_ids(
                v,
                valence::use_!(r"When **Gauge** needs the **owners of a permission domain**, we **follow the owner edges** so the product can show owners on the domain detail or decide who may edit. Editors see that list; access checks use it only to allow or deny."),
            )
            .await?
        {
            if let Some(reference) = principal_ref_from_record(&owner, v).await? {
                if reference.kind != PrincipalKind::User {
                    continue;
                }
                let key = format!("{:?}:{}", reference.kind, reference.id);
                if owner_seen.insert(key) {
                    owner_users.push(redact_user_principal_label(reference, true));
                }
            }
        }
    }

    Ok(Some(PermissionDomainDetailDto {
        id: record_pk_id(domain.id()),
        name: domain.name().clone(),
        description: domain.description().cloned().unwrap_or_default(),
        owner_users,
        resource_scoped: *domain.resource_scoped(),
    }))
}

/// List permission domains, optionally filtered by a name/description-contains `search` term.
/// Owner lists are always empty on list responses.
pub async fn list_domains(
    v: &Valence,
    search: Option<String>,
) -> anyhow::Result<Vec<PermissionDomainDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    let needle = search
        .as_ref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let mut out = Vec::new();
    for row in raw_table_rows("permission_domain", v).await? {
        let domain: PermissionDomain = serde_json::from_value(row)
            .map_err(|e| anyhow::anyhow!("decode permission_domain: {e}"))?;
        if let Some(ref needle) = needle {
            let name = domain.name().to_lowercase();
            let description = domain
                .description()
                .map(|d| d.to_lowercase())
                .unwrap_or_default();
            if !name.contains(needle) && !description.contains(needle) {
                continue;
            }
        }
        out.push(domain_to_list_detail(&domain));
    }
    Ok(out)
}
