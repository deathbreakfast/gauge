use chrono::Utc;
use valence::{Model, Valence};

use crate::generated::PermissionDomain;
use crate::types::{PermissionDomainCreateInput, PermissionDomainDetailDto};

use super::helpers::{get_domain_raw, raw_table_rows, record_pk_id, require_user_id};

pub fn domain_to_detail(domain: &PermissionDomain) -> PermissionDomainDetailDto {
    PermissionDomainDetailDto {
        id: record_pk_id(domain.id()),
        name: domain.name().clone(),
        description: domain.description().cloned().unwrap_or_default(),
    }
}

/// Create a new permission domain (taxonomy root). Requires an authenticated actor.
pub async fn create_domain(
    input: PermissionDomainCreateInput,
    v: &Valence,
) -> anyhow::Result<PermissionDomain> {
    let _actor_user_id = require_user_id(v)?;
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
    let created = PermissionDomain::create(domain, system).await?;
    Ok(created)
}

/// Load a single permission domain by id, or `None` if it does not exist.
pub async fn get_domain_detail(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionDomainDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    let Some(domain) = get_domain_raw(id, v).await? else {
        return Ok(None);
    };
    Ok(Some(domain_to_detail(&domain)))
}

/// List permission domains, optionally filtered by a name/description-contains `search` term.
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
        out.push(domain_to_detail(&domain));
    }
    Ok(out)
}
