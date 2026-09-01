//! Search-source registration for permission principal pickers (users and groups).

#![allow(missing_docs)]

#[cfg(feature = "ssr")]
use valence::Model;

uf_product_macros::define_search_sources! {
    enum PermissionSearchSourceId {
        User => {
            id: "user_search_source",
            label: "Users",
            description: "Searches user principals",
            provider: PlatformUserSearchSource
        },
        PermissionGroup => {
            id: "permission_group_search_source",
            label: "Permission Groups",
            description: "Searches permission-group principals",
            provider: PermissionGroupSearchSource
        }
    }
}

/// [`uf_search_core::SearchSourceProvider`] searching users by email, for principal pickers.
#[cfg(feature = "ssr")]
pub struct PlatformUserSearchSource;

#[cfg(feature = "ssr")]
impl uf_search_core::SearchSourceProvider for PlatformUserSearchSource {
    fn query<'a>(
        &'a self,
        v: &'a valence::Valence,
        query_text: &'a str,
        max_results: u32,
    ) -> uf_search_core::SearchSourceFuture<'a> {
        Box::pin(async move {
            let query_lower = query_text.to_lowercase();
            // InMemory backends only apply equality WHERE; scan + filter Contains here.
            let users = lepton::generated::User::query(v)
                .limit(max_results.saturating_mul(20).max(50))
                .await?;
            let mut out = Vec::new();
            for user in users {
                let id: String = user
                    .id()
                    .and_then(|t| valence::extract_id_from_record(t).ok())
                    .unwrap_or_default();
                let title = match user.primary_email() {
                    Some(pid) => {
                        let bare = valence::extract_id_from_record(pid).unwrap_or_default();
                        lepton::generated::AccountEmail::get(&bare, v)
                            .await?
                            .map_or_else(
                                || id.clone(),
                                |email| {
                                    let address = email.address().clone();
                                    if address.is_empty() {
                                        id.clone()
                                    } else {
                                        address
                                    }
                                },
                            )
                    }
                    None => id.clone(),
                };
                if !query_lower.is_empty()
                    && !id.to_lowercase().contains(&query_lower)
                    && !title.to_lowercase().contains(&query_lower)
                {
                    continue;
                }
                out.push(uf_search_core::SearchSourceItem {
                    source_id: PermissionSearchSourceId::User.as_str().to_string(),
                    id,
                    title,
                    description: Some("User account".to_string()),
                    kind: "user".to_string(),
                });
                if out.len() >= max_results as usize {
                    break;
                }
            }

            Ok(out)
        })
    }
}

/// [`uf_search_core::SearchSourceProvider`] searching permission groups by name/description.
#[cfg(feature = "ssr")]
pub struct PermissionGroupSearchSource;

#[cfg(feature = "ssr")]
impl uf_search_core::SearchSourceProvider for PermissionGroupSearchSource {
    fn query<'a>(
        &'a self,
        v: &'a valence::Valence,
        query_text: &'a str,
        max_results: u32,
    ) -> uf_search_core::SearchSourceFuture<'a> {
        Box::pin(async move {
            // InMemory backends only apply equality WHERE clauses; filter Contains
            // in-process so pickers work across mem/sqlite/surreal.
            let groups = crate::generated::PermissionGroup::query(v)
                .limit(max_results.saturating_mul(20).max(50))
                .await?;
            let query_lower = query_text.to_lowercase();
            let out = groups
                .into_iter()
                .filter(|group| {
                    if query_lower.is_empty() {
                        return true;
                    }
                    group.name().to_lowercase().contains(&query_lower)
                        || group
                            .description()
                            .is_some_and(|d| d.to_lowercase().contains(&query_lower))
                })
                .take(max_results as usize)
                .map(|group| uf_search_core::SearchSourceItem {
                    source_id: PermissionSearchSourceId::PermissionGroup
                        .as_str()
                        .to_string(),
                    id: group
                        .id()
                        .and_then(|t| valence::extract_id_from_record(t).ok())
                        .unwrap_or_default(),
                    title: group.name().clone(),
                    description: Some(group.description().cloned().unwrap_or_default()),
                    kind: "permission_group".to_string(),
                })
                .collect::<Vec<_>>();
            Ok(out)
        })
    }
}
