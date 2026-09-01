//! Permission-check server functions.
//!
//! This module exposes lightweight request-context APIs that frontend/runtime
//! callers use to evaluate permission state.
//!
//! ## Capabilities
//!
//! - `has_permission_by_name`: check whether current actor has a permission.
//! - `resolve_permission_id_by_name`: resolve a permission name to its record id.
//!
//! ## Errors
//!
//! Both functions return Leptos `ServerFnError` (framework boundary). SSR maps
//! Valence / service failures with operation context; empty names are soft-false /
//! `None` rather than errors.

use leptos::prelude::*;

/// Returns `true` when the current request actor has the named permission.
#[server(HasPermissionByName)]
#[allow(clippy::unused_async)]
pub async fn has_permission_by_name(
    /// Name of the permission to check for the current request actor.
    permission_name: String,
) -> Result<bool, ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        let permission_name = permission_name.trim().to_string();
        if permission_name.is_empty() {
            return Ok(false);
        }

        let ctx = higgs::Higgs::from_request().await?;
        let valence = ctx
            .valence()
            .map_err(|e| ServerFnError::new(format!("Failed to build Valence: {e}")))?;
        let _caller = crate::instrumentation::PermissionCheckCallerGuard::new("server_fn");
        crate::service::actor_can(&valence, &permission_name)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to check permission: {e}")))
    }

    #[cfg(not(feature = "ssr"))]
    {
        let _ = permission_name;
        Ok(false)
    }
}

/// Resolve a permission name to id for authenticated users.
#[server(ResolvePermissionIdByName)]
#[allow(clippy::unused_async)]
pub async fn resolve_permission_id_by_name(
    /// Name of the permission to resolve to a record id.
    permission_name: String,
) -> Result<Option<String>, ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        use valence::StringPredicate;

        let permission_name = permission_name.trim().to_string();
        if permission_name.is_empty() {
            return Ok(None);
        }

        let ctx = higgs::Higgs::from_request().await?;
        if ctx.session_user_id().is_none() {
            return Ok(None);
        }

        let valence = ctx
            .valence()
            .map_err(|e| ServerFnError::new(format!("Failed to build Valence: {e}")))?;
        let rows = crate::generated::Permission::query(&valence)
            .where_name(StringPredicate::Equals(permission_name))
            .limit(1)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to query permission: {e}")))?;

        Ok(rows.into_iter().next().and_then(|row| {
            row.id()
                .and_then(|id| valence::extract_id_from_record(id).ok())
        }))
    }

    #[cfg(not(feature = "ssr"))]
    {
        let _ = permission_name;
        Ok(None)
    }
}
