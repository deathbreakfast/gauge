//! Typed errors for resource permission bundles and host wiring.

use std::fmt;

/// Errors from [`super::ensure_resource_permission_bundle`] and [`super::seed_resource_kind_catalog`].
#[derive(Debug)]
pub enum ResourcePermissionError {
    /// `maintainer_actor` was empty or not a usable user id.
    MissingMaintainer {
        /// Resource kind label (e.g. `gluon_app`).
        kind: String,
        /// Caller-supplied resource id (safe identifier).
        resource_id: String,
    },
    /// Resource id was empty or illegal after normalization.
    InvalidResourceId {
        /// Resource kind label.
        kind: String,
    },
    /// Underlying Gauge / Valence service failure.
    GaugeService {
        /// Resource kind label.
        kind: String,
        /// Resource id when applicable (empty for bootstrap-only ops).
        resource_id: String,
        /// Operation label (e.g. `ensure_domain`, `grant_view`).
        operation: String,
        /// Source error.
        source: anyhow::Error,
    },
}

impl fmt::Display for ResourcePermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMaintainer { kind, resource_id } => write!(
                f,
                "resource permission ensure requires maintainer_actor (kind={kind}, resource_id={resource_id})"
            ),
            Self::InvalidResourceId { kind } => {
                write!(f, "invalid resource_id for kind={kind}")
            }
            Self::GaugeService {
                kind,
                resource_id,
                operation,
                source,
            } => write!(
                f,
                "gauge resource permission {operation} failed (kind={kind}, resource_id={resource_id}): {source}"
            ),
        }
    }
}

impl std::error::Error for ResourcePermissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GaugeService { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl ResourcePermissionError {
    pub(crate) fn service(
        kind: impl Into<String>,
        resource_id: impl Into<String>,
        operation: impl Into<String>,
        source: impl Into<anyhow::Error>,
    ) -> Self {
        Self::GaugeService {
            kind: kind.into(),
            resource_id: resource_id.into(),
            operation: operation.into(),
            source: source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResourcePermissionError;
    use std::error::Error;

    #[test]
    fn display_and_source_for_variants() {
        let missing = ResourcePermissionError::MissingMaintainer {
            kind: "gluon_app".into(),
            resource_id: "app-1".into(),
        };
        assert!(missing.to_string().contains("maintainer_actor"));
        assert!(missing.source().is_none());

        let invalid = ResourcePermissionError::InvalidResourceId {
            kind: "gluon_app".into(),
        };
        assert!(invalid.to_string().contains("invalid resource_id"));
        assert!(invalid.source().is_none());

        let service = ResourcePermissionError::service(
            "gluon_app",
            "app-1",
            "ensure_domain",
            anyhow::anyhow!("backend down"),
        );
        let msg = service.to_string();
        assert!(msg.contains("ensure_domain"));
        assert!(msg.contains("gluon_app"));
        assert!(service.source().is_some());
    }
}
