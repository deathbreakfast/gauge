//! Typed service-layer errors (authz, not-found, validation, invariants).
//!
//! Public service APIs still return [`anyhow::Result`] so hosts can `?` into
//! application aggregates; classify failures by downcasting to
//! [`GaugeServiceError`] via [`anyhow::Error::downcast_ref`].

use std::fmt;

/// Classifiable Gauge service failure.
#[derive(Debug)]
pub enum GaugeServiceError {
    /// Caller is not allowed to perform the operation.
    NotAuthorized {
        /// Short operation label (safe to log).
        operation: String,
    },
    /// Referenced entity does not exist.
    NotFound {
        /// Entity kind (e.g. `permission`, `permission_group`).
        entity: String,
        /// Caller-supplied id (safe identifier).
        id: String,
    },
    /// Invalid caller input.
    Validation {
        /// Human-readable validation message (no secrets).
        message: String,
    },
    /// Local invariant broken (e.g. missing id after create).
    Invariant {
        /// What invariant failed.
        message: String,
    },
}

impl GaugeServiceError {
    /// Caller is not allowed to perform `operation`.
    pub fn not_authorized(operation: impl Into<String>) -> Self {
        Self::NotAuthorized {
            operation: operation.into(),
        }
    }

    /// `entity` with id `id` was not found.
    pub fn not_found(entity: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity: entity.into(),
            id: id.into(),
        }
    }

    /// Invalid caller input described by `message`.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Broken local invariant described by `message`.
    pub fn invariant(message: impl Into<String>) -> Self {
        Self::Invariant {
            message: message.into(),
        }
    }
}

impl fmt::Display for GaugeServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthorized { operation } => {
                write!(f, "Not authorized to {operation}")
            }
            Self::NotFound { entity, id } => write!(f, "{entity} not found: {id}"),
            Self::Validation { message } | Self::Invariant { message } => {
                write!(f, "{message}")
            }
        }
    }
}

impl std::error::Error for GaugeServiceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_downcast_via_anyhow() {
        let err: anyhow::Error = GaugeServiceError::not_found("permission", "p1").into();
        let typed = err.downcast_ref::<GaugeServiceError>().expect("typed");
        assert!(matches!(
            typed,
            GaugeServiceError::NotFound { entity, id }
                if entity == "permission" && id == "p1"
        ));
        assert_eq!(typed.to_string(), "permission not found: p1");
    }
}
