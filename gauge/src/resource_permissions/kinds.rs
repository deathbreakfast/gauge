//! Resource kinds, actions, and stable permission / group name builders.

/// Kind of platform resource that receives a Gauge permission bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// Neutrino sealed secret.
    NeutrinoSecret,
    /// Nucleus database stack.
    NucleusStack,
    /// Gluon application.
    GluonApp,
    /// Gluon app set.
    GluonAppSet,
}

impl ResourceKind {
    /// Stable snake prefix used in permission names and domain keys (e.g. `gluon_app`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::NeutrinoSecret => "neutrino_secret",
            Self::NucleusStack => "nucleus_stack",
            Self::GluonApp => "gluon_app",
            Self::GluonAppSet => "gluon_app_set",
        }
    }

    /// Human-readable label for domains and errors.
    #[must_use]
    pub const fn display_label(self) -> &'static str {
        match self {
            Self::NeutrinoSecret => "Neutrino secret",
            Self::NucleusStack => "Nucleus stack",
            Self::GluonApp => "Gluon application",
            Self::GluonAppSet => "Gluon app set",
        }
    }

    /// Default actions for a new resource of this kind.
    #[must_use]
    pub fn default_actions(self) -> Vec<ResourceAction> {
        match self {
            Self::NeutrinoSecret => vec![
                ResourceAction::View,
                ResourceAction::Reveal,
                ResourceAction::Edit,
                ResourceAction::Delete,
                ResourceAction::Maintain,
            ],
            _ => vec![
                ResourceAction::View,
                ResourceAction::Edit,
                ResourceAction::Delete,
                ResourceAction::Maintain,
            ],
        }
    }

    /// Whether `ensure_resource_permission_bundle` auto-grants umbrella groups.
    ///
    /// [`UmbrellaPolicy::None`] for Neutrino secrets — access requires an explicit
    /// per-secret grant or owners-group membership. Gluon / Nucleus keep
    /// [`UmbrellaPolicy::KindWide`]. See
    /// [Who can act on a resource](crate#who-can-act-on-a-resource).
    #[must_use]
    pub const fn umbrella_policy(self) -> UmbrellaPolicy {
        match self {
            Self::NeutrinoSecret => UmbrellaPolicy::None,
            Self::NucleusStack | Self::GluonApp | Self::GluonAppSet => UmbrellaPolicy::KindWide,
        }
    }
}

/// Per-kind policy for auto-granting standing umbrella groups on ensure.
///
/// Source of truth for the umbrella column in
/// [Who can act on a resource](crate#who-can-act-on-a-resource).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UmbrellaPolicy {
    /// Grant View/Edit/Delete/Reveal to the kind's viewers / editors / operators groups.
    KindWide,
    /// No umbrella grants. The owners group still receives every action on the
    /// resource; additional access needs an explicit grant.
    None,
}

/// Named action on a resource permission bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceAction {
    /// Read / list metadata.
    View,
    /// Mutate non-destructive fields.
    Edit,
    /// Delete / deprovision the resource.
    Delete,
    /// Manage ACL / owners group for the resource.
    Maintain,
    /// Reveal secret plaintext (Neutrino secrets only).
    Reveal,
}

impl ResourceAction {
    /// Suffix used in permission names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "View",
            Self::Edit => "Edit",
            Self::Delete => "Delete",
            Self::Maintain => "Maintain",
            Self::Reveal => "Reveal",
        }
    }
}

/// Normalize a resource id into a Valence-safe ACL fragment.
///
/// Non-ASCII-alphanumeric characters become `_` and the result is lowercased.
/// A short FNV-1a digest of the **raw** id is appended so ids that collide after
/// sanitization (`abc-123` vs `abc_123`) still get distinct permission names,
/// domain ids, and owners groups. The digest is the ACL key's collision contract
/// — do not strip it at call sites.
///
/// Empty input yields an empty string (callers reject via `InvalidResourceId`).
#[must_use]
pub fn normalize_id_fragment(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        return String::new();
    }
    format!("{sanitized}_{}", short_digest(value))
}

/// Stable 8-hex-char digest of `raw` (FNV-1a 64-bit, truncated). Independent of
/// Rust's `DefaultHasher` so ACL keys stay stable across toolchain upgrades.
fn short_digest(raw: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in raw.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let full = format!("{hash:016x}");
    full[..8].to_string()
}

/// Build the unique Gauge permission name for a resource action.
///
/// Format: `{kind_prefix}.{normalized_resource_id}.{Action}`.
#[must_use]
pub fn permission_name(kind: ResourceKind, resource_id: &str, action: ResourceAction) -> String {
    format!(
        "{}.{}.{}",
        kind.prefix(),
        normalize_id_fragment(resource_id),
        action.as_str()
    )
}

/// Stable domain record id for a resource bundle.
#[must_use]
pub fn domain_id(kind: ResourceKind, resource_id: &str) -> String {
    format!(
        "rp_domain_{}_{}",
        kind.prefix(),
        normalize_id_fragment(resource_id)
    )
}

/// Stable owners group id for a resource bundle.
#[must_use]
pub fn owners_group_id(kind: ResourceKind, resource_id: &str) -> String {
    format!(
        "rp_owners_{}_{}",
        kind.prefix(),
        normalize_id_fragment(resource_id)
    )
}

/// Stable permission record id for a resource action.
#[must_use]
pub fn permission_record_id(
    kind: ResourceKind,
    resource_id: &str,
    action: ResourceAction,
) -> String {
    format!(
        "rp_perm_{}_{}_{}",
        kind.prefix(),
        normalize_id_fragment(resource_id),
        action.as_str().to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_name_is_stable() {
        let name = permission_name(ResourceKind::GluonApp, "App-1", ResourceAction::View);
        assert!(name.starts_with("gluon_app.app_1_"));
        assert!(name.ends_with(".View"));
        // Same raw id → same fragment every time.
        assert_eq!(
            permission_name(ResourceKind::GluonApp, "App-1", ResourceAction::View),
            name
        );
    }

    #[test]
    fn normalize_replaces_non_alnum_and_appends_digest() {
        let frag = normalize_id_fragment("A B");
        assert!(frag.starts_with("a_b_"));
        assert_eq!(frag.len(), "a_b_".len() + 8);
        assert_eq!(
            normalize_id_fragment("already_ok").starts_with("already_ok_"),
            true
        );
    }

    #[test]
    fn colliding_sanitized_ids_get_distinct_fragments() {
        let a = normalize_id_fragment("abc-123");
        let b = normalize_id_fragment("abc_123");
        let c = normalize_id_fragment("abc:123");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        assert!(a.starts_with("abc_123_"));
        assert!(b.starts_with("abc_123_"));
        assert!(c.starts_with("abc_123_"));
    }
}
