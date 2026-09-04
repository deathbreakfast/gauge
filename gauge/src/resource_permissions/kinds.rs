//! Resource kinds, actions, and stable permission / group name builders.
//!
//! [`ResourceKindDescriptor`] is what the name builders and the ensure / seed paths
//! actually read: a prefix, a label, an action set, an umbrella policy, four default
//! group ids, and a coarse create permission. [`ResourceKind`] is a frozen
//! compatibility shim for the four kinds shipped before descriptors existed; products
//! declare their own descriptor rather than adding a variant here.

use super::default_groups::KindDefaultGroups;

/// Frozen wire-format compatibility shim for the four kinds Gauge shipped before
/// [`ResourceKindDescriptor`].
///
/// **Products must not treat this enum as the extension point.** Declare a
/// `const ResourceKindDescriptor` (and your own `StaticPermissionGate` /
/// `ResourcePermissionPolicy`) in the owning product crate. Every variant is still
/// reachable as a descriptor via [`ResourceKind::descriptor`] or `From` so existing
/// golden tests and unpublished git consumers keep compiling until Gauge publishes a
/// release that can drop the variants.
///
/// Do **not** delete variants yet: product golden name tables and many path deps still
/// serialize against these four names.
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
        self.default_action_slice().to_vec()
    }

    /// Same set as [`ResourceKind::default_actions`], usable in const context.
    const fn default_action_slice(self) -> &'static [ResourceAction] {
        match self {
            Self::NeutrinoSecret => ResourceAction::WITH_REVEAL,
            Self::NucleusStack | Self::GluonApp | Self::GluonAppSet => ResourceAction::STANDARD,
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

    /// Everything Gauge needs to know about this kind, in one value.
    ///
    /// The descriptor is what the name builders and ensure paths read, so it is also
    /// the shape a product declares when it owns a kind Gauge has no variant for.
    #[must_use]
    pub const fn descriptor(self) -> ResourceKindDescriptor {
        ResourceKindDescriptor {
            prefix: self.prefix(),
            display_label: self.display_label(),
            actions: self.default_action_slice(),
            umbrella: self.umbrella_policy(),
            groups: self.default_groups(),
            create_permission: self.create_permission_name(),
        }
    }
}

/// Everything Gauge needs to name, seed, and gate one kind of resource.
///
/// Const-constructible end to end, so the crate that owns a resource kind declares
/// it once and hands the same value to the name builders,
/// [`super::seed_resource_kind_catalog`], [`super::ensure_resource_permission_bundle`],
/// and [`super::ResourcePermissionPolicy`]:
///
/// ```ignore
/// use gauge::resource_permissions::{
///     KindDefaultGroups, ResourceAction, ResourceKindDescriptor, UmbrellaPolicy,
/// };
///
/// pub const WIDGET: ResourceKindDescriptor = ResourceKindDescriptor {
///     prefix: "widget",
///     display_label: "Widget",
///     actions: ResourceAction::STANDARD,
///     umbrella: UmbrellaPolicy::KindWide,
///     groups: KindDefaultGroups {
///         creators: "widget.creators",
///         viewers: "widget.viewers",
///         editors: "widget.editors",
///         operators: "widget.operators",
///     },
///     create_permission: "CreateWidgets",
/// };
/// ```
///
/// `prefix` and the action suffixes end up in permission names, domain record ids,
/// and owners-group ids, so they are wire values: pick them once and treat a change
/// as a data migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceKindDescriptor {
    /// Snake prefix for permission names and record ids (e.g. `gluon_app`).
    pub prefix: &'static str,
    /// Human-readable label for domains, group names, and errors.
    pub display_label: &'static str,
    /// Actions materialized when a bundle does not name its own.
    pub actions: &'static [ResourceAction],
    /// Whether ensure auto-grants the kind's umbrella groups.
    pub umbrella: UmbrellaPolicy,
    /// Kind-wide group ids that receive umbrella grants.
    pub groups: KindDefaultGroups,
    /// Coarse create permission name checked before a resource exists.
    pub create_permission: &'static str,
}

impl ResourceKindDescriptor {
    /// Owned copy of [`ResourceKindDescriptor::actions`].
    #[must_use]
    pub fn default_actions(&self) -> Vec<ResourceAction> {
        self.actions.to_vec()
    }
}

impl From<ResourceKind> for ResourceKindDescriptor {
    fn from(kind: ResourceKind) -> Self {
        kind.descriptor()
    }
}

impl From<&Self> for ResourceKindDescriptor {
    fn from(descriptor: &Self) -> Self {
        *descriptor
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
    /// View / Edit / Delete / Maintain — the action set most kinds want.
    pub const STANDARD: &'static [Self] = &[Self::View, Self::Edit, Self::Delete, Self::Maintain];

    /// [`ResourceAction::STANDARD`] plus Reveal, for kinds holding secret material.
    pub const WITH_REVEAL: &'static [Self] = &[
        Self::View,
        Self::Reveal,
        Self::Edit,
        Self::Delete,
        Self::Maintain,
    ];

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
/// Format: `{kind_prefix}.{normalized_resource_id}.{Action}`. Takes a
/// [`ResourceKind`], a [`ResourceKindDescriptor`], or a reference to one.
#[must_use]
pub fn permission_name(
    kind: impl Into<ResourceKindDescriptor>,
    resource_id: &str,
    action: ResourceAction,
) -> String {
    format!(
        "{}.{}.{}",
        kind.into().prefix,
        normalize_id_fragment(resource_id),
        action.as_str()
    )
}

/// Stable domain record id for a resource bundle.
#[must_use]
pub fn domain_id(kind: impl Into<ResourceKindDescriptor>, resource_id: &str) -> String {
    format!(
        "rp_domain_{}_{}",
        kind.into().prefix,
        normalize_id_fragment(resource_id)
    )
}

/// Stable owners group id for a resource bundle.
#[must_use]
pub fn owners_group_id(kind: impl Into<ResourceKindDescriptor>, resource_id: &str) -> String {
    format!(
        "rp_owners_{}_{}",
        kind.into().prefix,
        normalize_id_fragment(resource_id)
    )
}

/// Stable permission record id for a resource action.
#[must_use]
pub fn permission_record_id(
    kind: impl Into<ResourceKindDescriptor>,
    resource_id: &str,
    action: ResourceAction,
) -> String {
    format!(
        "rp_perm_{}_{}_{}",
        kind.into().prefix,
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

    #[test]
    fn descriptor_matches_enum_accessors() {
        for kind in [
            ResourceKind::NeutrinoSecret,
            ResourceKind::NucleusStack,
            ResourceKind::GluonApp,
            ResourceKind::GluonAppSet,
        ] {
            let d = kind.descriptor();
            assert_eq!(d.prefix, kind.prefix());
            assert_eq!(d.display_label, kind.display_label());
            assert_eq!(d.actions.to_vec(), kind.default_actions());
            assert_eq!(d.umbrella, kind.umbrella_policy());
            assert_eq!(d.groups, kind.default_groups());
            assert_eq!(d.create_permission, kind.create_permission_name());
            assert_eq!(ResourceKindDescriptor::from(kind), d);
            assert_eq!(ResourceKindDescriptor::from(&d), d);
        }
    }

    #[test]
    fn builders_accept_kind_or_descriptor() {
        let kind = ResourceKind::NucleusStack;
        let d = kind.descriptor();
        assert_eq!(
            permission_name(kind, "stk-9", ResourceAction::Edit),
            permission_name(&d, "stk-9", ResourceAction::Edit)
        );
        assert_eq!(domain_id(kind, "stk-9"), domain_id(d, "stk-9"));
        assert_eq!(owners_group_id(kind, "stk-9"), owners_group_id(&d, "stk-9"));
        assert_eq!(
            permission_record_id(kind, "stk-9", ResourceAction::Delete),
            permission_record_id(&d, "stk-9", ResourceAction::Delete)
        );
    }
}
