//! Force-link trait inventory. Entity schemas are registered by
//! `generated_models.rs` (build.rs / valence-codegen) with trait fields already
//! merged — do **not** also `include!` the `valence_schema!` sources here, or
//! inventory order can let the incomplete macro-only schema (entity fields
//! only) overwrite the complete codegen schema (see `spectra-topics` + history
//! integration failures).

#[cfg(feature = "ssr")]
mod permission_shared_trait {
    include!("../schemas/permission_shared_valence_trait.rs");
    #[doc(hidden)]
    pub const __INVENTORY_LINK: () = ();
}

#[cfg(feature = "ssr")]
mod permission_principal_trait {
    include!("../schemas/permission_principal_valence_trait.rs");
    #[doc(hidden)]
    pub const __INVENTORY_LINK: () = ();
}

#[cfg(feature = "ssr")]
mod history_source_trait {
    include!("../schemas/history_source_valence_trait.rs");
    #[doc(hidden)]
    pub const __INVENTORY_LINK: () = ();
}

#[cfg(feature = "ssr")]
mod record_history_trait {
    include!("../schemas/record_history_valence_trait.rs");
    #[doc(hidden)]
    pub const __INVENTORY_LINK: () = ();
}

/// Keep trait `inventory` submissions linked and retain generated model modules
/// (which submit the complete entity [`valence::SchemaMetadataInit`] entries).
#[cfg(feature = "ssr")]
#[inline(never)]
pub fn ensure_inventory_linked() {
    let _ = (
        permission_shared_trait::__INVENTORY_LINK,
        permission_principal_trait::__INVENTORY_LINK,
        history_source_trait::__INVENTORY_LINK,
        record_history_trait::__INVENTORY_LINK,
        std::any::type_name::<crate::generated::PermissionGroup>(),
        std::any::type_name::<crate::generated::Permission>(),
        std::any::type_name::<crate::generated::PermissionDomain>(),
        std::any::type_name::<crate::generated::PermissionHistory>(),
        std::any::type_name::<crate::generated::PermissionRequest>(),
        std::any::type_name::<crate::generated::PermissionUserPrincipal>(),
        std::any::type_name::<crate::generated::PermissionGroupPrincipal>(),
        std::any::type_name::<crate::generated::PermissionServiceUserPrincipal>(),
    );
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    #![allow(clippy::expect_used)]

    /// Every permission check looks rows up by `name`; without the index each lookup scans
    /// the whole table, which grows with every resource that gets a permission bundle.
    #[test]
    fn permission_names_are_indexed_happy() {
        super::ensure_inventory_linked();
        for table in ["permission", "permission_group", "permission_domain"] {
            let meta = valence::SchemaRegistry::global()
                .get_schema(table)
                .expect("schema registered");
            let field = |name: &str| {
                meta.schema
                    .fields
                    .iter()
                    .find(|f| f.name == name)
                    .unwrap_or_else(|| panic!("{table}.{name} missing"))
            };
            assert!(field("name").indexed, "{table}.name should be indexed");
            assert!(
                !field("description").indexed,
                "{table}.description should not be indexed"
            );
        }
    }
}
