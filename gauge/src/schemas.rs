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
    );
}
