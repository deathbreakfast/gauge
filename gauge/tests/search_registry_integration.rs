#![cfg(feature = "ssr")]
#![allow(missing_docs)]

#[test]
fn search_source_registry_discovers_permission_sources() {
    // Force the module containing inventory registrations to be linked.
    let _ = gauge::search_sources::PermissionSearchSourceId::User.as_str();
    let _ = gauge::search_sources::PermissionSearchSourceId::PermissionGroup.as_str();

    let registry = uf_search_core::SearchSourceRegistry::auto_discover();
    assert!(registry.get("user_search_source").is_some());
    assert!(registry.get("permission_group_search_source").is_some());
}
