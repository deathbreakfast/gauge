#![cfg(feature = "ssr")]
#![allow(missing_docs)]

#[test]
fn permission_principal_trait_implementors_registered() {
    gauge::touch_schema_inventory();
    let tables = valence::TraitRegistry::global().tables_for_trait("PermissionPrincipal");
    assert!(
        tables.contains(&"permission_user_principal"),
        "expected permission_user_principal implementor, got: {:?}",
        tables
    );
    assert!(
        tables.contains(&"permission_group_principal"),
        "expected permission_group_principal implementor, got: {:?}",
        tables
    );
}
