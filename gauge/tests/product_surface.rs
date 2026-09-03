//! Product surface contracts for gauge-app (composer repo).
//!
//! Lives under the **gauge domain** crate so local monorepo CI can gate
//! route/testid/auth/admin needles without compiling Orbital/turf UI.
//! When `L4-composers/gauge-uf-app` is absent (standalone uf-dev CI), each
//! test returns early — domain contract suites remain the merge gate.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn composer_app_src() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("L4-composers/gauge-uf-app/gauge-app/src");
    path.is_dir().then_some(path)
}

fn read_app(rel: &str) -> Option<String> {
    let src = composer_app_src()?;
    let path = src.join(rel);
    fs::read_to_string(&path).ok()
}

#[test]
fn permission_routes_mount_happy_path() {
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    for needle in [
        r#"path!("permission")"#,
        r#"path!("")"#,
        r#"path!("permissions")"#,
        r#"path!("permissions/:id")"#,
        r#"path!("create-permission")"#,
        r#"path!("create-domain")"#,
        r#"path!("groups")"#,
        r#"path!("groups/:id")"#,
        r#"path!("create-group")"#,
        r#"path!("requests")"#,
        r#"path!("requests/:id")"#,
        "PermissionLayout",
        "id: \"permission\"",
        "route_path: \"/permission\"",
        "permission_manifest: permissions::GaugePermission",
    ] {
        assert!(
            lib.contains(needle),
            "PermissionRoutes / uf_app missing `{needle}`"
        );
    }
}

#[test]
fn permission_routes_drop_leaf_sad_path() {
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    for needle in [
        r#"path!("create-domain")"#,
        r#"path!("requests/:id")"#,
        r#"path!("groups/:id")"#,
    ] {
        assert!(
            lib.contains(needle),
            "removing `{needle}` drops a Permission admin funnel entry"
        );
    }
    assert!(
        !lib.contains("unimplemented!"),
        "PermissionRoutes must not ship unimplemented placeholders"
    );
}

#[test]
fn uf_app_wrong_id_sad_path() {
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    assert!(
        lib.contains("id: \"permission\""),
        "wrong uf_app id breaks Orbital host registration"
    );
    assert!(
        !lib.contains("id: \"gauge\""),
        "uf_app id must stay `permission` (product route id), not crate name gauge"
    );
}

#[test]
fn layout_auth_gate_and_nav_happy_path() {
    let Some(layout) = read_app("layout.rs") else {
        return;
    };
    for needle in [
        "permission-app-root",
        "RequireAuthenticated",
        "Outlet",
        "nav-permissions",
        "nav-create-permission",
        "nav-create-domain",
        "nav-requests",
        "nav-groups",
        "nav-create-group",
        "AppBarUserMenu",
        "UnifiedFieldShellLayout",
    ] {
        assert!(
            layout.contains(needle),
            "PermissionLayout missing contract `{needle}`"
        );
    }
}

#[test]
fn layout_drop_auth_guard_sad_path() {
    let Some(layout) = read_app("layout.rs") else {
        return;
    };
    assert!(
        layout.contains("RequireAuthenticated") && layout.contains("<Outlet />"),
        "removing RequireAuthenticated opens /permission pages to anonymous sessions"
    );
    assert!(
        layout.contains("requires_email_verification=true"),
        "layout must keep email-verification gate on the admin outlet"
    );
}

#[test]
fn layout_missing_nav_sad_path() {
    let Some(layout) = read_app("layout.rs") else {
        return;
    };
    for id in [
        "nav-permissions",
        "nav-create-permission",
        "nav-create-domain",
        "nav-requests",
        "nav-groups",
        "nav-create-group",
    ] {
        assert!(
            layout.contains(id),
            "dropping `{id}` breaks operator left-nav contract"
        );
    }
}

#[test]
fn admin_mutations_require_gauge_admin_happy_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    for fn_name in [
        "create_domain",
        "create_permission",
        "create_group",
        "search_principals",
    ] {
        assert!(server.contains(fn_name), "server missing `{fn_name}`");
    }
    let admin_attr = r#"permission = "GaugeAdmin""#;
    assert!(
        server.matches(admin_attr).count() >= 4,
        "admin mutations must carry GaugeAdmin permission attribute"
    );
    assert!(
        server.contains("GAUGE_ADMIN_PERMISSION: &str = \"GaugeAdmin\""),
        "GAUGE_ADMIN_PERMISSION constant must stay GaugeAdmin"
    );
    // TM-SEC-09 runtime deny: gauge-uf-app-e2e `*_no_admin` scenarios (save_no_admin,
    // principals_no_admin). Static attribute coverage above is not a substitute.
}

/// Attribute window immediately before `pub async fn {name}(`.
///
/// Require the opening `(` so `create_permission` does not match
/// `create_permission_request`.
fn server_fn_attr_window<'a>(server: &'a str, fn_name: &str) -> &'a str {
    let needle = format!("pub async fn {fn_name}(");
    let start = server
        .find(&needle)
        .unwrap_or_else(|| panic!("missing fn `{fn_name}`"));
    &server[start.saturating_sub(220)..start]
}

#[test]
fn tier_a_mutations_require_step_up_window_happy_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    // TM-11: window step-up on Tier A mutations (macro `step_up` → require_step_up("window")).
    for fn_name in [
        "create_permission",
        "update_permission",
        "delete_permission",
        "delete_group",
        "add_permission_user",
        "remove_permission_user",
        "add_permission_group",
        "remove_permission_group",
        "add_group_group",
        "remove_group_group",
        "decide_permission_request",
    ] {
        let window = server_fn_attr_window(&server, fn_name);
        assert!(
            window.contains("step_up"),
            "`{fn_name}` must carry `step_up` (TM-11 window gate)"
        );
    }
}

#[test]
fn create_domain_and_create_group_must_not_require_step_up_sad_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    // Domains/groups creation stay GaugeAdmin-only; step-up applies to Tier A mutations.
    for fn_name in ["create_domain", "create_group"] {
        let window = server_fn_attr_window(&server, fn_name);
        assert!(
            window.contains(r#"permission = "GaugeAdmin""#),
            "`{fn_name}` must stay GaugeAdmin"
        );
        assert!(
            !window.contains("step_up"),
            "`{fn_name}` must not carry `step_up`"
        );
    }
}

#[test]
fn super_user_membership_requires_fresh_totp_happy_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    assert!(
        server.contains("fn require_group_membership_step_up"),
        "membership helper must exist for Super User fresh TOTP"
    );
    assert!(
        server.contains("verify_fresh_totp") && server.contains(r#"require_step_up("window")"#),
        "membership helper must verify_fresh_totp for Super User and window otherwise"
    );
    for fn_name in [
        "add_group_user",
        "add_group_owner_user",
        "remove_group_owner_user",
        "remove_group_user",
    ] {
        let needle = format!("pub async fn {fn_name}(");
        let start = server
            .find(&needle)
            .unwrap_or_else(|| panic!("missing fn `{fn_name}`"));
        let body_end = (start + 700).min(server.len());
        let body = &server[start..body_end];
        assert!(
            body.contains("totp_code"),
            "`{fn_name}` must take `totp_code` for Super User fresh step-up"
        );
        assert!(
            body.contains("require_group_membership_step_up"),
            "`{fn_name}` must call require_group_membership_step_up"
        );
        let window = server_fn_attr_window(&server, fn_name);
        assert!(
            !window.contains("step_up"),
            "`{fn_name}` uses helper step-up, not macro `step_up`"
        );
    }
}

#[test]
fn request_workflow_must_not_require_gauge_admin_sad_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    // Session + service ownership checks apply; GaugeAdmin would block normal requestors.
    for block_start in [
        "pub async fn create_permission_request",
        "pub async fn list_my_permission_requests",
        "pub async fn list_review_permission_requests",
        "pub async fn get_permission_request",
        "pub async fn decide_permission_request",
    ] {
        let start = server
            .find(block_start)
            .unwrap_or_else(|| panic!("missing `{block_start}`"));
        let window_start = start.saturating_sub(160);
        let window = &server[window_start..start];
        assert!(
            !window.contains(r#"permission = "GaugeAdmin""#),
            "`{block_start}` must not require GaugeAdmin (request funnel is session-scoped)"
        );
    }
}

#[test]
fn search_principals_clamps_results_and_avoids_query_logging_happy_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    assert!(
        server.contains("MAX_PRINCIPAL_SEARCH_RESULTS"),
        "search_principals must define a max_results hard cap"
    );
    assert!(
        server.contains("max_results.clamp(1, MAX_PRINCIPAL_SEARCH_RESULTS)"),
        "search_principals must clamp max_results"
    );
    assert!(
        server.contains("query_len={}"),
        "search_principals must log query length, not the raw query string"
    );
    assert!(
        !server.contains("query='{}'"),
        "search_principals must not log the raw principal search query"
    );
}

#[test]
fn server_require_session_happy_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    assert!(
        server.contains("fn require_session")
            && server.contains("Authentication required")
            && server.contains("session_user_id()"),
        "server must fail closed without a session"
    );
    for call_site in [
        "list_permissions",
        "create_domain",
        "decide_permission_request",
    ] {
        assert!(server.contains(call_site), "server missing `{call_site}`");
    }
}

#[test]
fn server_drop_require_session_on_list_sad_path() {
    let Some(server) = read_app("server.rs") else {
        return;
    };
    let start = server
        .find("pub async fn list_permissions")
        .expect("list_permissions");
    let body = &server[start..start + 450.min(server.len() - start)];
    assert!(
        body.contains("require_session(&ctx)?"),
        "list_permissions must call require_session before service"
    );
}

#[test]
fn index_pages_testid_and_list_bindings_happy_path() {
    let Some(permissions) = read_app("pages/permissions_index.rs") else {
        return;
    };
    for needle in [
        "gauge-permissions-index",
        "list_permissions",
        "CREATE_PERMISSION",
    ] {
        assert!(
            permissions.contains(needle),
            "PermissionsIndexPage missing `{needle}`"
        );
    }

    let Some(groups) = read_app("pages/groups_index.rs") else {
        return;
    };
    for needle in ["gauge-groups-index", "list_groups", "CREATE_GROUP"] {
        assert!(
            groups.contains(needle),
            "GroupsIndexPage missing `{needle}`"
        );
    }

    let Some(requests) = read_app("pages/requests_index.rs") else {
        return;
    };
    for needle in [
        "gauge-requests-index",
        "list_my_permission_requests",
        "list_review_permission_requests",
    ] {
        assert!(
            requests.contains(needle),
            "RequestsIndexPage missing `{needle}`"
        );
    }
}

#[test]
fn index_drop_permissions_testid_sad_path() {
    let Some(permissions) = read_app("pages/permissions_index.rs") else {
        return;
    };
    assert!(
        permissions.contains("data_testid=\"gauge-permissions-index\""),
        "dropping gauge-permissions-index breaks host / future Playwright parity"
    );
    let Some(groups) = read_app("pages/groups_index.rs") else {
        return;
    };
    assert!(
        groups.contains("data_testid=\"gauge-groups-index\""),
        "dropping gauge-groups-index breaks host / future Playwright parity"
    );
    let Some(requests) = read_app("pages/requests_index.rs") else {
        return;
    };
    assert!(
        requests.contains("data_testid=\"gauge-requests-index\""),
        "dropping gauge-requests-index breaks host / future Playwright parity"
    );
}

#[test]
fn request_detail_decide_binding_happy_path() {
    let Some(detail) = read_app("pages/request_detail.rs") else {
        return;
    };
    for needle in [
        "gauge-request-detail",
        "decide_permission_request",
        "get_permission_request",
        "approve",
    ] {
        assert!(
            detail.contains(needle),
            "RequestDetailPage missing `{needle}`"
        );
    }
}

#[test]
fn request_detail_missing_decide_sad_path() {
    let Some(detail) = read_app("pages/request_detail.rs") else {
        return;
    };
    assert!(
        detail.contains("decide_permission_request"),
        "request detail must bind decide_permission_request for reviewer approve/deny"
    );
    assert!(
        !detail.contains("unimplemented!"),
        "request detail must not ship unimplemented placeholders"
    );
}

#[test]
fn permission_manifest_gauge_admin_happy_path() {
    let Some(perms) = read_app("permissions.rs") else {
        return;
    };
    for needle in [
        "domain_key = \"gauge\"",
        "GaugeAdmin",
        "UfPermissionManifest",
    ] {
        assert!(
            perms.contains(needle),
            "GaugePermission manifest missing `{needle}`"
        );
    }
}

#[test]
fn embedded_gauge_host_matches_uf_app_happy_path() {
    let host =
        fs::read_to_string(workspace_root().join("examples/embedded-gauge-host/src/main.rs"))
            .expect("embedded-gauge-host main.rs");
    for needle in [
        "\"app_id\": \"permission\"",
        "\"route_path\": \"/permission\"",
        "\"admin_permission\": \"GaugeAdmin\"",
        "actor_can",
        "SUPER_USER_GROUP_ID",
    ] {
        assert!(
            host.contains(needle),
            "embedded-gauge-host missing contract `{needle}`"
        );
    }
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    assert!(
        lib.contains("id: \"permission\"") && lib.contains("route_path: \"/permission\""),
        "host inventory must stay aligned with uf_app!"
    );
    let Some(perms) = read_app("permissions.rs") else {
        return;
    };
    assert!(
        perms.contains("GaugeAdmin"),
        "host admin_permission must stay aligned with GaugePermission"
    );
}

#[test]
fn lazy_routes_wire_pages_happy_path() {
    let Some(lazy) = read_app("lazy_routes.rs") else {
        return;
    };
    for needle in [
        "PermissionsIndexPage",
        "PermissionDetailPage",
        "PermissionCreatePage",
        "DomainCreatePage",
        "GroupsIndexPage",
        "GroupDetailPage",
        "GroupCreatePage",
        "RequestsIndexPage",
        "RequestDetailPage",
    ] {
        assert!(
            lazy.contains(needle),
            "lazy_routes missing page wire `{needle}`"
        );
    }
}
