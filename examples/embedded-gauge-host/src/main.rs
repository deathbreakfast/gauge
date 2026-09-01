//! Embedded gauge host: bootstrap Super User owner, then deny → grant → allow
//! via `actor_can` under a session-gated teaching route.
//!
//! Uses System-actor generated-model bootstrap (avoids User privacy readback of
//! `password_hash` when calling `service::create_*` as a User actor).
//!
//! Copy surfaces for product hosts: this package's `Cargo.toml` + `main.rs`,
//! plus the product-mount dependency / Leptos sketches in the host README.
//! Oneshot path `/permissions` is a protected API stand-in; Orbital app id/path
//! stay `permission` / `/permission` (see JSON `inventory`).
//!
//! ## When to use
//! Smoke permission bootstrap + evaluation without mounting `PermissionRoutes`.
//!
//! ## Command
//! ```bash
//! export CARGO_BUILD_JOBS=1
//! export CARGO_TARGET_DIR=target-gauge
//! cargo run -p embedded-gauge-host
//! ```
//!
//! ## Success
//! Stdout prints `embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow`.
//!
//! ## Look next
//! Mount `<PermissionRoutes />` from `gauge-app`; sync manifests in host bootstrap.

#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use gauge::generated::{Permission, PermissionDomain, PermissionGroup, PermissionUserPrincipal};
use gauge::service;
use gauge::super_user::{SUPER_USER_GROUP_ID, SUPER_USER_GROUP_NAME};
use http_body_util::BodyExt;
use tower::ServiceExt;
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    InMemoryBackend, Model, RecordId, RegisterBackendLogicalNamesOptions, Valence, MEM_ENGINE_ID,
    SQLITE_ENGINE_ID,
};

#[derive(Clone)]
struct DemoSession {
    user_id: String,
}

#[derive(Clone)]
struct HostState {
    member: Arc<Valence>,
    permission_name: String,
}

async fn require_session(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if req.extensions().get::<DemoSession>().is_some() {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn inject_demo_session(mut req: Request<Body>, next: Next) -> Response {
    if let Some(user) = req
        .headers()
        .get("x-demo-user")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
    {
        req.extensions_mut().insert(DemoSession { user_id: user });
    }
    next.run(req).await
}

fn prepare_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    unsafe {
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

fn mem_router() -> Arc<DatabaseRouter> {
    prepare_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        Arc::clone(&backend),
        gauge::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions {
            register_alias_engine_id: Some(SQLITE_ENGINE_ID),
        },
    );
    router.register(
        router_key(gauge::embedded_surreal::LOGICAL_NAME, SQLITE_ENGINE_ID),
        backend,
    );
    Arc::new(router)
}

fn valence_for(router: Arc<DatabaseRouter>, actor: Actor) -> Valence {
    Valence::builder()
        .database_router(router)
        .default_backend_key(router_key(
            gauge::embedded_surreal::LOGICAL_NAME,
            MEM_ENGINE_ID,
        ))
        .with_actor(actor)
        .build()
        .expect("valence build")
}

async fn seed_user(id: &str, email: &str, valence: &Valence) {
    let _ = email; // email lives on AccountEmail upstream; label kept for call-site readability
    let now = Utc::now();
    let user = lepton::generated::User::new(
        Some(lepton::generated::UserUserType::Person),
        Some("test-password-hash".to_string()),
        Some(lepton::generated::UserStatus::Active),
        None,
        None,
        Some(now),
        None,
        None,
        now,
        now,
    )
    .expect("build user");
    lepton::generated::User::upsert(id, user, valence)
        .await
        .expect("upsert user");
}

async fn seed_super_user_owner(
    system: &Valence,
    now: chrono::DateTime<Utc>,
) -> PermissionUserPrincipal {
    let super_group = PermissionGroup::upsert(
        SUPER_USER_GROUP_ID,
        PermissionGroup::new(
            SUPER_USER_GROUP_NAME.to_string(),
            Some("Hard-coded singleton super-user group".into()),
            now,
            now,
        )
        .expect("build super user group"),
        system,
    )
    .await
    .expect("bootstrap super user group");
    let owner_principal = PermissionUserPrincipal::upsert(
        "user:owner-1",
        PermissionUserPrincipal::new(RecordId::new("user", "owner-1"), "owner-1".into())
            .expect("owner principal"),
        system,
    )
    .await
    .expect("upsert owner principal");
    super_group
        .relate_to_owner_record(owner_principal.id().expect("id"), system)
        .await
        .expect("relate super owner");
    super_group
        .relate_to_member_record(owner_principal.id().expect("id"), system)
        .await
        .expect("relate super member");
    owner_principal
}

async fn seed_demo_permission(
    system: &Valence,
    owner_principal: &PermissionUserPrincipal,
    now: chrono::DateTime<Utc>,
) -> (String, Permission) {
    let owners = PermissionGroup::upsert(
        "deployers",
        PermissionGroup::new("Deployers".into(), Some("demo owners".into()), now, now)
            .expect("owners group"),
        system,
    )
    .await
    .expect("upsert owners");
    owners
        .relate_to_owner_record(owner_principal.id().expect("id"), system)
        .await
        .expect("owners owner");

    let domain = PermissionDomain::upsert(
        "demo-domain",
        PermissionDomain::new(
            false,
            None,
            "Demo".into(),
            Some("embedded host demo".into()),
            now,
            now,
        )
        .expect("domain"),
        system,
    )
    .await
    .expect("upsert domain");

    let permission_name = "CanDeploy".to_string();
    let permission = Permission::upsert(
        "can-deploy",
        Permission::new(
            RecordId::new("user", "owner-1"),
            RecordId::new("permission_group", "deployers"),
            domain.id().expect("domain id").clone(),
            permission_name.clone(),
            Some("Allow deployments".into()),
            now,
            now,
        )
        .expect("permission"),
        system,
    )
    .await
    .expect("upsert permission");
    (permission_name, permission)
}

async fn bootstrap_host() -> HostState {
    let router = mem_router();
    let system = valence_for(
        router.clone(),
        Actor::System {
            operation: "embedded-gauge-host".into(),
        },
    );

    seed_user("owner-1", "owner@example.com", &system).await;
    seed_user("member-1", "member@example.com", &system).await;

    let now = Utc::now();
    let owner_principal = seed_super_user_owner(&system, now).await;
    let (permission_name, permission) = seed_demo_permission(&system, &owner_principal, now).await;

    let member = Arc::new(system.with_actor(Actor::User {
        user_id: "member-1".into(),
    }));

    let denied = service::actor_can(member.as_ref(), &permission_name)
        .await
        .expect("actor_can before grant");
    assert!(!denied, "member must be denied before grant");

    let member_principal = PermissionUserPrincipal::upsert(
        "user:member-1",
        PermissionUserPrincipal::new(RecordId::new("user", "member-1"), "member-1".into())
            .expect("member principal"),
        &system,
    )
    .await
    .expect("upsert member principal");
    permission
        .relate_to_allowed_principal_record(member_principal.id().expect("id"), &system)
        .await
        .expect("grant member");

    let allowed = service::actor_can(member.as_ref(), &permission_name)
        .await
        .expect("actor_can after grant");
    assert!(allowed, "member must be allowed after grant");

    HostState {
        member,
        permission_name,
    }
}

async fn permissions_api(
    Extension(session): Extension<DemoSession>,
    Extension(state): Extension<HostState>,
) -> impl IntoResponse {
    let can = service::actor_can(state.member.as_ref(), &state.permission_name)
        .await
        .expect("actor_can");
    Json(serde_json::json!({
        "path": "/permissions",
        "user": session.user_id,
        "permission": state.permission_name,
        "member_can": can,
        "bootstrap_owner": "owner@example.com",
        "super_user_group": SUPER_USER_GROUP_ID,
        // Matches gauge-app `uf_app!` / GaugePermission (not the oneshot URI).
        "inventory": {
            "app_id": "permission",
            "route_path": "/permission",
            "admin_permission": "GaugeAdmin",
        },
    }))
}

fn app(state: HostState) -> Router {
    Router::new()
        .route("/permissions", get(permissions_api))
        .route_layer(from_fn(require_session))
        .layer(Extension(state))
        .layer(from_fn(inject_demo_session))
}

#[tokio::main]
async fn main() {
    let state = bootstrap_host().await;

    let denied = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/permissions")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot")
        .status();
    assert_eq!(denied, StatusCode::UNAUTHORIZED);

    let response = app(state)
        .oneshot(
            Request::builder()
                .uri("/permissions")
                .header("x-demo-user", "demo-ops")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["path"], "/permissions");
    assert_eq!(body["member_can"], true);
    assert_eq!(body["inventory"]["app_id"], "permission");
    assert_eq!(body["inventory"]["route_path"], "/permission");
    assert_eq!(body["inventory"]["admin_permission"], "GaugeAdmin");

    println!("embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow");
}
