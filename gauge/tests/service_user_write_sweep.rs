//! No Gauge write succeeds for a service user, an infrastructure service user, or an
//! anonymous caller (B3 K11).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/service_users.rs"]
mod service_users_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use gauge::generated::{Permission, PermissionGroup};
use gauge::gluon_operator_groups::ensure_gluon_default_operator_groups;
use gauge::manifest_sync::{
    sync_permission_manifests, PermissionDomainInput, PermissionInput, PermissionManifestInput,
};
use gauge::resource_permissions::{
    delete_resource_permission_bundle, ensure_resource_permission_bundle,
    seed_resource_kind_catalog, ActorId, ResourceKind, ResourcePermissionSpec,
};
use gauge::service as svc;
use gauge::service_users::seed_service_user_permissions;
use gauge::super_user::{ensure_super_user_group, SUPER_USER_GROUP_ID};
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
    PermissionRequestCreateInput, PermissionRequestDecision, PermissionRequestDecisionInput,
    PermissionRequestTargetKind,
};
use service_users_fixtures::{create_service_user, raw_count, world, World, READ, READERS};
use valence::{Actor, Model, StringPredicate, Valence};

const TABLES: [&str; 8] = [
    "permission",
    "permission_group",
    "permission_domain",
    "permission_user_principal",
    "permission_group_principal",
    "permission_service_user_principal",
    "permission_request",
    "permission_history",
];

/// Everything a forbidden write could have changed.
async fn fingerprint(w: &World, read_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    for table in TABLES {
        out.push(format!("{table}={}", raw_count(&w.system, table).await));
    }
    let perm = Permission::get(read_id, &w.system, valence::use_!(r"**Test:** Fixture **permission** load in the gauge write sweep to compare its holders before and after. CI and developers running the suite only."))
        .await
        .unwrap()
        .unwrap();
    let mut holders: Vec<String> = perm
        .get_allowed_principals_record_ids(&w.system, valence::use_!(r"**Test:** Fixture edge read in the gauge write sweep to compare permission holders before and after. CI and developers running the suite only."))
        .await
        .unwrap()
        .iter()
        .map(|r| format!("{}:{}", r.table(), r.id()))
        .collect();
    holders.sort();
    out.push(format!("holders={holders:?}"));
    for group_id in [READERS, SUPER_USER_GROUP_ID, "service_user_creators"] {
        let group = PermissionGroup::get(group_id, &w.system, valence::use_!(r"**Test:** Fixture **permission group** load in the gauge write sweep to compare its members before and after. CI and developers running the suite only."))
            .await
            .unwrap()
            .unwrap();
        let mut members: Vec<String> = group
            .get_members_record_ids(&w.system, valence::use_!(r"**Test:** Fixture edge read in the gauge write sweep to compare group members before and after. CI and developers running the suite only."))
            .await
            .unwrap()
            .iter()
            .chain(
                group
                    .get_owners_record_ids(&w.system, valence::use_!(r"**Test:** Fixture edge read in the gauge write sweep to compare group owners before and after. CI and developers running the suite only."))
                    .await
                    .unwrap()
                    .iter(),
            )
            .map(|r| format!("{}:{}", r.table(), r.id()))
            .collect();
        members.sort();
        out.push(format!("{group_id}={members:?}"));
    }
    out
}

fn manifest() -> PermissionManifestInput {
    PermissionManifestInput {
        app_id: "sweep".into(),
        domains: vec![PermissionDomainInput {
            key: "sweep".into(),
            name: "Sweep".into(),
            description: "Must never be created".into(),
            permissions: vec![PermissionInput {
                name: "sweep.escalate".into(),
                description: "Must never be created".into(),
            }],
        }],
    }
}

/// Call every public Gauge write as `v`; return the names of calls that succeeded.
async fn every_write(
    v: &Valence,
    read_id: &str,
    bundle_resource: &str,
    service_user: &lepton_identity::service_users::ServiceUserId,
) -> Vec<&'static str> {
    let mut ok = service_writes(v, service_user).await;
    ok.extend(permission_writes(v, read_id).await);
    ok.extend(boot_helper_writes(v, bundle_resource).await);
    ok
}

/// Group membership and ownership writes; returns the names of calls that succeeded.
async fn service_writes(
    v: &Valence,
    service_user: &lepton_identity::service_users::ServiceUserId,
) -> Vec<&'static str> {
    let mut ok = Vec::new();
    macro_rules! attempt {
        ($name:literal, $call:expr) => {
            if $call.await.is_ok() {
                ok.push($name);
            }
        };
    }
    attempt!(
        "create_group",
        svc::create_group(
            PermissionGroupCreateInput {
                name: "Escalators".into(),
                description: String::new()
            },
            v
        )
    );
    attempt!(
        "update_group",
        svc::update_group(READERS, "Renamed".into(), String::new(), v)
    );
    attempt!("delete_group", svc::delete_group(READERS, v));
    attempt!(
        "add_group_owner_user",
        svc::add_group_owner_user(READERS, "bob", v)
    );
    attempt!(
        "remove_group_owner_user",
        svc::remove_group_owner_user(READERS, "bob", v)
    );
    attempt!(
        "add_group_member_user",
        svc::add_group_member_user(READERS, "bob", v)
    );
    attempt!(
        "add_group_member_user_su",
        svc::add_group_member_user(SUPER_USER_GROUP_ID, "bob", v)
    );
    attempt!(
        "remove_group_member_user",
        svc::remove_group_member_user("service_user_creators", "alice", v)
    );
    attempt!(
        "add_group_member_group",
        svc::add_group_member_group(READERS, "service_user_creators", v)
    );
    attempt!(
        "remove_group_member_group",
        svc::remove_group_member_group(READERS, "service_user_creators", v)
    );
    attempt!(
        "add_group_member_service_user",
        svc::add_group_member_service_user(READERS, service_user, v)
    );
    attempt!(
        "remove_group_member_service_user",
        svc::remove_group_member_service_user(READERS, service_user, v)
    );
    ok
}

/// Domain, permission and request writes; returns the names of calls that succeeded.
async fn permission_writes(v: &Valence, read_id: &str) -> Vec<&'static str> {
    let mut ok = Vec::new();
    macro_rules! attempt {
        ($name:literal, $call:expr) => {
            if $call.await.is_ok() {
                ok.push($name);
            }
        };
    }
    attempt!(
        "create_domain",
        svc::create_domain(
            PermissionDomainCreateInput {
                name: "Escalation".into(),
                description: String::new()
            },
            v
        )
    );
    attempt!(
        "create_permission",
        svc::create_permission(
            PermissionCreateInput {
                name: "escalate".into(),
                description: String::new(),
                owners_group_id: READERS.into(),
                domain_id: "test_records".into()
            },
            v
        )
    );
    attempt!(
        "update_permission",
        svc::update_permission(
            read_id,
            "renamed".into(),
            String::new(),
            READERS.into(),
            "test_records".into(),
            v
        )
    );
    attempt!("delete_permission", svc::delete_permission(read_id, v));
    attempt!(
        "grant_permission_to_user",
        svc::grant_permission_to_user(read_id, "bob", v)
    );
    attempt!(
        "revoke_permission_from_group",
        svc::revoke_permission_from_group(read_id, READERS, v)
    );
    attempt!(
        "grant_permission_to_group",
        svc::grant_permission_to_group(read_id, "service_user_creators", v)
    );
    attempt!(
        "create_permission_request",
        svc::create_permission_request(
            PermissionRequestCreateInput {
                target_kind: PermissionRequestTargetKind::Group,
                target_id: READERS.into(),
                reason: "please".into()
            },
            v
        )
    );
    attempt!(
        "decide_permission_request",
        svc::decide_permission_request(
            PermissionRequestDecisionInput {
                request_id: "any".into(),
                decision: PermissionRequestDecision::Approve
            },
            v
        )
    );
    ok
}

/// Boot and host-wiring helpers that write as System internally.
async fn boot_helper_writes(v: &Valence, bundle_resource: &str) -> Vec<&'static str> {
    let mut ok = Vec::new();
    macro_rules! attempt {
        ($name:literal, $call:expr) => {
            if $call.await.is_ok() {
                ok.push($name);
            }
        };
    }
    attempt!(
        "sync_permission_manifests",
        sync_permission_manifests(v, &[manifest()])
    );
    attempt!(
        "seed_resource_kind_catalog",
        seed_resource_kind_catalog(
            v,
            ResourceKind::GluonApp,
            "sweep_catalog",
            "Sweep",
            "sweep_create"
        )
    );
    attempt!(
        "ensure_resource_permission_bundle",
        ensure_resource_permission_bundle(
            v,
            ResourcePermissionSpec {
                kind: ResourceKind::GluonApp,
                resource_id: "sweep-app".into(),
                display_name: "Sweep".into(),
                actions: vec![],
                actor: ActorId::User("bob".into())
            }
        )
    );
    attempt!(
        "delete_resource_permission_bundle",
        delete_resource_permission_bundle(v, ResourceKind::GluonApp, bundle_resource)
    );
    attempt!(
        "ensure_gluon_default_operator_groups",
        ensure_gluon_default_operator_groups(v)
    );
    attempt!("ensure_super_user_group", ensure_super_user_group(v));
    attempt!(
        "seed_service_user_permissions",
        seed_service_user_permissions(v)
    );
    ok
}

#[tokio::test]
async fn tm_service_user_write_sweep_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "sweeping").await;
    let read_id = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in the gauge write sweep to find the readers permission id. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(READ.into()))
        .first()
        .await
        .unwrap()
        .unwrap()
        .id()
        .and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap();
    // A bundle that exists, so a successful delete would show.
    ensure_resource_permission_bundle(
        &w.system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "kept-app".into(),
            display_name: "Kept".into(),
            actions: vec![],
            actor: ActorId::user_for_system(&w.system, "alice").unwrap(),
        },
    )
    .await
    .expect("seed bundle");

    let callers = [
        ("service_user", w.as_service_user(&service_user)),
        (
            "infra service user",
            w.as_actor(Actor::ServiceUser {
                service_name: "spectra-ingest".into(),
            }),
        ),
        ("anonymous", w.as_actor(Actor::Anonymous)),
    ];
    for (label, v) in callers {
        let before = fingerprint(&w, &read_id).await;
        let succeeded = every_write(&v, &read_id, "kept-app", &service_user).await;
        let after = fingerprint(&w, &read_id).await;
        assert!(
            succeeded.is_empty(),
            "{label} writes succeeded: {succeeded:?}"
        );
        assert_eq!(before, after, "{label} changed Gauge state");
    }
}
