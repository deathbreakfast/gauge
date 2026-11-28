//! Leaving Gauge: user erase (principal cascade, `created_by` cleared) and self-removal
//! from groups and direct grants without owner rights.
#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use chrono::Utc;
use common::{record_pk_id, seed_super_user_group_with_member, seed_user, test_valence};
use gauge::generated::{Permission, PermissionDomain, PermissionGroup, PermissionHistory};
use gauge::service;
use gauge::types::{HistoryEntryDto, PermissionGroupCreateInput};
use valence::deletion::dag::{DeletionAction, DeletionDag};
use valence::{Actor, Model, RecordId, Valence};

const ERIN_PRINCIPAL: &str = "user:erin";

async fn system() -> Valence {
    test_valence(Actor::System {
        operation: "membership_exit_test".to_string(),
    })
    .await
}

fn user(system: &Valence, id: &str) -> Valence {
    system.with_actor(Actor::User {
        user_id: id.to_string(),
    })
}

/// Olive creates a group (owner + member) and adds Erin as a member.
async fn team(system: &Valence) -> String {
    seed_user("olive", "olive@example.test", system).await;
    seed_user("erin", "erin@example.test", system).await;
    let olive = user(system, "olive");
    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Team".to_string(),
            description: String::new(),
        },
        &olive,
    )
    .await
    .expect("olive creates group");
    let gid = record_pk_id(group.id());
    service::add_group_member_user(&gid, "erin", &olive)
        .await
        .expect("add erin as member");
    gid
}

/// A permission owned by `owners_group_id` and created by `creator` (System fixture).
async fn seed_permission(system: &Valence, owners_group_id: &str, creator: &str) -> String {
    let domain = PermissionDomain::upsert(
        "domain_exit",
        PermissionDomain::new(
            false,
            None,
            false,
            "Exit Domain".to_string(),
            None,
            Utc::now(),
            Utc::now(),
        )
        .expect("build domain"),
        system,
        valence::use_!(r"**Test:** Fixture **Permission Domain** save for `membership_exit_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert domain");
    let now = Utc::now();
    let permission = Permission::new(
        Some(RecordId::new("user", creator)),
        RecordId::new("permission_group", owners_group_id),
        domain.id().expect("domain id").clone(),
        None,
        "ExitPermission".to_string(),
        None,
        now,
        now,
    )
    .expect("build permission");
    Permission::upsert("perm_exit", permission, system, valence::use_!(r"**Test:** Fixture **Permission** save for `membership_exit_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert permission");
    "perm_exit".to_string()
}

async fn group_edges(system: &Valence, gid: &str) -> (Vec<String>, Vec<String>) {
    let group = PermissionGroup::get(gid, system, valence::use_!(r"**Test:** Load a **Permission Group** for `membership_exit_integration` so the suite can assert its edges. CI and developers running the suite only."))
        .await
        .expect("load group")
        .expect("group exists");
    let ids = |rids: Vec<RecordId>| rids.into_iter().map(|r| r.id().to_string()).collect();
    let owners = group
        .get_owners_record_ids(system, valence::use_!(r"**Test:** Read the **owner edges** of a permission group for `membership_exit_integration` so the suite can assert who owns it. CI and developers running the suite only."))
        .await
        .expect("owners");
    let members = group
        .get_members_record_ids(system, valence::use_!(r"**Test:** Read the **member edges** of a permission group for `membership_exit_integration` so the suite can assert who belongs to it. CI and developers running the suite only."))
        .await
        .expect("members");
    (ids(owners), ids(members))
}

async fn load_permission(system: &Valence, pid: &str) -> Permission {
    Permission::get(pid, system, valence::use_!(r"**Test:** Load a **Permission** for `membership_exit_integration` so the suite can assert its creator and edges. CI and developers running the suite only."))
        .await
        .expect("load permission")
        .expect("permission exists")
}

async fn granted(system: &Valence, pid: &str) -> Vec<String> {
    load_permission(system, pid)
        .await
        .get_allowed_principals_record_ids(system, valence::use_!(r"**Test:** Read the **allowed-principal edges** of a permission for `membership_exit_integration` so the suite can assert who holds it. CI and developers running the suite only."))
        .await
        .expect("allowed principals")
        .into_iter()
        .map(|r| r.id().to_string())
        .collect()
}

/// History of a subject as read by a seeded super user. Call once per test.
async fn history(system: &Valence, kind: &str, id: &str) -> Vec<HistoryEntryDto> {
    seed_user("auditor", "auditor@example.test", system).await;
    seed_super_user_group_with_member(system, "auditor").await;
    service::list_history(
        &user(system, "auditor"),
        Some(kind.to_string()),
        Some(id.to_string()),
    )
    .await
    .expect("list history")
}

/// Whether `entries` holds a row by `actor` that removed `actor` from `field`.
fn has_self_removal(entries: &[HistoryEntryDto], field: &str, actor: &str) -> bool {
    entries.iter().any(|e| {
        e.actor_user_id.as_deref() == Some(actor)
            && e.diffs.iter().any(|d| {
                d.field == field && d.old_value == serde_json::Value::String(actor.to_string())
            })
    })
}

// ---- User erase ---------------------------------------------------------------------------

#[tokio::test]
async fn erase_user_with_principal_and_edges_unblocked_happy() {
    let system = system().await;
    let gid = team(&system).await;
    let olive = user(&system, "olive");
    service::add_group_owner_user(&gid, "erin", &olive)
        .await
        .expect("add erin as co-owner");
    let pid = seed_permission(&system, &gid, "erin").await;
    service::grant_permission_to_user(&pid, "erin", &olive)
        .await
        .expect("grant erin directly");

    // `erase_account` removes the account rows first; the user's DAG comes after.
    for (table, id) in [("account_email", "email_erin"), ("account", "acct_erin")] {
        let backend = system.backend_for_table(table).expect("account backend");
        valence::delete_record(
            backend.as_ref(),
            table,
            id,
            valence::use_!(r"**Test:** Physically delete a fixture account row for `membership_exit_integration` the way account erase does before the user. CI and developers running the suite only."),
        )
        .await
        .unwrap_or_else(|e| panic!("delete {table}:{id}: {e}"));
    }

    let dag = DeletionDag::compute("user", "erin", &system)
        .await
        .expect("compute user deletion DAG");
    // Any Restrict violation empties the plan, so none may remain.
    assert!(
        dag.restrict_violations.is_empty(),
        "rows block erase: {:?}",
        dag.restrict_violations
    );

    // Apply the plan the way Lepton's erase does: physical deletes for cascaded rows (by
    // their stored id, which for a principal is `user:<id>`), plus Valence's per-node apply
    // for SetNull and edge removal.
    let nodes = format!("{:?}", dag.nodes);
    for node in &dag.nodes {
        if node.table == "user" {
            continue;
        }
        match node.action {
            DeletionAction::CascadeDelete => {
                let backend = system.backend_for_table(&node.table).expect("node backend");
                valence::delete_record(
                    backend.as_ref(),
                    &node.table,
                    &node.record_id,
                    valence::use_!(r"**Test:** Physically delete a cascaded row for `membership_exit_integration` the way account erase does. CI and developers running the suite only."),
                )
                .await
                .unwrap_or_else(|e| panic!("delete {}:{}: {e}", node.table, node.record_id));
            }
            _ => valence::apply_deletion_node(node, &system)
                .await
                .unwrap_or_else(|e| panic!("apply {node:?}: {e}")),
        }
    }

    let principal = valence::get_record(
        system
            .backend_for_table("permission_user_principal")
            .expect("principal backend")
            .as_ref(),
        "permission_user_principal",
        ERIN_PRINCIPAL,
        valence::use_!(r"**Test:** Read a **Permission User Principal** row for `membership_exit_integration` so the suite can assert erase removed it. CI and developers running the suite only."),
    )
    .await
    .expect("read principal");
    assert!(
        principal.is_none(),
        "erin's principal survives erase; DAG nodes: {nodes}"
    );

    let (owners, members) = group_edges(&system, &gid).await;
    assert!(
        !owners.iter().any(|id| id == ERIN_PRINCIPAL),
        "owner edge left: {owners:?}; DAG nodes: {nodes}"
    );
    assert!(
        !members.iter().any(|id| id == ERIN_PRINCIPAL),
        "member edge left: {members:?}; DAG nodes: {nodes}"
    );
    assert!(
        owners.iter().any(|id| id == "user:olive"),
        "co-owner kept: {owners:?}"
    );
    let holders = granted(&system, &pid).await;
    assert!(
        !holders.iter().any(|id| id == ERIN_PRINCIPAL),
        "grant left: {holders:?}; DAG nodes: {nodes}"
    );

    let permission = load_permission(&system, &pid).await;
    assert!(
        permission.created_by().is_none(),
        "created_by should be cleared, got {:?}",
        permission.created_by()
    );
}

// ---- Owner removing themselves --------------------------------------------------------------

#[tokio::test]
async fn owner_removes_self_with_coowner_left_happy() {
    let system = system().await;
    let gid = team(&system).await;
    service::add_group_owner_user(&gid, "erin", &user(&system, "olive"))
        .await
        .expect("add erin as co-owner");

    service::remove_group_owner_user(&gid, "erin", &user(&system, "erin"))
        .await
        .expect("erin gives up ownership");

    let (owners, _) = group_edges(&system, &gid).await;
    assert!(
        !owners.iter().any(|id| id == ERIN_PRINCIPAL),
        "owner edge left: {owners:?}"
    );
    let entries = history(&system, "permission_group", &gid).await;
    assert!(
        has_self_removal(&entries, "owner_users", "erin"),
        "missing owner removal row: {entries:?}"
    );
}

// ---- Member leaving / dropping a direct grant ---------------------------------------------

#[tokio::test]
async fn member_leaves_group_happy() {
    let system = system().await;
    let gid = team(&system).await;

    service::leave_group(&gid, &user(&system, "erin"))
        .await
        .expect("erin leaves");

    let (_, members) = group_edges(&system, &gid).await;
    assert!(
        !members.iter().any(|id| id == ERIN_PRINCIPAL),
        "member edge left: {members:?}"
    );
    assert!(
        members.iter().any(|id| id == "user:olive"),
        "others kept: {members:?}"
    );
    let entries = history(&system, "permission_group", &gid).await;
    assert!(
        has_self_removal(&entries, "member_users", "erin"),
        "missing member removal row: {entries:?}"
    );
}

#[tokio::test]
async fn leave_group_not_a_member_changes_nothing_sad() {
    let system = system().await;
    let gid = team(&system).await;
    seed_user("mallory", "mallory@example.test", &system).await;

    service::leave_group(&gid, &user(&system, "mallory"))
        .await
        .expect("leaving a group you aren't in is a no-op");

    let (_, members) = group_edges(&system, &gid).await;
    assert!(
        members.iter().any(|id| id == ERIN_PRINCIPAL),
        "erin kept: {members:?}"
    );
    let entries = history(&system, "permission_group", &gid).await;
    assert!(
        !has_self_removal(&entries, "member_users", "mallory"),
        "no-op wrote history: {entries:?}"
    );
}

#[tokio::test]
async fn member_cannot_leave_managed_group_sad() {
    let system = system().await;
    seed_user("olive", "olive@example.test", &system).await;
    seed_user("erin", "erin@example.test", &system).await;
    service::create_managed_group(
        "team_exit",
        "Exit Team",
        "",
        Some("olive"),
        Some("polaron"),
        None,
        &system,
    )
    .await
    .expect("create managed group");
    service::add_group_member_user("team_exit", "erin", &system)
        .await
        .expect("sync adds erin");

    let err = service::leave_group("team_exit", &user(&system, "erin"))
        .await
        .expect_err("members of a managed group leave in the managing product");
    assert!(
        matches!(
            err.downcast_ref::<service::GaugeServiceError>(),
            Some(service::GaugeServiceError::Validation { .. })
        ),
        "expected Validation, got {err:#}"
    );
    let (_, members) = group_edges(&system, "team_exit").await;
    assert!(
        members.iter().any(|id| id == ERIN_PRINCIPAL),
        "erin kept: {members:?}"
    );
}

#[tokio::test]
async fn holder_revokes_own_permission_happy() {
    let system = system().await;
    let gid = team(&system).await;
    let pid = seed_permission(&system, &gid, "olive").await;
    service::grant_permission_to_user(&pid, "erin", &user(&system, "olive"))
        .await
        .expect("grant erin directly");

    service::revoke_own_permission(&pid, &user(&system, "erin"))
        .await
        .expect("erin drops the grant");

    let holders = granted(&system, &pid).await;
    assert!(
        !holders.iter().any(|id| id == ERIN_PRINCIPAL),
        "grant left: {holders:?}"
    );
    let entries = history(&system, "permission", &pid).await;
    assert!(
        has_self_removal(&entries, "granted_users", "erin"),
        "missing revoke row: {entries:?}"
    );
}

#[tokio::test]
async fn forged_self_removal_history_refused_sad() {
    let system = system().await;
    let gid = team(&system).await;
    seed_user("mallory", "mallory@example.test", &system).await;

    let row = PermissionHistory::new(
        RecordId::new("permission_group", &gid),
        "member_users".to_string(),
        "mallory".to_string(),
        String::new(),
        Utc::now(),
        Some(RecordId::new("user", "mallory")),
    )
    .expect("build history row");
    let result = PermissionHistory::create(row, &user(&system, "mallory"), valence::use_!(r"**Test:** Attempt a **Permission History** save for `membership_exit_integration` so the suite can assert a forged leave row is refused. CI and developers running the suite only.")).await;
    assert!(result.is_err(), "non-member logged a leave row");
}
