//! Managed groups (chosen id, named owner), groups owning groups, and System on group writes.
#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{
    record_pk_id, seed_group_with_owner, seed_super_user_group_with_member, seed_user, test_valence,
};
use gauge::generated::PermissionGroup;
use gauge::service;
use gauge::super_user::{SUPER_USER_GROUP_ID, SUPER_USER_GROUP_NAME};
use gauge::types::{HistoryEntryDto, PermissionGroupCreateInput};
use valence::{Actor, Model, Valence};

async fn system() -> Valence {
    test_valence(Actor::System {
        operation: "managed_groups_test".to_string(),
    })
    .await
}

fn user(system: &Valence, id: &str) -> Valence {
    system.with_actor(Actor::User {
        user_id: id.to_string(),
    })
}

fn input(name: &str) -> PermissionGroupCreateInput {
    PermissionGroupCreateInput {
        name: name.to_string(),
        description: String::new(),
    }
}

async fn load(system: &Valence, id: &str) -> PermissionGroup {
    PermissionGroup::get(id, system, valence::use_!(r"**Test:** Load a **Permission Group** for `managed_groups_integration` so the suite can assert its edges. CI and developers running the suite only."))
        .await
        .expect("load group")
        .expect("group exists")
}

/// Principal row ids of the group's owner edges.
async fn owners(system: &Valence, id: &str) -> Vec<String> {
    load(system, id)
        .await
        .get_owners_record_ids(system, valence::use_!(r"**Test:** Read the **owner edges** of a permission group for `managed_groups_integration` so the suite can assert who owns it. CI and developers running the suite only."))
        .await
        .expect("owners")
        .into_iter()
        .map(|r| r.id().to_string())
        .collect()
}

/// Principal row ids of the group's member edges.
async fn members(system: &Valence, id: &str) -> Vec<String> {
    load(system, id)
        .await
        .get_members_record_ids(system, valence::use_!(r"**Test:** Read the **member edges** of a permission group for `managed_groups_integration` so the suite can assert who belongs to it. CI and developers running the suite only."))
        .await
        .expect("members")
        .into_iter()
        .map(|r| r.id().to_string())
        .collect()
}

/// Group history as read by a seeded super user (`list_history` needs a signed-in user).
/// Call once per test: it seeds the Super User group.
async fn history(system: &Valence, id: &str) -> Vec<HistoryEntryDto> {
    seed_user("auditor", "auditor@example.test", system).await;
    seed_super_user_group_with_member(system, "auditor").await;
    service::list_history(
        &user(system, "auditor"),
        Some("permission_group".to_string()),
        Some(id.to_string()),
    )
    .await
    .expect("list history")
}

async fn history_actors(system: &Valence, id: &str) -> Vec<Option<String>> {
    history(system, id)
        .await
        .into_iter()
        .map(|e| e.actor_user_id)
        .collect()
}

fn assert_not_authorized(err: &anyhow::Error) {
    assert!(
        matches!(
            err.downcast_ref::<service::GaugeServiceError>(),
            Some(service::GaugeServiceError::NotAuthorized { .. })
        ),
        "expected NotAuthorized, got {err:#}"
    );
}

fn assert_validation(err: &anyhow::Error) {
    assert!(
        matches!(
            err.downcast_ref::<service::GaugeServiceError>(),
            Some(service::GaugeServiceError::Validation { .. })
        ),
        "expected Validation, got {err:#}"
    );
}

// ---- System on group writes -------------------------------------------------------------

#[tokio::test]
async fn system_creates_group_without_owner_happy() {
    let system = system().await;
    let group = service::create_group(input("System Made"), &system)
        .await
        .expect("System creates group");
    let gid = record_pk_id(group.id());
    assert!(owners(&system, &gid).await.is_empty());
    assert!(members(&system, &gid).await.is_empty());
}

#[tokio::test]
async fn system_create_group_owner_only_refused_sad() {
    let system = system().await;
    let err = service::create_group_owner_only(input("No Owner"), &system)
        .await
        .expect_err("System has no user to own the group");
    assert_not_authorized(&err);
}

#[tokio::test]
async fn system_edits_group_and_history_records_system_happy() {
    let system = system().await;
    seed_group_with_owner(&system, "g_sys", "owner").await;
    seed_group_with_owner(&system, "g_child", "child_owner").await;
    seed_user("member", "member@example.test", &system).await;
    seed_user("second", "second@example.test", &system).await;

    service::update_group("g_sys", "Renamed".to_string(), "desc".to_string(), &system)
        .await
        .expect("System updates group");
    assert_eq!(load(&system, "g_sys").await.name(), "Renamed");

    service::add_group_member_user("g_sys", "member", &system)
        .await
        .expect("add member user");
    service::add_group_member_group("g_sys", "g_child", &system)
        .await
        .expect("add member group");
    assert_eq!(members(&system, "g_sys").await.len(), 2);
    service::remove_group_member_user("g_sys", "member", &system)
        .await
        .expect("remove member user");
    service::remove_group_member_group("g_sys", "g_child", &system)
        .await
        .expect("remove member group");
    assert!(members(&system, "g_sys").await.is_empty());

    service::add_group_owner_user("g_sys", "second", &system)
        .await
        .expect("add owner user");
    assert_eq!(owners(&system, "g_sys").await.len(), 2);
    service::remove_group_owner_user("g_sys", "second", &system)
        .await
        .expect("remove owner user");
    assert_eq!(
        owners(&system, "g_sys").await,
        vec!["user:owner".to_string()]
    );

    service::add_group_member_user("g_sys", "member", &system)
        .await
        .expect("re-add member");
    let removed = service::clear_group_members("g_sys", &system)
        .await
        .expect("System clears members");
    assert_eq!(removed, 1);

    let actors = history_actors(&system, "g_sys").await;
    let edge_actors: Vec<_> = actors.iter().flatten().collect();
    assert!(
        edge_actors.len() >= 7,
        "expected a history row per edge edit, got {actors:?}"
    );
    assert!(
        edge_actors.iter().all(|a| a.ends_with("system")),
        "history must record the actor as system, got {actors:?}"
    );
}

#[tokio::test]
async fn session_non_owner_refused_on_group_writes_sad() {
    let system = system().await;
    seed_group_with_owner(&system, "g_owned", "owner").await;
    seed_group_with_owner(&system, "g_other", "other_owner").await;
    seed_user("mallory", "mallory@example.test", &system).await;
    let mallory = user(&system, "mallory");

    assert_not_authorized(
        &service::update_group("g_owned", "x".to_string(), String::new(), &mallory)
            .await
            .expect_err("update"),
    );
    assert_not_authorized(
        &service::add_group_member_user("g_owned", "mallory", &mallory)
            .await
            .expect_err("add member"),
    );
    assert_not_authorized(
        &service::add_group_owner_user("g_owned", "mallory", &mallory)
            .await
            .expect_err("add owner"),
    );
    assert_not_authorized(
        &service::add_group_member_group("g_owned", "g_other", &mallory)
            .await
            .expect_err("add member group"),
    );
    assert_not_authorized(
        &service::clear_group_members("g_owned", &mallory)
            .await
            .expect_err("clear"),
    );
    assert_eq!(
        owners(&system, "g_owned").await,
        vec!["user:owner".to_string()]
    );
    assert!(members(&system, "g_owned").await.is_empty());
}

#[tokio::test]
async fn anonymous_still_refused_on_group_writes_sad() {
    let system = system().await;
    seed_group_with_owner(&system, "g_anon", "owner").await;
    let anon = system.with_actor(Actor::Anonymous);
    let err = service::create_group(input("Anon"), &anon)
        .await
        .expect_err("anonymous create");
    assert!(
        err.to_string().contains("Authenticated user required"),
        "got {err}"
    );
    let err = service::add_group_member_user("g_anon", "owner", &anon)
        .await
        .expect_err("anonymous add member");
    assert!(
        err.to_string().contains("Authenticated user required"),
        "got {err}"
    );
}

// ---- create_managed_group ---------------------------------------------------------------

#[tokio::test]
async fn system_creates_managed_group_with_named_owner_happy() {
    let system = system().await;
    seed_user("alice", "alice@example.test", &system).await;

    let group =
        service::create_managed_group("team_ops", "Ops", "ops team", Some("alice"), &system)
            .await
            .expect("create managed group");
    assert_eq!(record_pk_id(group.id()), "team_ops");
    assert_eq!(group.name(), "Ops");
    assert_eq!(
        owners(&system, "team_ops").await,
        vec!["user:alice".to_string()]
    );
    assert!(members(&system, "team_ops").await.is_empty());

    let alice = user(&system, "alice");
    assert!(
        service::can_edit_group(&load(&system, "team_ops").await, &alice)
            .await
            .expect("can_edit_group")
    );
}

#[tokio::test]
async fn create_managed_group_twice_changes_nothing_happy() {
    let system = system().await;
    seed_user("alice", "alice@example.test", &system).await;

    service::create_managed_group("team_ops", "Ops", "", Some("alice"), &system)
        .await
        .expect("first create");
    let again =
        service::create_managed_group("team_ops", "Other", "changed", Some("alice"), &system)
            .await
            .expect("second create returns existing");
    assert_eq!(record_pk_id(again.id()), "team_ops");
    assert_eq!(again.name(), "Ops");
    assert_eq!(load(&system, "team_ops").await.name(), "Ops");
    assert_eq!(
        owners(&system, "team_ops").await,
        vec!["user:alice".to_string()]
    );
    assert!(members(&system, "team_ops").await.is_empty());
}

#[tokio::test]
async fn managed_group_id_taken_by_another_owner_is_refused_sad() {
    let system = system().await;
    seed_user("alice", "alice@example.test", &system).await;
    seed_user("mallory", "mallory@example.test", &system).await;
    let mallory = user(&system, "mallory");

    // A session user claims the id before the job runs.
    service::create_managed_group("team_ops", "Squat", "", None, &mallory)
        .await
        .expect("mallory creates team_ops");

    assert_validation(
        &service::create_managed_group("team_ops", "Ops", "", Some("alice"), &system)
            .await
            .expect_err("job must not adopt a group alice doesn't own"),
    );
    assert_eq!(
        owners(&system, "team_ops").await,
        vec!["user:mallory".to_string()]
    );
    assert_eq!(load(&system, "team_ops").await.name(), "Squat");
}

#[tokio::test]
async fn session_user_owns_managed_group_by_default_happy() {
    let system = system().await;
    seed_user("alice", "alice@example.test", &system).await;
    let alice = user(&system, "alice");

    service::create_managed_group("alice_team", "Alice team", "", None, &alice)
        .await
        .expect("session create");
    assert_eq!(
        owners(&system, "alice_team").await,
        vec!["user:alice".to_string()]
    );
    assert!(members(&system, "alice_team").await.is_empty());
}

#[tokio::test]
async fn create_managed_group_rejects_reserved_and_taken_names_sad() {
    let system = system().await;
    seed_user("alice", "alice@example.test", &system).await;

    assert_validation(
        &service::create_managed_group(SUPER_USER_GROUP_ID, "Fine", "", Some("alice"), &system)
            .await
            .expect_err("reserved id"),
    );
    assert_validation(
        &service::create_managed_group(
            "fine_id",
            SUPER_USER_GROUP_NAME,
            "",
            Some("alice"),
            &system,
        )
        .await
        .expect_err("reserved name"),
    );

    service::create_managed_group("first", "Taken", "", Some("alice"), &system)
        .await
        .expect("first");
    assert_validation(
        &service::create_managed_group("second", "Taken", "", Some("alice"), &system)
            .await
            .expect_err("name used by a different id"),
    );
    assert!(
        PermissionGroup::get("second", &system, valence::use_!(r"**Test:** Check a refused **Permission Group** was not saved for `managed_groups_integration`. CI and developers running the suite only."))
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn system_managed_group_requires_owner_sad() {
    let system = system().await;
    assert_validation(
        &service::create_managed_group("no_owner", "No owner", "", None, &system)
            .await
            .expect_err("System must name an owner"),
    );
}

#[tokio::test]
async fn session_user_cannot_name_another_owner_sad() {
    let system = system().await;
    seed_user("alice", "alice@example.test", &system).await;
    seed_user("bob", "bob@example.test", &system).await;
    let alice = user(&system, "alice");

    assert_not_authorized(
        &service::create_managed_group("bob_team", "Bob team", "", Some("bob"), &alice)
            .await
            .expect_err("alice names bob"),
    );
    assert!(
        PermissionGroup::get("bob_team", &system, valence::use_!(r"**Test:** Check a refused **Permission Group** was not saved for `managed_groups_integration`. CI and developers running the suite only."))
            .await
            .expect("get")
            .is_none()
    );
}

// ---- add/remove_group_owner_group -------------------------------------------------------

#[tokio::test]
async fn owner_group_grants_edit_to_its_owners_happy() {
    let system = system().await;
    seed_group_with_owner(&system, "g_target", "owner").await;
    seed_group_with_owner(&system, "g_admins", "admin").await;
    let owner = user(&system, "owner");
    let admin = user(&system, "admin");

    assert!(
        !service::can_edit_group(&load(&system, "g_target").await, &admin)
            .await
            .expect("can_edit before")
    );

    service::add_group_owner_group("g_target", "g_admins", &owner)
        .await
        .expect("owner adds owner group");
    service::add_group_owner_group("g_target", "g_admins", &owner)
        .await
        .expect("second add is a no-op");

    assert_eq!(owners(&system, "g_target").await.len(), 2);
    assert!(
        service::can_edit_group(&load(&system, "g_target").await, &admin)
            .await
            .expect("can_edit after")
    );

    let history = history(&system, "g_target").await;
    let adds = history
        .iter()
        .flat_map(|e| &e.diffs)
        .filter(|d| d.field == "owner_groups" && d.new_value == serde_json::json!("g_admins"))
        .count();
    assert_eq!(adds, 1, "one history row for the add, got {history:?}");
}

#[tokio::test]
async fn system_adds_and_removes_owner_group_happy() {
    let system = system().await;
    seed_group_with_owner(&system, "g_target", "owner").await;
    seed_group_with_owner(&system, "g_admins", "admin").await;

    service::add_group_owner_group("g_target", "g_admins", &system)
        .await
        .expect("System adds owner group");
    assert_eq!(owners(&system, "g_target").await.len(), 2);
    service::remove_group_owner_group("g_target", "g_admins", &system)
        .await
        .expect("System removes owner group");
    assert_eq!(
        owners(&system, "g_target").await,
        vec!["user:owner".to_string()]
    );

    let history = history(&system, "g_target").await;
    assert!(
        history
            .iter()
            .flat_map(|e| &e.diffs)
            .any(|d| d.field == "owner_groups" && d.old_value == serde_json::json!("g_admins")),
        "remove recorded, got {history:?}"
    );
}

#[tokio::test]
async fn non_owner_cannot_change_owner_groups_sad() {
    let system = system().await;
    seed_group_with_owner(&system, "g_target", "owner").await;
    seed_group_with_owner(&system, "g_mine", "mallory").await;
    let mallory = user(&system, "mallory");

    assert_not_authorized(
        &service::add_group_owner_group("g_target", "g_mine", &mallory)
            .await
            .expect_err("non-owner add"),
    );
    service::add_group_owner_group("g_target", "g_mine", &system)
        .await
        .expect("seed owner group");
    let outsider = {
        seed_user("outsider", "outsider@example.test", &system).await;
        user(&system, "outsider")
    };
    assert_not_authorized(
        &service::remove_group_owner_group("g_target", "g_mine", &outsider)
            .await
            .expect_err("non-owner remove"),
    );
    assert_eq!(owners(&system, "g_target").await.len(), 2);
}

#[tokio::test]
async fn owner_group_self_and_last_owner_refused_sad() {
    let system = system().await;
    seed_group_with_owner(&system, "g_admins", "admin").await;
    let created = service::create_group(input("Group-owned"), &system)
        .await
        .expect("ownerless group");
    let gid = record_pk_id(created.id());

    assert_validation(
        &service::add_group_owner_group("g_admins", "g_admins", &system)
            .await
            .expect_err("self ownership"),
    );

    service::add_group_owner_group(&gid, "g_admins", &system)
        .await
        .expect("only owner is a group");
    assert_validation(
        &service::remove_group_owner_group(&gid, "g_admins", &system)
            .await
            .expect_err("last owner"),
    );
    assert_eq!(owners(&system, &gid).await.len(), 1);
}
