//! The reads and writes behind Gauge's usability pass: display names, who has access and why, a
//! person's access, request deny and withdraw, owners managing members, the change log, and a
//! resource's activity.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(clippy::unused_async)]
mod common;
#[path = "common/service_users.rs"]
mod service_users_fixtures;

use gauge::resource_permissions::{
    ensure_resource_permission_bundle, permission_name, roles::Role, set_principal_role, ActorId,
    ResourceAction, ResourceKind, ResourcePermissionSpec,
};
use gauge::service::{
    actor_can, add_group_member_group, add_group_member_service_user, add_group_member_user,
    create_domain, create_group, create_permission, create_permission_request,
    decide_permission_request, deny_request, get_permission_detail, grant_permission_to_group,
    grant_permission_to_user, list_activity, list_effective_holders, list_group_access,
    list_resource_activity, principal_access, principal_access_self, remove_group_member_user,
    withdraw_request, GaugeServiceError,
};
use gauge::service_users::{
    __test_reach_read_count, __test_reset_reach_read_count, service_user_effective_permissions,
};
use gauge::types::{
    AccessPath, ActivityFilter, ActivityKind, PermissionCreateInput, PermissionDomainCreateInput,
    PermissionGroupCreateInput, PermissionRequestCreateInput, PermissionRequestDecision,
    PermissionRequestDecisionInput, PermissionRequestStatusDto, PermissionRequestTargetKind,
    PrincipalKey, PrincipalKind, RecordKind, RecordRef,
};
use valence::Valence;

use service_users_fixtures::{create_service_user, world, World};

async fn group(name: &str, v: &Valence) -> String {
    let g = create_group(
        PermissionGroupCreateInput {
            name: name.into(),
            description: "Fixture group".into(),
        },
        v,
    )
    .await
    .expect("create group");
    common::record_pk_id(g.id())
}

/// A permission `dave` owns through an owner group, named "Approve payroll runs".
async fn payroll(w: &World) -> String {
    let dave = w.as_user("dave");
    let owners = group("Payroll owners", &dave).await;
    let domain = create_domain(
        PermissionDomainCreateInput {
            name: "Payroll".into(),
            description: "Fixture domain".into(),
        },
        &dave,
    )
    .await
    .expect("domain");
    let permission = create_permission(
        PermissionCreateInput {
            display_name: "Approve payroll runs".into(),
            name: String::new(),
            description: "Lets you **approve** a run.".into(),
            owners_group_id: owners,
            domain_id: common::record_pk_id(domain.id()),
        },
        &dave,
    )
    .await
    .expect("permission");
    common::record_pk_id(permission.id())
}

fn assert_err<T: std::fmt::Debug>(result: anyhow::Result<T>, want: &str) {
    let err = result.expect_err("refused");
    let got = match err.downcast_ref::<GaugeServiceError>() {
        Some(GaugeServiceError::NotAuthorized { .. }) => "NotAuthorized",
        Some(GaugeServiceError::Validation { .. }) => "Validation",
        Some(GaugeServiceError::NotFound { .. }) => "NotFound",
        _ => "other",
    };
    assert_eq!(got, want, "{err:#}");
}

#[tokio::test]
async fn display_name_makes_key_and_owner_group_happy() {
    let w = world().await;
    let dave = w.as_user("dave");
    let domain = create_domain(
        PermissionDomainCreateInput {
            name: "Payroll".into(),
            description: String::new(),
        },
        &dave,
    )
    .await
    .unwrap();
    let permission = create_permission(
        PermissionCreateInput {
            display_name: "Approve payroll runs".into(),
            name: String::new(),
            description: String::new(),
            owners_group_id: String::new(),
            domain_id: common::record_pk_id(domain.id()),
        },
        &dave,
    )
    .await
    .unwrap();
    assert_eq!(permission.name(), "ApprovePayrollRuns");
    let detail = get_permission_detail(&common::record_pk_id(permission.id()), &dave)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.display_name, "Approve payroll runs");
    let owners = gauge::service::get_group_detail(&detail.owners_group_id, &dave)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owners.name, "Owners of Approve payroll runs");
}

#[tokio::test]
async fn effective_holders_list_direct_nested_and_super_user_paths_happy() {
    let w = world().await;
    let permission_id = payroll(&w).await;
    let dave = w.as_user("dave");
    let outer = group("Finance", &dave).await;
    let inner = group("Payroll clerks", &dave).await;
    add_group_member_group(&outer, &inner, &dave).await.unwrap();
    add_group_member_user(&inner, "alice", &dave).await.unwrap();
    grant_permission_to_group(&permission_id, &outer, &dave)
        .await
        .unwrap();
    grant_permission_to_user(&permission_id, "bob", &dave)
        .await
        .unwrap();

    let holders = list_effective_holders(&permission_id, &dave).await.unwrap();
    let paths = |id: &str| {
        holders
            .iter()
            .find(|h| h.principal.id == id)
            .unwrap_or_else(|| panic!("{id} missing from {holders:?}"))
            .paths
            .clone()
    };
    assert_eq!(paths("bob"), vec![AccessPath::Direct]);
    assert!(holders
        .iter()
        .find(|h| h.principal.id == "bob")
        .unwrap()
        .since
        .is_some());
    let AccessPath::ThroughGroup(chain) = &paths("alice")[0] else {
        panic!("alice should hold through groups");
    };
    let names: Vec<_> = chain.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["Finance", "Payroll clerks"], "outermost first");
    assert!(paths("carol").contains(&AccessPath::SuperUser));
}

#[tokio::test]
async fn effective_holders_refuse_non_owner_sad() {
    let w = world().await;
    let permission_id = payroll(&w).await;
    assert_err(
        list_effective_holders(&permission_id, &w.as_user("bob")).await,
        "NotAuthorized",
    );
    // A Super User passes as a Gauge admin.
    list_effective_holders(&permission_id, &w.as_user("carol"))
        .await
        .expect("super user reads");
}

#[tokio::test]
async fn group_access_lists_inherited_permissions_happy() {
    let w = world().await;
    let permission_id = payroll(&w).await;
    let dave = w.as_user("dave");
    let outer = group("Finance", &dave).await;
    let inner = group("Payroll clerks", &dave).await;
    add_group_member_group(&outer, &inner, &dave).await.unwrap();
    grant_permission_to_group(&permission_id, &outer, &dave)
        .await
        .unwrap();
    let access = list_group_access(&inner, &dave).await.unwrap();
    assert_eq!(access.len(), 1);
    assert_eq!(access[0].display_name, "Approve payroll runs");
    assert_eq!(access[0].key, "ApprovePayrollRuns");
    assert_err(
        list_group_access(&inner, &w.as_user("bob")).await,
        "NotAuthorized",
    );
}

#[tokio::test]
async fn principal_access_for_a_person_in_two_groups_happy() {
    let w = world().await;
    let permission_id = payroll(&w).await;
    let dave = w.as_user("dave");
    let finance = group("Finance", &dave).await;
    let clerks = group("Payroll clerks", &dave).await;
    add_group_member_user(&finance, "bob", &dave).await.unwrap();
    add_group_member_user(&clerks, "bob", &dave).await.unwrap();
    grant_permission_to_group(&permission_id, &finance, &dave)
        .await
        .unwrap();
    grant_permission_to_group(&permission_id, &clerks, &dave)
        .await
        .unwrap();

    let access = principal_access_self(&w.as_user("bob")).await.unwrap();
    let groups: Vec<_> = access
        .groups
        .iter()
        .map(|g| g.group.name.as_str())
        .collect();
    assert_eq!(groups, vec!["Finance", "Payroll clerks"]);
    assert!(access.groups.iter().all(|g| g.added_at.is_some()));
    assert_eq!(access.groups[0].added_by_label.as_deref(), Some("dave"));
    assert_eq!(access.permissions.len(), 1);
    assert_eq!(access.permissions[0].0.display_name, "Approve payroll runs");
    assert_eq!(access.permissions[0].1.len(), 2, "one path per group");

    // dave owns the groups he created.
    let dave_access = principal_access_self(&dave).await.unwrap();
    assert!(dave_access.owns.iter().any(|r| r.label == "Finance"));
    assert!(dave_access
        .owns
        .iter()
        .any(|r| r.label == "Approve payroll runs"));
}

#[tokio::test]
async fn principal_access_of_someone_else_needs_gauge_admin_sad() {
    let w = world().await;
    let alice = PrincipalKey {
        kind: PrincipalKind::User,
        id: "alice".into(),
    };
    assert_err(
        principal_access(&alice, &w.as_user("bob")).await,
        "NotAuthorized",
    );
    principal_access(&alice, &w.as_user("carol"))
        .await
        .expect("super user reads anyone");
}

async fn pending_request(w: &World, permission_id: &str) -> String {
    create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: permission_id.to_string(),
            reason: "Covering for Ravi".into(),
            on_behalf_of: None,
        },
        &w.as_user("alice"),
    )
    .await
    .expect("request")
    .id
}

#[tokio::test]
async fn deny_needs_a_reason_and_keeps_it_happy() {
    let w = world().await;
    let permission_id = payroll(&w).await;
    let request_id = pending_request(&w, &permission_id).await;
    let dave = w.as_user("dave");
    assert_err(deny_request(&request_id, "  ", &dave).await, "Validation");
    assert_err(
        decide_permission_request(
            PermissionRequestDecisionInput {
                request_id: request_id.clone(),
                decision: PermissionRequestDecision::Deny,
            },
            &dave,
        )
        .await,
        "Validation",
    );
    let row = deny_request(&request_id, "Ask your manager first", &dave)
        .await
        .unwrap();
    assert_eq!(row.status, PermissionRequestStatusDto::Denied);
    assert_eq!(row.deny_reason.as_deref(), Some("Ask your manager first"));
    assert_eq!(row.decided_by.as_deref(), Some("dave"));
    assert!(row.decided_at.is_some());
    assert_eq!(row.target_label, "Approve payroll runs");
    assert_eq!(row.requester_label, "alice");
}

#[tokio::test]
async fn withdraw_by_someone_else_is_refused_sad() {
    let w = world().await;
    let permission_id = payroll(&w).await;
    let request_id = pending_request(&w, &permission_id).await;
    assert_err(
        withdraw_request(&request_id, &w.as_user("bob")).await,
        "NotAuthorized",
    );
    let row = withdraw_request(&request_id, &w.as_user("alice"))
        .await
        .expect("requester withdraws");
    assert_eq!(row.status, PermissionRequestStatusDto::Withdrawn);
    assert_err(
        withdraw_request(&request_id, &w.as_user("alice")).await,
        "Validation",
    );
}

#[tokio::test]
async fn group_owner_without_gauge_admin_removes_member_happy() {
    let w = world().await;
    let dave = w.as_user("dave");
    let clerks = group("Payroll clerks", &dave).await;
    add_group_member_user(&clerks, "bob", &dave).await.unwrap();
    assert!(!actor_can(&dave, "GaugeAdmin").await.unwrap());
    assert_err(
        remove_group_member_user(&clerks, "bob", &w.as_user("alice")).await,
        "NotAuthorized",
    );
    remove_group_member_user(&clerks, "bob", &dave)
        .await
        .expect("owner removes");
    let access = principal_access_self(&w.as_user("bob")).await.unwrap();
    assert!(access.groups.is_empty());
}

#[tokio::test]
async fn activity_rows_name_people_and_records_happy() {
    let w = world().await;
    let dave = w.as_user("dave");
    let clerks = group("Payroll clerks", &dave).await;
    add_group_member_user(&clerks, "bob", &dave).await.unwrap();
    remove_group_member_user(&clerks, "bob", &dave)
        .await
        .unwrap();

    let page = list_activity(
        ActivityFilter {
            kinds: vec![ActivityKind::Membership],
            record: Some(RecordRef {
                kind: RecordKind::Group,
                id: clerks.clone(),
                label: String::new(),
            }),
            ..ActivityFilter::default()
        },
        None,
        &w.as_user("carol"),
    )
    .await
    .unwrap();
    let summaries: Vec<_> = page.items.iter().map(|r| r.summary.as_str()).collect();
    assert!(
        summaries.contains(&"Removed bob from the group"),
        "{summaries:?}"
    );
    assert!(
        summaries.contains(&"Added bob to the group"),
        "{summaries:?}"
    );
    for row in &page.items {
        assert_eq!(row.record.label, "Payroll clerks");
        assert_eq!(row.actor_label, "dave");
        assert!(!row.summary.contains(':'), "no record ids: {}", row.summary);
    }
    assert_err(
        list_activity(ActivityFilter::default(), None, &dave).await,
        "NotAuthorized",
    );
}

#[tokio::test]
async fn old_bundle_gains_audit_on_ensure_and_keeps_grants_happy() {
    let w = world().await;
    let spec = |actions: Vec<ResourceAction>| ResourcePermissionSpec {
        kind: ResourceKind::NeutrinoSecret,
        resource_id: "bank-credential".into(),
        display_name: "Bank credential".into(),
        actions,
        actor: ActorId::user_for_system(&w.system, "dave").expect("actor"),
    };
    let old_set = vec![
        ResourceAction::View,
        ResourceAction::Reveal,
        ResourceAction::Edit,
        ResourceAction::Delete,
        ResourceAction::Maintain,
    ];
    let before = ensure_resource_permission_bundle(&w.system, spec(old_set))
        .await
        .unwrap();
    assert!(before.name_for(ResourceAction::Audit).is_none());
    set_principal_role(
        &w.as_user("dave"),
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        (PrincipalKind::User, "bob"),
        Role::View,
    )
    .await
    .unwrap();

    let after = ensure_resource_permission_bundle(&w.system, spec(Vec::new()))
        .await
        .unwrap();
    let audit = permission_name(
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        ResourceAction::Audit,
    );
    assert_eq!(after.name_for(ResourceAction::Audit), Some(audit.as_str()));
    assert!(
        actor_can(&w.as_user("dave"), &audit).await.unwrap(),
        "owners hold Audit"
    );
    let view = permission_name(
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        ResourceAction::View,
    );
    assert!(
        actor_can(&w.as_user("bob"), &view).await.unwrap(),
        "grant kept"
    );
    assert!(!actor_can(&w.as_user("bob"), &audit).await.unwrap());
}

#[tokio::test]
async fn resource_activity_answers_audit_holder_and_refuses_view_only_sad() {
    let w = world().await;
    ensure_resource_permission_bundle(
        &w.system,
        ResourcePermissionSpec {
            kind: ResourceKind::NeutrinoSecret,
            resource_id: "bank-credential".into(),
            display_name: "Bank credential".into(),
            actions: Vec::new(),
            actor: ActorId::user_for_system(&w.system, "dave").expect("actor"),
        },
    )
    .await
    .unwrap();
    let dave = w.as_user("dave");
    set_principal_role(
        &dave,
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        (PrincipalKind::User, "bob"),
        Role::View,
    )
    .await
    .unwrap();
    // An owner gives alice the secret's activity alone.
    let audit = permission_name(
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        ResourceAction::Audit,
    );
    let audit_id = gauge::resource_permissions::permission_record_id(
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        ResourceAction::Audit,
    );
    grant_permission_to_user(&audit_id, "alice", &dave)
        .await
        .unwrap();
    assert!(actor_can(&w.as_user("alice"), &audit).await.unwrap());

    let page = list_resource_activity(
        &w.as_user("alice"),
        ResourceKind::NeutrinoSecret,
        "bank-credential",
        None,
    )
    .await
    .expect("Audit holder reads");
    assert!(
        page.items
            .iter()
            .any(|r| r.summary.starts_with("Gave bob ")),
        "{:?}",
        page.items
    );
    assert_err(
        list_resource_activity(
            &w.as_user("bob"),
            ResourceKind::NeutrinoSecret,
            "bank-credential",
            None,
        )
        .await,
        "NotAuthorized",
    );
}

#[tokio::test]
async fn service_user_reads_dont_grow_with_unrelated_groups_happy() {
    let w = world().await;
    let carol = w.as_user("carol");
    let su = create_service_user(&w, "alice", "counted").await;
    let home = group("Agents", &carol).await;
    add_group_member_service_user(&home, &su, &carol)
        .await
        .unwrap();
    let alice = w.as_user("alice");

    __test_reset_reach_read_count();
    let first = service_user_effective_permissions(&alice, &su)
        .await
        .unwrap();
    let small = __test_reach_read_count();

    for n in 0..25 {
        let g = group(&format!("Unrelated {n}"), &carol).await;
        add_group_member_user(&g, "bob", &carol).await.unwrap();
    }
    __test_reset_reach_read_count();
    let second = service_user_effective_permissions(&alice, &su)
        .await
        .unwrap();
    let large = __test_reach_read_count();

    assert_eq!(first, second);
    assert_eq!(small, large, "reads follow what the service user holds");
}

#[tokio::test]
async fn requester_cannot_approve_their_own_request_sad() {
    use valence::Model;
    let w = world().await;
    let permission_id = payroll(&w).await;
    let request_id = pending_request(&w, &permission_id).await;
    let alice = w.as_user("alice");
    let loaded = gauge::generated::PermissionRequest::get(&request_id, &w.system, valence::use_!(r"**Test:** Fixture **Permission Request** load so the suite can check a requester can't approve their own request. CI and developers running the suite only."))
        .await
        .unwrap()
        .unwrap();
    for status in [
        gauge::generated::PermissionRequestStatus::Approved,
        gauge::generated::PermissionRequestStatus::Denied,
    ] {
        let result = loaded
            .clone()
            .get_mutable(&alice, valence::use_!(r"**Test:** Fixture **this data** access so the suite can check a requester can't decide their own request. CI and developers running the suite only."))
            .set_status(status)
            .unwrap()
            .commit()
            .await;
        assert!(
            result.is_err(),
            "requester must not decide their own request"
        );
    }
}
