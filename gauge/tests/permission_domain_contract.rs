//! Named happy/sad contracts for product-local gauge permission domain APIs.
//!
//! Covers the same service surface that backs `gauge-app` / `PermissionRoutes`
//! (CRUD, grant/revoke, `actor_can` / `user_can`, request/review). Higgs
//! `#[server]` wrappers are thin request-context adapters over
//! [`gauge::service`].
//!
//! Run: `cargo test -p gauge --features ssr --test permission_domain_contract`

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{record_pk_id, seed_super_user_group_with_member, seed_user, test_valence};
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
    PermissionRequestCreateInput, PermissionRequestDecision, PermissionRequestDecisionInput,
    PermissionRequestStatusDto, PermissionRequestTargetKind,
};
use valence::{Actor, Valence};

struct SeededPermission {
    system: Valence,
    owner_ctx: Valence,
    outsider_ctx: Valence,
    requestor_ctx: Valence,
    group_id: String,
    domain_id: String,
    permission_id: String,
    permission_name: String,
}

async fn seed_permission_world(permission_name: &str) -> SeededPermission {
    let system = test_valence(Actor::System {
        operation: "permission_domain_contract_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("outsider", "outsider@example.com", &system).await;
    seed_user("requestor", "requestor@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let outsider_ctx = system.with_actor(Actor::User {
        user_id: "outsider".to_string(),
    });
    let requestor_ctx = system.with_actor(Actor::User {
        user_id: "requestor".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: format!("{permission_name}-owners"),
            description: "contract owners".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = record_pk_id(group.id());

    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: format!("{permission_name}-domain"),
            description: "contract domain".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: permission_name.to_string(),
            description: "contract permission".to_string(),
            owners_group_id: group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &owner_ctx,
    )
    .await
    .expect("create permission");

    SeededPermission {
        system,
        owner_ctx,
        outsider_ctx,
        requestor_ctx,
        group_id,
        domain_id,
        permission_id: record_pk_id(permission.id()),
        permission_name: permission_name.to_string(),
    }
}

#[tokio::test]
async fn domain_create_list_get_happy_path() {
    let system = test_valence(Actor::System {
        operation: "domain_create_list_get".to_string(),
    })
    .await;
    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let created = service::create_domain(
        PermissionDomainCreateInput {
            name: "Ops".to_string(),
            description: "operations".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(created.id());
    assert_ne!(domain_id, "", "created domain must have an id");
    assert_eq!(created.name(), "Ops");
    assert_eq!(
        created.description().map(String::as_str),
        Some("operations")
    );

    let listed = service::list_domains(&owner_ctx, None)
        .await
        .expect("list domains");
    assert!(
        listed.iter().any(|d| d.id == domain_id && d.name == "Ops"),
        "created domain must appear in list_domains"
    );

    let detail = service::get_domain_detail(&domain_id, &owner_ctx)
        .await
        .expect("get domain")
        .expect("domain detail exists");
    assert_eq!(detail.id, domain_id);
    assert_eq!(detail.name, "Ops");
    assert_eq!(detail.description, "operations");
}

#[tokio::test]
async fn grant_revoke_direct_and_group_inheritance_happy_path() {
    let world = seed_permission_world("CanDeployContract").await;
    let requestor = &world.requestor_ctx;

    let before = service::actor_can(requestor, &world.permission_name)
        .await
        .expect("actor_can before");
    assert!(!before, "no grant yet");

    service::grant_permission_to_user(&world.permission_id, "requestor", &world.owner_ctx)
        .await
        .expect("grant user");
    assert!(
        service::actor_can(requestor, &world.permission_name)
            .await
            .expect("after direct grant"),
        "direct grant should allow"
    );
    assert!(
        service::user_can(&world.owner_ctx, "requestor", &world.permission_name)
            .await
            .expect("user_can after direct"),
        "user_can should mirror actor_can"
    );
    assert!(
        service::has_permission(requestor, &world.permission_name)
            .await
            .expect("has_permission alias"),
        "has_permission is actor_can alias"
    );

    service::revoke_permission_from_user(&world.permission_id, "requestor", &world.owner_ctx)
        .await
        .expect("revoke user");
    assert!(
        !service::actor_can(requestor, &world.permission_name)
            .await
            .expect("after revoke"),
        "revoke should deny"
    );

    service::add_group_member_user(&world.group_id, "requestor", &world.owner_ctx)
        .await
        .expect("add member");
    service::grant_permission_to_group(&world.permission_id, &world.group_id, &world.owner_ctx)
        .await
        .expect("grant group");
    assert!(
        service::actor_can(requestor, &world.permission_name)
            .await
            .expect("after group grant"),
        "group membership should inherit grant"
    );

    service::revoke_permission_from_group(&world.permission_id, &world.group_id, &world.owner_ctx)
        .await
        .expect("revoke group");
    assert!(
        !service::actor_can(requestor, &world.permission_name)
            .await
            .expect("after group revoke"),
        "group revoke should deny"
    );

    let detail = service::get_permission_detail(&world.permission_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("permission exists");
    assert_eq!(detail.name, world.permission_name);
    assert_eq!(detail.domain_id, world.domain_id);
}

#[tokio::test]
async fn permission_request_approve_grants_access_happy_path() {
    let world = seed_permission_world("CanReviewContract").await;

    let created = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id.clone(),
            reason: "Need deploy access for release".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create request");
    assert_eq!(created.status, PermissionRequestStatusDto::Pending);
    assert_eq!(created.requestor_user_id, "requestor");

    let decided = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: created.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &world.owner_ctx,
    )
    .await
    .expect("approve request");
    assert_eq!(decided.status, PermissionRequestStatusDto::Approved);
    assert_eq!(decided.approver_user_id.as_deref(), Some("owner"));

    assert!(
        service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("actor_can after approve"),
        "approval should grant permission"
    );
}

#[tokio::test]
async fn permission_workflow_domain_grant_request_review_happy_path() {
    // Multi-step covering integ for Layer 2 e2e waiver.
    let world = seed_permission_world("CanShipContract").await;

    let domains = service::list_domains(&world.owner_ctx, None)
        .await
        .expect("list domains");
    assert!(domains.iter().any(|d| d.id == world.domain_id));

    service::grant_permission_to_user(&world.permission_id, "requestor", &world.owner_ctx)
        .await
        .expect("grant");
    assert!(
        service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("granted")
    );
    service::revoke_permission_from_user(&world.permission_id, "requestor", &world.owner_ctx)
        .await
        .expect("revoke");

    let request = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id.clone(),
            reason: "Ship window access".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("request");

    let mine = service::list_permission_requests_for_actor(&world.requestor_ctx)
        .await
        .expect("actor requests");
    assert!(mine.iter().any(|r| r.id == request.id));

    let review = service::list_permission_requests_for_review(&world.owner_ctx)
        .await
        .expect("review queue");
    assert!(review.iter().any(|r| r.id == request.id));

    let denied = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: request.id.clone(),
            decision: PermissionRequestDecision::Deny,
        },
        &world.owner_ctx,
    )
    .await
    .expect("deny");
    assert_eq!(
        denied.status,
        PermissionRequestStatusDto::Denied,
        "deny must persist Denied status"
    );
    assert_eq!(
        denied.approver_user_id.as_deref(),
        Some("owner"),
        "deny must record approver"
    );
    assert!(
        !service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("after deny"),
        "deny must not grant"
    );
}

#[tokio::test]
async fn outsider_cannot_decide_permission_request_sad() {
    let world = seed_permission_world("OutsiderDecide").await;
    let request = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id.clone(),
            reason: "Please approve".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create request");

    let denied = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: request.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &world.outsider_ctx,
    )
    .await;
    let msg = denied.expect_err("outsider decide").to_string();
    assert!(
        msg.contains("Not authorized to review this request"),
        "got {msg}"
    );

    let detail = service::get_permission_request_detail(&request.id, &world.requestor_ctx)
        .await
        .expect("detail")
        .expect("request exists");
    assert_eq!(
        detail.status,
        PermissionRequestStatusDto::Pending,
        "unauthorized decide must not change status"
    );
    assert!(
        !service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("actor_can"),
        "unauthorized approve must not grant access"
    );
}

#[tokio::test]
async fn actor_can_unknown_permission_returns_false_happy_path() {
    let world = seed_permission_world("KnownPerm").await;
    let allowed = service::actor_can(&world.owner_ctx, "definitely.missing.permission")
        .await
        .expect("actor_can unknown");
    assert!(!allowed);
}

#[tokio::test]
async fn actor_can_empty_permission_name_returns_false_sad() {
    let world = seed_permission_world("EmptyNameCheck").await;
    let allowed = service::actor_can(&world.owner_ctx, "   ")
        .await
        .expect("empty name");
    assert!(!allowed, "blank permission name must deny");
}

#[tokio::test]
async fn duplicate_permission_and_group_names_rejected_sad() {
    let system = test_valence(Actor::System {
        operation: "unique_name_sad".to_string(),
    })
    .await;
    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    service::create_group(
        PermissionGroupCreateInput {
            name: "Unique Group Name".to_string(),
            description: String::new(),
        },
        &owner_ctx,
    )
    .await
    .expect("first group");

    let dup_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Unique Group Name".to_string(),
            description: String::new(),
        },
        &owner_ctx,
    )
    .await;
    let group_msg = dup_group.expect_err("duplicate group name").to_string();
    assert!(group_msg.contains("already exists"), "got {group_msg}");

    let world = seed_permission_world("Unique Permission Name").await;
    let dup_perm = service::create_permission(
        PermissionCreateInput {
            name: "Unique Permission Name".to_string(),
            description: String::new(),
            owners_group_id: world.group_id,
            domain_id: world.domain_id,
        },
        &world.owner_ctx,
    )
    .await;
    let perm_msg = dup_perm.expect_err("duplicate permission name").to_string();
    assert!(perm_msg.contains("already exists"), "got {perm_msg}");
}

#[tokio::test]
async fn create_permission_missing_domain_rejected_sad() {
    let system = test_valence(Actor::System {
        operation: "missing_domain_sad".to_string(),
    })
    .await;
    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Missing Domain Owners".to_string(),
            description: String::new(),
        },
        &owner_ctx,
    )
    .await
    .expect("group");

    let err = service::create_permission(
        PermissionCreateInput {
            name: "NeedsDomain".to_string(),
            description: String::new(),
            owners_group_id: record_pk_id(group.id()),
            domain_id: "does-not-exist".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect_err("missing domain");
    let msg = err.to_string();
    assert!(msg.contains("Permission domain not found"), "got {msg}");
}

#[tokio::test]
async fn non_owner_cannot_grant_permission_sad() {
    let world = seed_permission_world("OwnerOnlyGrant").await;
    let err =
        service::grant_permission_to_user(&world.permission_id, "requestor", &world.outsider_ctx)
            .await
            .expect_err("outsider grant");
    let msg = err.to_string();
    assert!(
        msg.contains("Not authorized to edit permission"),
        "got {msg}"
    );
    assert!(
        !service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("actor_can"),
        "denied grant must not confer access"
    );
}

#[tokio::test]
async fn non_owner_cannot_update_group_sad() {
    let world = seed_permission_world("OwnerOnlyGroupEdit").await;
    let before = service::get_group_detail(&world.group_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("group");
    let err = service::update_group(
        &world.group_id,
        "Hijacked".to_string(),
        "nope".to_string(),
        &world.outsider_ctx,
    )
    .await
    .expect_err("outsider update");
    let msg = err.to_string();
    assert!(msg.contains("Not authorized to edit group"), "got {msg}");
    let after = service::get_group_detail(&world.group_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("group");
    assert_eq!(after.name, before.name, "denied update must not rename");
    assert_eq!(
        after.description, before.description,
        "denied update must not change description"
    );
}

#[tokio::test]
async fn creator_becomes_maintainer_outsider_cannot_update_tm_sec_07() {
    let system = test_valence(Actor::System {
        operation: "tm_sec_07_create_maintainer".to_string(),
    })
    .await;
    seed_user("creator", "creator@example.test", &system).await;
    seed_user("outsider", "outsider@example.test", &system).await;

    let creator_ctx = system.with_actor(Actor::User {
        user_id: "creator".to_string(),
    });
    let outsider_ctx = system.with_actor(Actor::User {
        user_id: "outsider".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "TM-SEC-07 Group".to_string(),
            description: "creator owned".to_string(),
        },
        &creator_ctx,
    )
    .await
    .expect("create");
    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    service::update_group(
        &group_id,
        "TM-SEC-07 Group".to_string(),
        "creator updated".to_string(),
        &creator_ctx,
    )
    .await
    .expect("creator maintainer update");

    let denied = service::update_group(
        &group_id,
        "Hijacked".to_string(),
        "outsider".to_string(),
        &outsider_ctx,
    )
    .await
    .expect_err("outsider update");
    assert!(
        denied.to_string().contains("Not authorized to edit group"),
        "got {denied}"
    );

    let detail = service::get_group_detail(&group_id, &creator_ctx)
        .await
        .expect("detail")
        .expect("group");
    assert_eq!(detail.description, "creator updated");
}

#[tokio::test]
async fn unauthenticated_cannot_create_group_sad() {
    let system = test_valence(Actor::System {
        operation: "unauthenticated_create_group".to_string(),
    })
    .await;
    let err = service::create_group(
        PermissionGroupCreateInput {
            name: "No Actor Group".to_string(),
            description: String::new(),
        },
        &system,
    )
    .await
    .expect_err("system actor");
    let msg = err.to_string();
    assert!(msg.contains("Authenticated user required"), "got {msg}");
}

#[tokio::test]
async fn unauthenticated_cannot_list_or_create_domain_sad() {
    let anon = test_valence(Actor::Anonymous).await;
    let list_err = service::list_domains(&anon, None)
        .await
        .expect_err("anonymous list_domains");
    assert!(
        list_err.to_string().contains("Authenticated user required"),
        "got {list_err}"
    );

    let get_err = service::get_domain_detail("any-id", &anon)
        .await
        .expect_err("anonymous get_domain_detail");
    assert!(
        get_err.to_string().contains("Authenticated user required"),
        "got {get_err}"
    );

    let create_err = service::create_domain(
        PermissionDomainCreateInput {
            name: "AnonDomain".to_string(),
            description: String::new(),
        },
        &anon,
    )
    .await
    .expect_err("anonymous create_domain");
    assert!(
        create_err
            .to_string()
            .contains("Authenticated user required"),
        "got {create_err}"
    );
}

#[tokio::test]
async fn owners_group_member_cannot_mutate_permission_sad() {
    let world = seed_permission_world("MemberVsOwner").await;
    service::add_group_member_user(&world.group_id, "requestor", &world.owner_ctx)
        .await
        .expect("add member");

    let grant_err =
        service::grant_permission_to_user(&world.permission_id, "outsider", &world.requestor_ctx)
            .await
            .expect_err("member grant");
    assert!(
        grant_err
            .to_string()
            .contains("Not authorized to edit permission"),
        "got {grant_err}"
    );
    assert!(
        !service::actor_can(&world.outsider_ctx, &world.permission_name)
            .await
            .expect("outsider actor_can"),
        "member grant must not confer outsider access"
    );

    let before = service::get_permission_detail(&world.permission_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("permission");
    let update_err = service::update_permission(
        &world.permission_id,
        "Hijacked".to_string(),
        "nope".to_string(),
        world.group_id.clone(),
        world.domain_id.clone(),
        &world.requestor_ctx,
    )
    .await
    .expect_err("member update");
    assert!(
        update_err
            .to_string()
            .contains("Not authorized to edit permission"),
        "got {update_err}"
    );
    let after = service::get_permission_detail(&world.permission_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("permission");
    assert_eq!(after.name, before.name, "member update must not rename");
    assert_eq!(
        after.description, before.description,
        "member update must not change description"
    );

    service::grant_permission_to_user(&world.permission_id, "outsider", &world.owner_ctx)
        .await
        .expect("owner grant happy path");
    assert!(
        service::actor_can(&world.outsider_ctx, &world.permission_name)
            .await
            .expect("after owner grant"),
        "owner grant must still succeed"
    );
}

#[tokio::test]
async fn owner_can_update_permission_happy_path() {
    let world = seed_permission_world("OwnerMutate").await;
    service::update_permission(
        &world.permission_id,
        "RenamedPerm".to_string(),
        "updated".to_string(),
        world.group_id.clone(),
        world.domain_id.clone(),
        &world.owner_ctx,
    )
    .await
    .expect("owner update_permission");

    let detail = service::get_permission_detail(&world.permission_id, &world.owner_ctx)
        .await
        .expect("get detail")
        .expect("exists");
    assert_eq!(detail.name, "RenamedPerm");
    assert_eq!(detail.description, "updated");

    service::delete_permission(&world.permission_id, &world.owner_ctx)
        .await
        .expect("owner delete_permission");
}

#[tokio::test]
async fn create_permission_request_overlong_reason_rejected_sad() {
    let world = seed_permission_world("ReasonTooLong").await;
    let reason = "r".repeat(service::MAX_REQUEST_REASON_CHARS + 1);
    let err = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id,
            reason,
        },
        &world.requestor_ctx,
    )
    .await
    .expect_err("overlong reason");
    let msg = err.to_string();
    assert!(msg.contains("Reason is too long"), "got {msg}");
}

#[tokio::test]
async fn create_permission_request_empty_reason_rejected_sad() {
    let world = seed_permission_world("NeedsReason").await;
    let err = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id,
            reason: "   ".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect_err("empty reason");
    let msg = err.to_string();
    assert!(msg.contains("Reason is required"), "got {msg}");
}

#[tokio::test]
async fn create_permission_request_already_has_permission_rejected_sad() {
    let world = seed_permission_world("AlreadyGranted").await;
    service::grant_permission_to_user(&world.permission_id, "requestor", &world.owner_ctx)
        .await
        .expect("grant first");

    let err = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id,
            reason: "Already have it".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect_err("already has");
    let msg = err.to_string();
    assert!(msg.contains("already have this permission"), "got {msg}");
}

#[tokio::test]
async fn get_permission_request_detail_unauthorized_viewer_sad() {
    let world = seed_permission_world("PrivateRequest").await;
    let created = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id,
            reason: "Please".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create request");

    let err = service::get_permission_request_detail(&created.id, &world.outsider_ctx)
        .await
        .expect_err("outsider view");
    let msg = err.to_string();
    assert!(
        msg.contains("Not authorized to view this request"),
        "got {msg}"
    );
}

#[tokio::test]
async fn duplicate_named_super_user_group_does_not_grant_privilege_sad() {
    use chrono::Utc;
    use gauge::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID, SUPER_USER_GROUP_NAME};
    use valence::Model;

    let system = test_valence(Actor::System {
        operation: "duplicate_super_user_name_test".to_string(),
    })
    .await;

    seed_user("legit", "legit@example.com", &system).await;
    seed_user("attacker", "attacker@example.com", &system).await;

    let super_group = gauge::generated::PermissionGroup::new(
        SUPER_USER_GROUP_NAME.to_string(),
        Some("super users".to_string()),
        Utc::now(),
        Utc::now(),
    )
    .expect("build super user group");
    let created =
        gauge::generated::PermissionGroup::upsert(SUPER_USER_GROUP_ID, super_group, &system)
            .await
            .expect("upsert well-known super user group");

    let legit = lepton::generated::User::get("legit", &system)
        .await
        .expect("query legit")
        .expect("legit exists");
    let legit_principal = gauge::generated::PermissionUserPrincipal::upsert(
        "user:legit",
        gauge::generated::PermissionUserPrincipal::new(
            legit.id().expect("legit id").clone(),
            "legit".to_string(),
        )
        .expect("new principal"),
        &system,
    )
    .await
    .expect("upsert legit principal");
    created
        .relate_to_owner_record(legit_principal.id().expect("principal id"), &system)
        .await
        .expect("relate legit owner");
    created
        .relate_to_member_record(legit_principal.id().expect("principal id"), &system)
        .await
        .expect("relate legit member");

    let fake = gauge::generated::PermissionGroup::new(
        SUPER_USER_GROUP_NAME.to_string(),
        Some("imposter".to_string()),
        Utc::now(),
        Utc::now(),
    )
    .expect("build fake super user group");
    let fake_group =
        gauge::generated::PermissionGroup::upsert("fake_super_user_group", fake, &system)
            .await
            .expect("upsert fake super user group");

    let attacker = lepton::generated::User::get("attacker", &system)
        .await
        .expect("query attacker")
        .expect("attacker exists");
    let attacker_principal = gauge::generated::PermissionUserPrincipal::upsert(
        "user:attacker",
        gauge::generated::PermissionUserPrincipal::new(
            attacker.id().expect("attacker id").clone(),
            "attacker".to_string(),
        )
        .expect("new principal"),
        &system,
    )
    .await
    .expect("upsert attacker principal");
    fake_group
        .relate_to_owner_record(attacker_principal.id().expect("principal id"), &system)
        .await
        .expect("relate fake owner");
    fake_group
        .relate_to_member_record(attacker_principal.id().expect("principal id"), &system)
        .await
        .expect("relate fake member");

    let attacker_ctx = system.with_actor(Actor::User {
        user_id: "attacker".to_string(),
    });
    let legit_ctx = system.with_actor(Actor::User {
        user_id: "legit".to_string(),
    });

    assert!(
        !actor_is_super_user(&attacker_ctx)
            .await
            .expect("attacker check"),
        "duplicate-name Super User membership must not grant privilege"
    );
    assert!(
        actor_is_super_user(&legit_ctx).await.expect("legit check"),
        "well-known Super User group membership must still grant privilege"
    );
}

#[tokio::test]
async fn create_permission_arbitrary_owners_group_rejected_sad() {
    let world = seed_permission_world("ArbitraryOwnersGroup").await;

    let err = service::create_permission(
        PermissionCreateInput {
            name: "HijackedOwners".to_string(),
            description: "nope".to_string(),
            owners_group_id: world.group_id.clone(),
            domain_id: world.domain_id.clone(),
        },
        &world.outsider_ctx,
    )
    .await
    .expect_err("outsider cannot pick owner group");
    let msg = err.to_string();
    assert!(
        msg.contains("Not authorized to use owner group"),
        "got {msg}"
    );

    let listed = service::list_permissions(&world.owner_ctx, Some("HijackedOwners".to_string()))
        .await
        .expect("list");
    assert!(
        listed.iter().all(|p| p.name != "HijackedOwners"),
        "denied create must not persist permission: {listed:?}"
    );
}

#[tokio::test]
async fn permission_detail_allow_list_editor_matrix() {
    let world = seed_permission_world("AllowListMatrix").await;
    service::grant_permission_to_user(&world.permission_id, "requestor", &world.owner_ctx)
        .await
        .expect("grant for allow-list");

    let outsider_detail = service::get_permission_detail(&world.permission_id, &world.outsider_ctx)
        .await
        .expect("outsider read")
        .expect("permission exists");
    assert!(
        outsider_detail.allow_list.is_empty(),
        "outsider must not see the grant graph; got {:?}",
        outsider_detail.allow_list
    );

    let owner_detail = service::get_permission_detail(&world.permission_id, &world.owner_ctx)
        .await
        .expect("owner read")
        .expect("permission exists");
    assert!(
        owner_detail
            .allow_list
            .iter()
            .any(|entry| entry.id == "requestor"),
        "owner must see requestor in allow_list; got {:?}",
        owner_detail.allow_list
    );

    seed_user("coowner", "coowner@example.com", &world.system).await;
    service::add_group_owner_user(&world.group_id, "coowner", &world.owner_ctx)
        .await
        .expect("add co-owner to owners group");
    let coowner_ctx = world.system.with_actor(Actor::User {
        user_id: "coowner".to_string(),
    });
    let coowner_detail = service::get_permission_detail(&world.permission_id, &coowner_ctx)
        .await
        .expect("coowner read")
        .expect("permission exists");
    assert!(
        coowner_detail
            .allow_list
            .iter()
            .any(|entry| entry.id == "requestor"),
        "owners-group co-owner must see grant graph; got {:?}",
        coowner_detail.allow_list
    );

    let su = "super_allow_list";
    seed_user(su, "super_allow_list@example.com", &world.system).await;
    seed_super_user_group_with_member(&world.system, su).await;
    let su_ctx = world.system.with_actor(Actor::User {
        user_id: su.to_string(),
    });
    let su_detail = service::get_permission_detail(&world.permission_id, &su_ctx)
        .await
        .expect("super user read")
        .expect("permission exists");
    assert!(
        su_detail
            .allow_list
            .iter()
            .any(|entry| entry.id == "requestor"),
        "Super User must see grant graph; got {:?}",
        su_detail.allow_list
    );
}

#[tokio::test]
async fn group_detail_omits_owners_and_members_for_outsider_sad() {
    let world = seed_permission_world("GroupGraphOmit").await;

    let outsider_detail = service::get_group_detail(&world.group_id, &world.outsider_ctx)
        .await
        .expect("outsider read")
        .expect("group exists");
    assert!(
        outsider_detail.owner_users.is_empty() && outsider_detail.members.is_empty(),
        "outsider must not see owners/members; got owners={:?} members={:?}",
        outsider_detail.owner_users,
        outsider_detail.members
    );

    let owner_detail = service::get_group_detail(&world.group_id, &world.owner_ctx)
        .await
        .expect("owner read")
        .expect("group exists");
    assert!(
        !owner_detail.owner_users.is_empty(),
        "owner must see owner_users; got {:?}",
        owner_detail.owner_users
    );
}

#[tokio::test]
async fn authenticated_user_cannot_mutate_domain_via_valence_sad() {
    use chrono::Utc;
    use gauge::generated::PermissionDomain;
    use valence::{Model, PrivacyEvaluator, PrivacyOperation, SchemaRegistry};

    let system = test_valence(Actor::System {
        operation: "domain_valence_policy".to_string(),
    })
    .await;
    seed_user("owner", "owner@example.com", &system).await;
    seed_user("outsider", "outsider@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let outsider_ctx = system.with_actor(Actor::User {
        user_id: "outsider".to_string(),
    });

    let created = service::create_domain(
        PermissionDomainCreateInput {
            name: "PolicyDomain".to_string(),
            description: "valence policy".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create domain via service");
    let domain_id = record_pk_id(created.id());

    let schema = SchemaRegistry::global()
        .get_schema("permission_domain")
        .expect("permission_domain schema registered");
    let raw = valence::QueryCore::get_record_json("permission_domain", &domain_id, &system)
        .await
        .expect("load domain json")
        .expect("domain row");

    let update_allowed = PrivacyEvaluator::check_entity_access(
        schema,
        PrivacyOperation::Update,
        &raw,
        &outsider_ctx,
    )
    .await
    .is_ok();
    assert!(
        !update_allowed,
        "authenticated users must not update domains via Valence"
    );

    let hijacked = PermissionDomain::new(
        false,
        None,
        "Hijacked".to_string(),
        Some("blocked".to_string()),
        Utc::now(),
        Utc::now(),
    )
    .expect("build domain");
    let direct_err = PermissionDomain::upsert(&domain_id, hijacked, &outsider_ctx)
        .await
        .expect_err("direct domain upsert");
    assert!(
        direct_err.to_string().to_lowercase().contains("privac")
            || direct_err.to_string().to_lowercase().contains("denied")
            || direct_err
                .to_string()
                .to_lowercase()
                .contains("not authorized"),
        "got {direct_err}"
    );
}

#[tokio::test]
async fn authenticated_user_cannot_read_foreign_request_via_service_sad() {
    let world = seed_permission_world("RequestValencePolicy").await;
    let created = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id,
            reason: "Please".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create request");

    assert!(
        service::get_permission_request_detail(&created.id, &world.requestor_ctx)
            .await
            .expect("service read")
            .is_some(),
        "service layer must still expose requests to the requestor"
    );

    // Model A: Valence read is AUTHENTICATED; containment is service-layer filtering.
    let err = service::get_permission_request_detail(&created.id, &world.outsider_ctx)
        .await
        .expect_err("outsider service read");
    assert!(
        err.to_string()
            .contains("Not authorized to view this request"),
        "outsider must not see foreign requests via service, got {err}"
    );
}

#[tokio::test]
async fn nested_group_membership_inherits_permission_happy_path() {
    let world = seed_permission_world("NestedInheritPerm").await;
    let parent_id = world.group_id.clone();

    let child = service::create_group(
        PermissionGroupCreateInput {
            name: "NestedInheritChild".to_string(),
            description: "child group".to_string(),
        },
        &world.owner_ctx,
    )
    .await
    .expect("create child");
    let child_id = record_pk_id(child.id());

    service::add_group_member_user(&child_id, "requestor", &world.owner_ctx)
        .await
        .expect("add requestor to child");
    service::grant_permission_to_group(&world.permission_id, &parent_id, &world.owner_ctx)
        .await
        .expect("grant parent");

    assert!(
        !service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("before nest"),
        "requestor must not inherit until child is nested under parent"
    );

    service::add_group_member_group(&parent_id, &child_id, &world.owner_ctx)
        .await
        .expect("nest child under parent");

    assert!(
        service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("after nest"),
        "user in child must inherit grant on parent group"
    );
}

#[tokio::test]
async fn nested_group_remove_breaks_inheritance_happy_path() {
    let world = seed_permission_world("NestedRemovePerm").await;
    let parent_id = world.group_id.clone();

    let child = service::create_group(
        PermissionGroupCreateInput {
            name: "NestedRemoveChild".to_string(),
            description: "child group".to_string(),
        },
        &world.owner_ctx,
    )
    .await
    .expect("create child");
    let child_id = record_pk_id(child.id());

    service::add_group_member_user(&child_id, "requestor", &world.owner_ctx)
        .await
        .expect("add requestor to child");
    service::grant_permission_to_group(&world.permission_id, &parent_id, &world.owner_ctx)
        .await
        .expect("grant parent");
    service::add_group_member_group(&parent_id, &child_id, &world.owner_ctx)
        .await
        .expect("nest child");

    assert!(
        service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("nested allow"),
        "precondition: nested inheritance allows"
    );

    service::remove_group_member_group(&parent_id, &child_id, &world.owner_ctx)
        .await
        .expect("unnest child");

    assert!(
        !service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("after unnest"),
        "removing nested membership must revoke inherited allow"
    );

    let child_detail = service::get_group_detail(&child_id, &world.owner_ctx)
        .await
        .expect("child detail")
        .expect("child exists");
    assert!(
        child_detail
            .members
            .iter()
            .any(|m| { m.kind == gauge::types::PrincipalKind::User && m.id == "requestor" }),
        "user must remain a direct member of the child group"
    );
}

#[tokio::test]
async fn add_group_member_group_self_rejected_sad() {
    let world = seed_permission_world("NestedSelfReject").await;
    let err = service::add_group_member_group(&world.group_id, &world.group_id, &world.owner_ctx)
        .await
        .expect_err("self membership");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("itself") || msg.contains("self"),
        "expected self-membership rejection, got {msg}"
    );
}

#[tokio::test]
async fn non_owner_cannot_add_group_member_group_sad() {
    let world = seed_permission_world("NestedNonOwner").await;
    let child = service::create_group(
        PermissionGroupCreateInput {
            name: "NestedNonOwnerChild".to_string(),
            description: "child".to_string(),
        },
        &world.owner_ctx,
    )
    .await
    .expect("create child");
    let child_id = record_pk_id(child.id());

    let err = service::add_group_member_group(&world.group_id, &child_id, &world.outsider_ctx)
        .await
        .expect_err("outsider nest");
    let msg = err.to_string();
    assert!(
        msg.contains("Not authorized to edit group membership"),
        "got {msg}"
    );
}

#[tokio::test]
async fn group_request_approve_adds_member_happy_path() {
    let world = seed_permission_world("GroupReqApprove").await;

    let target = service::create_group(
        PermissionGroupCreateInput {
            name: "GroupReqTarget".to_string(),
            description: "join me".to_string(),
        },
        &world.owner_ctx,
    )
    .await
    .expect("target group");
    let target_id = record_pk_id(target.id());

    let created = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Group,
            target_id: target_id.clone(),
            reason: "Need to join the team group".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create group request");

    let decided = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: created.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &world.owner_ctx,
    )
    .await
    .expect("approve");
    assert_eq!(decided.status, PermissionRequestStatusDto::Approved);

    let detail = service::get_group_detail(&target_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("group exists");
    assert!(
        detail
            .members
            .iter()
            .any(|m| { m.kind == gauge::types::PrincipalKind::User && m.id == "requestor" }),
        "approval must add requestor as group member: {:?}",
        detail.members
    );
}

#[tokio::test]
async fn group_request_deny_does_not_add_member_sad() {
    let world = seed_permission_world("GroupReqDeny").await;

    let target = service::create_group(
        PermissionGroupCreateInput {
            name: "GroupReqDenyTarget".to_string(),
            description: "join me".to_string(),
        },
        &world.owner_ctx,
    )
    .await
    .expect("target group");
    let target_id = record_pk_id(target.id());

    let created = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Group,
            target_id: target_id.clone(),
            reason: "Please add me to the group".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create group request");

    let decided = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: created.id.clone(),
            decision: PermissionRequestDecision::Deny,
        },
        &world.owner_ctx,
    )
    .await
    .expect("deny");
    assert_eq!(decided.status, PermissionRequestStatusDto::Denied);

    let detail = service::get_group_detail(&target_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("group exists");
    assert!(
        !detail
            .members
            .iter()
            .any(|m| { m.kind == gauge::types::PrincipalKind::User && m.id == "requestor" }),
        "deny must not add requestor as member: {:?}",
        detail.members
    );
}

#[tokio::test]
async fn decide_non_pending_request_rejected_sad() {
    let world = seed_permission_world("ReDecideGuard").await;

    let created = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: world.permission_id.clone(),
            reason: "Need access for re-decide test".to_string(),
        },
        &world.requestor_ctx,
    )
    .await
    .expect("create");

    service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: created.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &world.owner_ctx,
    )
    .await
    .expect("first approve");

    assert!(
        service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("after first approve"),
        "first approve must grant"
    );

    let err = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: created.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &world.owner_ctx,
    )
    .await
    .expect_err("second decide");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("pending"),
        "expected pending-only guard, got {msg}"
    );

    // Containment: still allowed once (no panic / double-grant side effects required).
    assert!(
        service::actor_can(&world.requestor_ctx, &world.permission_name)
            .await
            .expect("still granted"),
        "failed re-decide must not revoke prior grant"
    );
}

#[tokio::test]
async fn owner_delete_group_happy_path() {
    use valence::ownership::{normalize_record_id_for_ownership, OwnershipService};
    use valence::Model;

    let system = test_valence(Actor::System {
        operation: "delete_group_happy_setup".to_string(),
    })
    .await;
    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "DeleteMeGroup".to_string(),
            description: "ephemeral".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create");
    let group_id = record_pk_id(group.id());
    let bare = normalize_record_id_for_ownership(&group_id);

    service::delete_group(&group_id, &owner_ctx)
        .await
        .expect("owner delete");

    // Harness uses a noop deletion dispatcher, so the durable service contract is
    // ownership marked pending_deletion (same pattern as counter ownership tests).
    let own = OwnershipService::get_ownership_json("permission_group", &bare, &system)
        .await
        .expect("ownership lookup")
        .expect("ownership row after delete");
    assert_eq!(
        own.get("status").and_then(|x| x.as_str()),
        Some("pending_deletion"),
        "delete_group must mark ownership pending_deletion, got {own}"
    );

    // Typed Model::get must gate pending rows.
    let typed = gauge::generated::PermissionGroup::get(&group_id, &system).await;
    assert!(
        matches!(typed, Err(valence::Error::PendingDeletion(_))) || matches!(typed, Ok(None)),
        "typed get after delete must not return a live group, got {typed:?}"
    );

    let missing = service::delete_group("definitely_missing_group_id", &owner_ctx)
        .await
        .expect_err("missing group");
    let msg = missing.to_string().to_lowercase();
    assert!(
        msg.contains("not found"),
        "missing id must classify not-found, got {msg}"
    );
}

#[tokio::test]
async fn non_owner_cannot_delete_group_sad() {
    let world = seed_permission_world("DeleteGroupAuthz").await;

    let err = service::delete_group(&world.group_id, &world.outsider_ctx)
        .await
        .expect_err("outsider delete");
    let msg = err.to_string();
    assert!(msg.contains("Not authorized to delete group"), "got {msg}");

    let still = service::get_group_detail(&world.group_id, &world.owner_ctx)
        .await
        .expect("detail")
        .expect("group must remain");
    assert_eq!(still.id, world.group_id);
}
