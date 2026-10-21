#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{record_pk_id, seed_user, test_valence};
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
};
use valence::Actor;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn create_and_mutate_permission_flows_happy_path() {
    let system = test_valence(Actor::System {
        operation: "permission_test_setup".to_string(),
    })
    .await;

    seed_user("u1", "owner@example.com", &system).await;
    seed_user("u2", "member@example.com", &system).await;

    let user_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });
    let member_ctx = system.with_actor(Actor::User {
        user_id: "u2".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Group A".to_string(),
            description: "Owners group".to_string(),
        },
        &user_ctx,
    )
    .await
    .expect("create group");

    let group_id = record_pk_id(group.id());
    service::add_group_member_user(&group_id, "u2", &user_ctx)
        .await
        .expect("add group member user");

    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Infrastructure".to_string(),
            description: "infra permissions".to_string(),
        },
        &user_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "CanDeploy".to_string(),
            description: "Allow deployments".to_string(),
            owners_group_id: group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &user_ctx,
    )
    .await
    .expect("create permission");

    let permission_id = record_pk_id(permission.id());

    let can_before_grants = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can before grants");
    assert!(
        !can_before_grants,
        "member should not have permission before grants"
    );

    service::grant_permission_to_user(&permission_id, "u2", &user_ctx)
        .await
        .expect("grant user");

    let can_via_direct_grant = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can after direct grant");
    assert!(
        can_via_direct_grant,
        "member should have permission after direct user grant"
    );

    let can_via_user_api = service::user_can(&user_ctx, "u2", "CanDeploy")
        .await
        .expect("check user_can after direct grant");
    assert!(
        can_via_user_api,
        "user_can should resolve direct user grant"
    );

    service::revoke_permission_from_user(&permission_id, "u2", &user_ctx)
        .await
        .expect("revoke user");

    let can_after_revoke_direct = service::has_permission(&member_ctx, "CanDeploy")
        .await
        .expect("check has_permission after direct revoke");
    assert!(
        !can_after_revoke_direct,
        "member should lose direct user grant"
    );

    service::grant_permission_to_group(&permission_id, &group_id, &user_ctx)
        .await
        .expect("grant group");

    let can_via_group_grant = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can after group grant");
    assert!(
        can_via_group_grant,
        "member should inherit permission through allowed group membership"
    );

    service::revoke_permission_from_group(&permission_id, &group_id, &user_ctx)
        .await
        .expect("revoke group");

    let can_after_revoke_group = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can after group revoke");
    assert!(
        !can_after_revoke_group,
        "member should lose permission after group revoke"
    );

    let detail = service::get_permission_detail(&permission_id, &user_ctx)
        .await
        .expect("detail query")
        .expect("permission detail");
    assert_eq!(detail.name, "CanDeploy");
}

#[tokio::test]
async fn duplicate_permission_and_group_names_are_rejected_sad() {
    let system = test_valence(Actor::System {
        operation: "permission_unique_name_test_setup".to_string(),
    })
    .await;

    seed_user("u1", "owner@example.com", &system).await;
    let user_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });

    let first_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Unique Group Name".to_string(),
            description: String::new(),
        },
        &user_ctx,
    )
    .await
    .expect("first group should create");

    let duplicate_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Unique Group Name".to_string(),
            description: String::new(),
        },
        &user_ctx,
    )
    .await;
    let dup_group_msg = duplicate_group
        .expect_err("duplicate group name")
        .to_string();
    assert!(
        dup_group_msg.contains("already exists"),
        "got {dup_group_msg}"
    );

    let owners_group_id = record_pk_id(first_group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Platform".to_string(),
            description: "platform permissions".to_string(),
        },
        &user_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let first_permission = service::create_permission(
        PermissionCreateInput {
            name: "Unique Permission Name".to_string(),
            description: String::new(),
            owners_group_id: owners_group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &user_ctx,
    )
    .await;
    assert!(first_permission.is_ok(), "first permission should create");

    let duplicate_permission = service::create_permission(
        PermissionCreateInput {
            name: "Unique Permission Name".to_string(),
            description: String::new(),
            owners_group_id,
            domain_id,
        },
        &user_ctx,
    )
    .await;
    let dup_perm_msg = duplicate_permission
        .expect_err("duplicate permission name")
        .to_string();
    assert!(
        dup_perm_msg.contains("already exists"),
        "got {dup_perm_msg}"
    );
}

// ---- create_group_owner_only / clear_group_members -------------------------------------

mod owner_only_and_clear {
    use super::{record_pk_id, seed_user, test_valence};
    use gauge::service::{self, GaugeServiceError};
    use gauge::types::{
        PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
    };
    use valence::{Actor, Valence};

    fn input(name: &str) -> PermissionGroupCreateInput {
        PermissionGroupCreateInput {
            name: name.to_string(),
            description: String::new(),
        }
    }

    fn kind(err: &anyhow::Error) -> &GaugeServiceError {
        err.downcast_ref::<GaugeServiceError>()
            .unwrap_or_else(|| panic!("not a GaugeServiceError: {err:#}"))
    }

    struct Ctx {
        system: Valence,
    }

    impl Ctx {
        async fn new() -> Self {
            let system = test_valence(Actor::System {
                operation: "owner_only_setup".to_string(),
            })
            .await;
            for id in ["a", "b", "c", "m1", "m2", "outsider"] {
                seed_user(id, &format!("{id}@example.com"), &system).await;
            }
            Self { system }
        }

        fn user(&self, id: &str) -> Valence {
            self.system.with_actor(Actor::User {
                user_id: id.to_string(),
            })
        }
    }

    async fn detail(id: &str, v: &Valence) -> gauge::types::PermissionGroupDetailDto {
        service::get_group_detail(id, v)
            .await
            .expect("detail")
            .expect("group exists")
    }

    #[tokio::test]
    async fn owner_only_create_has_owner_and_no_members_happy() {
        let c = Ctx::new().await;
        let a = c.user("a");
        let group = service::create_group_owner_only(input("Owner Only"), &a)
            .await
            .expect("create owner-only");
        let id = record_pk_id(group.id());

        let d = detail(&id, &a).await;
        assert_eq!(d.owner_users.len(), 1);
        assert_eq!(d.owner_users[0].id, "a");
        assert!(d.members.is_empty(), "no member edge: {:?}", d.members);

        // Still the owner: can add a member.
        service::add_group_member_user(&id, "m1", &a)
            .await
            .expect("owner adds member");

        // A second user owns the permission and grants it to the group, so the grant isn't
        // the creator's own.
        let b = c.user("b");
        let perm_owners = service::create_group(input("Perm Owners"), &b)
            .await
            .expect("owners");
        let domain = service::create_domain(
            PermissionDomainCreateInput {
                name: "D".to_string(),
                description: String::new(),
            },
            &b,
        )
        .await
        .expect("domain");
        let perm = service::create_permission(
            PermissionCreateInput {
                name: "OwnerOnlyPerm".to_string(),
                description: String::new(),
                owners_group_id: record_pk_id(perm_owners.id()),
                domain_id: record_pk_id(domain.id()),
            },
            &b,
        )
        .await
        .expect("permission");
        service::grant_permission_to_group(&record_pk_id(perm.id()), &id, &b)
            .await
            .expect("grant to group");
        // Group ownership counts as holding the group's grants, so owner-only creation
        // drops the member edge but not this access. Pinned so a change here is noticed.
        assert!(service::actor_can(&a, "OwnerOnlyPerm").await.unwrap());
        assert!(service::actor_can(&c.user("m1"), "OwnerOnlyPerm")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn create_group_still_makes_creator_owner_and_member_happy() {
        let c = Ctx::new().await;
        let a = c.user("a");
        let group = service::create_group(input("Both"), &a)
            .await
            .expect("create");
        let d = detail(&record_pk_id(group.id()), &a).await;
        assert_eq!(
            d.owner_users
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            ["a"]
        );
        assert_eq!(
            d.members.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            ["a"]
        );
    }

    #[tokio::test]
    async fn owner_only_create_without_user_record_is_refused_sad() {
        let c = Ctx::new().await;
        let ghost = c.user("ghost");
        let err = service::create_group_owner_only(input("Ghost Group"), &ghost)
            .await
            .expect_err("no user row");
        assert!(
            matches!(kind(&err), GaugeServiceError::NotAuthorized { operation } if operation == "create group as owner")
        );
        // Nothing was saved: the name is still free.
        service::create_group_owner_only(input("Ghost Group"), &c.user("a"))
            .await
            .expect("name unused after rejected create");
    }

    #[tokio::test]
    async fn owner_only_create_rejects_bad_names_and_saves_nothing_sad() {
        let c = Ctx::new().await;
        let a = c.user("a");
        service::create_group_owner_only(input("Taken"), &a)
            .await
            .expect("first");

        let dup = service::create_group_owner_only(input("Taken"), &a)
            .await
            .expect_err("duplicate");
        assert!(
            matches!(kind(&dup), GaugeServiceError::Validation { message } if message == "Permission group name already exists: Taken")
        );

        let empty = service::create_group_owner_only(input("   "), &a)
            .await
            .expect_err("empty");
        assert!(
            matches!(kind(&empty), GaugeServiceError::Validation { message } if message == "Group name is required")
        );

        let reserved =
            service::create_group_owner_only(input(gauge::super_user::SUPER_USER_GROUP_NAME), &a)
                .await
                .expect_err("reserved");
        assert!(
            matches!(kind(&reserved), GaugeServiceError::Validation { message } if message.contains("reserved for the well-known super-user group"))
        );
        let reserved_plain =
            service::create_group(input(gauge::super_user::SUPER_USER_GROUP_NAME), &a)
                .await
                .expect_err("reserved via create_group");
        assert!(matches!(
            kind(&reserved_plain),
            GaugeServiceError::Validation { .. }
        ));

        let groups = service::list_groups(&a, None).await.expect("list");
        assert_eq!(groups.iter().filter(|g| g.name == "Taken").count(), 1);
        assert_eq!(groups.len(), 1, "rejected creates left no row: {groups:?}");
    }

    #[tokio::test]
    async fn create_functions_refuse_callers_who_are_not_signed_in_sad() {
        let c = Ctx::new().await;
        assert!(service::create_group(input("X1"), &c.system).await.is_err());
        assert!(service::create_group_owner_only(input("X2"), &c.system)
            .await
            .is_err());
        assert!(service::clear_group_members("anything", &c.system)
            .await
            .is_err());
    }

    async fn group_with_members(c: &Ctx) -> String {
        let a = c.user("a");
        let group = service::create_group_owner_only(input("Team"), &a)
            .await
            .expect("create");
        let id = record_pk_id(group.id());
        service::add_group_member_user(&id, "m1", &a)
            .await
            .expect("m1");
        service::add_group_member_user(&id, "m2", &a)
            .await
            .expect("m2");
        id
    }

    #[tokio::test]
    async fn clear_by_owner_removes_members_and_keeps_owners_happy() {
        let c = Ctx::new().await;
        let a = c.user("a");
        let id = group_with_members(&c).await;
        let nested = record_pk_id(
            service::create_group_owner_only(input("Nested"), &a)
                .await
                .unwrap()
                .id(),
        );
        service::add_group_member_user(&nested, "b", &a)
            .await
            .unwrap();
        service::add_group_member_group(&id, &nested, &a)
            .await
            .unwrap();
        service::add_group_owner_user(&id, "c", &a).await.unwrap();

        let removed = service::clear_group_members(&id, &a).await.expect("clear");
        assert_eq!(removed, 3);

        let d = detail(&id, &a).await;
        assert!(d.members.is_empty(), "{:?}", d.members);
        let mut owners: Vec<_> = d.owner_users.iter().map(|p| p.id.clone()).collect();
        owners.sort();
        assert_eq!(owners, ["a", "c"]);
        let n = detail(&nested, &a).await;
        assert_eq!(
            n.members.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            ["b"]
        );
    }

    #[tokio::test]
    async fn clear_denied_for_member_and_outsider_leaves_state_unchanged_sad() {
        let c = Ctx::new().await;
        let a = c.user("a");
        let id = group_with_members(&c).await;
        let history_before =
            service::list_history(&a, Some("permission_group".into()), Some(id.clone()))
                .await
                .unwrap()
                .len();

        for who in ["m1", "outsider"] {
            let err = service::clear_group_members(&id, &c.user(who))
                .await
                .expect_err("denied");
            assert!(
                matches!(kind(&err), GaugeServiceError::NotAuthorized { operation } if operation == "edit group membership"),
                "{who}: {err:#}"
            );
        }
        let d = detail(&id, &a).await;
        assert_eq!(d.members.len(), 2);
        let history_after = service::list_history(&a, Some("permission_group".into()), Some(id))
            .await
            .unwrap()
            .len();
        assert_eq!(history_before, history_after);
    }

    #[tokio::test]
    async fn clear_by_super_user_who_is_not_owner_succeeds_happy() {
        let c = Ctx::new().await;
        super::super_user_seed(&c.system, "b").await;
        let id = group_with_members(&c).await;
        let removed = service::clear_group_members(&id, &c.user("b"))
            .await
            .expect("super user clears");
        assert_eq!(removed, 2);
        assert!(detail(&id, &c.user("a")).await.members.is_empty());
    }

    #[tokio::test]
    async fn clear_missing_group_is_not_found_sad() {
        let c = Ctx::new().await;
        let err = service::clear_group_members("no_such_group", &c.user("a"))
            .await
            .expect_err("missing");
        assert!(
            matches!(kind(&err), GaugeServiceError::NotFound { entity, id } if entity == "permission_group" && id == "no_such_group")
        );
    }
}

async fn super_user_seed(system: &valence::Valence, user: &str) {
    common::seed_super_user_group_with_member(system, user).await;
}
