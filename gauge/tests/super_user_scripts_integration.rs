#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{seed_membership, seed_user_with, test_valence};
use gauge::generated::PermissionGroup;
use gauge::super_user::{
    ensure_super_user_group, resync_eligible_super_user_group_members, SUPER_USER_GROUP_NAME,
};
use valence::{Actor, Model, StringPredicate, Valence};

async fn test_system_valence() -> Valence {
    test_valence(Actor::System {
        operation: "super_user_script_tests".to_string(),
    })
    .await
}

fn system_ctx(v: &Valence, operation: &str) -> Valence {
    v.with_actor(Actor::System {
        operation: operation.to_string(),
    })
}

#[tokio::test]
async fn ensure_super_user_group_script_is_idempotent_and_sync_seeds_roles() -> anyhow::Result<()> {
    let system = test_system_valence().await;
    seed_user_with("u_owner", "owner@example.com", true, &system).await;
    seed_user_with("u_super", "super@example.com", true, &system).await;
    seed_membership(
        "m_owner",
        "a1",
        "u_owner",
        lepton::generated::AccountMembershipRole::Owner,
        &system,
    )
    .await;
    seed_membership(
        "m_super",
        "a1",
        "u_super",
        lepton::generated::AccountMembershipRole::SuperAdmin,
        &system,
    )
    .await;

    ensure_super_user_group(&system_ctx(&system, "ensure_super_1")).await?;
    ensure_super_user_group(&system_ctx(&system, "ensure_super_2")).await?;
    resync_eligible_super_user_group_members(&system_ctx(&system, "sync_super_roles")).await?;

    let groups = PermissionGroup::query(&system, valence::use_!(r"**Test:** Fixture **Permission Group** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(SUPER_USER_GROUP_NAME.to_string()))
        .await?;
    assert_eq!(
        groups.len(),
        1,
        "script should enforce singleton super group"
    );
    let group = groups.first().expect("super group exists");

    let mut owner_ids = Vec::new();
    for rid in group.get_owners_record_ids(&system, valence::use_!(r"**Test:** Fixture owners edge list for `super_user_scripts_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await? {
        let principal_id = rid.id().to_string();
        if principal_id.is_empty() {
            continue;
        }
        if let Some(principal) =
            gauge::generated::PermissionUserPrincipal::get(&principal_id, &system, valence::use_!(r"**Test:** Fixture **Permission User Principal** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await?
        {
            if let Ok(user_id) = valence::extract_id_from_record(principal.user()) {
                owner_ids.push(user_id);
            }
        }
    }
    let mut member_ids = Vec::new();
    for rid in group.get_members_record_ids(&system, valence::use_!(r"**Test:** Fixture members edge list for `super_user_scripts_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await? {
        let principal_id = rid.id().to_string();
        if principal_id.is_empty() {
            continue;
        }
        if let Some(principal) =
            gauge::generated::PermissionUserPrincipal::get(&principal_id, &system, valence::use_!(r"**Test:** Fixture **Permission User Principal** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await?
        {
            if let Ok(user_id) = valence::extract_id_from_record(principal.user()) {
                member_ids.push(user_id);
            }
        }
    }

    assert!(owner_ids.contains(&"u_owner".to_string()));
    assert!(owner_ids.contains(&"u_super".to_string()));
    assert!(member_ids.contains(&"u_owner".to_string()));
    assert!(member_ids.contains(&"u_super".to_string()));

    Ok(())
}

#[tokio::test]
async fn demote_personal_account_owners_switches_owner_to_member_and_sync_skips_them(
) -> anyhow::Result<()> {
    use lepton::generated::{AccountMembership, AccountMembershipRole};

    let system = test_system_valence().await;
    seed_user_with("u_legacy", "legacy@example.com", true, &system).await;
    seed_user_with("u_admin", "admin@example.com", true, &system).await;
    seed_membership(
        "m_legacy",
        "a_legacy",
        "u_legacy",
        AccountMembershipRole::Owner,
        &system,
    )
    .await;
    seed_membership(
        "m_admin",
        "a_admin",
        "u_admin",
        AccountMembershipRole::SuperAdmin,
        &system,
    )
    .await;
    seed_user_with("u_platform", "platform@example.com", true, &system).await;
    seed_membership(
        "m_platform",
        "a_platform",
        "u_platform",
        AccountMembershipRole::Owner,
        &system,
    )
    .await;
    let keep = [
        "platform@example.com".to_string(),
        "nobody@example.com".to_string(),
    ];

    let changed =
        gauge::scripts::demote_personal_account_owners_with_valence(&system, &keep).await?;
    assert_eq!(changed, 1);
    let again = gauge::scripts::demote_personal_account_owners_with_valence(&system, &keep).await?;
    assert_eq!(again, 0, "second pass finds nothing left to change");

    let role_of = |id: &'static str| {
        let system = system.clone();
        async move {
            AccountMembership::get(id, &system, valence::use_!(r"**Test:** Fixture **Account Membership** load for `super_user_scripts_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
                .await
                .expect("load")
                .expect("membership")
                .role()
                .clone()
        }
    };
    assert_eq!(role_of("m_legacy").await, AccountMembershipRole::Member);
    assert_eq!(role_of("m_admin").await, AccountMembershipRole::SuperAdmin);
    assert_eq!(
        role_of("m_platform").await,
        AccountMembershipRole::Owner,
        "an owner listed in UF_SUPER_USER_EMAILS keeps the platform role"
    );

    resync_eligible_super_user_group_members(&system_ctx(&system, "sync_after_demote")).await?;
    let group = ensure_super_user_group(&system).await?;
    let mut member_ids = Vec::new();
    for rid in group.get_members_record_ids(&system, valence::use_!(r"**Test:** Fixture members edge list for `super_user_scripts_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await? {
        if let Some(principal) =
            gauge::generated::PermissionUserPrincipal::get(rid.id(), &system, valence::use_!(r"**Test:** Fixture **Permission User Principal** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await?
        {
            if let Ok(user_id) = valence::extract_id_from_record(principal.user()) {
                member_ids.push(user_id);
            }
        }
    }
    assert!(member_ids.contains(&"u_admin".to_string()));
    assert!(member_ids.contains(&"u_platform".to_string()));
    assert!(
        !member_ids.contains(&"u_legacy".to_string()),
        "a demoted sign-up must not be promoted: {member_ids:?}"
    );
    Ok(())
}

#[tokio::test]
async fn seed_super_user_member_by_email_rejects_unknown_email_sad() -> anyhow::Result<()> {
    let system = test_system_valence().await;
    let group = ensure_super_user_group(&system_ctx(&system, "ensure_for_email_sad")).await?;

    let err = gauge::super_user::seed_super_user_member_by_email(
        &system_ctx(&system, "seed_missing_email"),
        &group,
        "nobody@example.test",
    )
    .await
    .expect_err("unknown email");
    let msg = err.to_string();
    assert!(msg.contains("no user found for email"), "got {msg}");

    let members = group.get_members_record_ids(&system, valence::use_!(r"**Test:** Fixture members edge list for `super_user_scripts_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await?;
    assert!(
        members.is_empty(),
        "failed email seed must not invent membership: {members:?}"
    );

    Ok(())
}

#[tokio::test]
async fn seed_super_user_members_from_emails_seeds_known_and_soft_fails_missing(
) -> anyhow::Result<()> {
    let system = test_system_valence().await;
    seed_user_with("u_ops", "ops@example.com", true, &system).await;
    seed_user_with("u_second", "second@example.com", true, &system).await;

    let group = ensure_super_user_group(&system_ctx(&system, "ensure_for_multi")).await?;
    let stats = gauge::super_user::seed_super_user_members_from_emails(
        &system_ctx(&system, "seed_multi"),
        &group,
        &[
            "ops@example.com".into(),
            "nobody@example.test".into(),
            "second@example.com".into(),
        ],
    )
    .await?;

    assert_eq!(stats.configured, 3);
    assert_eq!(stats.seeded, 2);
    assert_eq!(stats.missing_user, 1);
    assert_eq!(stats.failed, 0);

    let mut member_ids = Vec::new();
    for rid in group.get_members_record_ids(&system, valence::use_!(r"**Test:** Fixture members edge list for `super_user_scripts_integration` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await? {
        let principal_id = rid.id().to_string();
        if let Some(principal) =
            gauge::generated::PermissionUserPrincipal::get(&principal_id, &system, valence::use_!(r"**Test:** Fixture **Permission User Principal** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await?
        {
            if let Ok(user_id) = valence::extract_id_from_record(principal.user()) {
                member_ids.push(user_id);
            }
        }
    }
    assert!(member_ids.contains(&"u_ops".to_string()));
    assert!(member_ids.contains(&"u_second".to_string()));

    // Idempotent second pass: still seeded, no failures.
    let again = gauge::super_user::seed_super_user_members_from_emails(
        &system_ctx(&system, "seed_multi_again"),
        &group,
        &["ops@example.com".into()],
    )
    .await?;
    assert_eq!(again.seeded, 1);
    assert_eq!(again.missing_user, 0);
    assert_eq!(again.failed, 0);

    Ok(())
}
