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

    let groups = PermissionGroup::query(&system)
        .where_name(StringPredicate::Equals(SUPER_USER_GROUP_NAME.to_string()))
        .await?;
    assert_eq!(
        groups.len(),
        1,
        "script should enforce singleton super group"
    );
    let group = groups.first().expect("super group exists");

    let mut owner_ids = Vec::new();
    for rid in group.get_owners_record_ids(&system).await? {
        let principal_id = rid.id().to_string();
        if principal_id.is_empty() {
            continue;
        }
        if let Some(principal) =
            gauge::generated::PermissionUserPrincipal::get(&principal_id, &system).await?
        {
            if let Ok(user_id) = valence::extract_id_from_record(principal.user()) {
                owner_ids.push(user_id);
            }
        }
    }
    let mut member_ids = Vec::new();
    for rid in group.get_members_record_ids(&system).await? {
        let principal_id = rid.id().to_string();
        if principal_id.is_empty() {
            continue;
        }
        if let Some(principal) =
            gauge::generated::PermissionUserPrincipal::get(&principal_id, &system).await?
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

    let members = group.get_members_record_ids(&system).await?;
    assert!(
        members.is_empty(),
        "failed email seed must not invent membership: {members:?}"
    );

    Ok(())
}
