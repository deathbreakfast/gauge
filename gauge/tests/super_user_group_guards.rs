//! Super User group delete and nesting guards.

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{seed_user_with, test_valence};
use gauge::service::{
    add_group_member_group, create_group, delete_group, remove_group_member_group,
};
use gauge::super_user::{ensure_super_user_group, SUPER_USER_GROUP_ID, SUPER_USER_GROUP_NAME};
use gauge::types::PermissionGroupCreateInput;
use valence::{Actor, Valence};

async fn owner_valence() -> Valence {
    let system = test_valence(Actor::System {
        operation: "super_user_guard_seed".to_string(),
    })
    .await;
    seed_user_with("u_owner", "owner@example.com", true, &system).await;
    ensure_super_user_group(&system)
        .await
        .expect("ensure super");
    system.with_actor(Actor::User {
        user_id: "u_owner".to_string(),
    })
}

#[tokio::test]
async fn create_group_reserved_super_user_name_sad() -> anyhow::Result<()> {
    let v = owner_valence().await;
    let err = create_group(
        PermissionGroupCreateInput {
            name: SUPER_USER_GROUP_NAME.to_string(),
            description: "must not create".to_string(),
        },
        &v,
    )
    .await
    .expect_err("must refuse reserved Super User name");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("reserved for the well-known super-user group"),
        "unexpected error: {msg}"
    );
    Ok(())
}

#[tokio::test]
async fn delete_super_user_group_denied() -> anyhow::Result<()> {
    let v = owner_valence().await;
    let err = delete_group(SUPER_USER_GROUP_ID, &v)
        .await
        .expect_err("must refuse delete of well-known Super User group");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Cannot delete the well-known Super User group"),
        "unexpected error: {msg}"
    );
    Ok(())
}

#[tokio::test]
async fn nest_under_super_user_group_denied() -> anyhow::Result<()> {
    let v = owner_valence().await;
    let child = create_group(
        PermissionGroupCreateInput {
            name: "nest_child".to_string(),
            description: String::new(),
        },
        &v,
    )
    .await?;
    let child_id = child.id().expect("id").id().to_string();

    let err = add_group_member_group(SUPER_USER_GROUP_ID, &child_id, &v)
        .await
        .expect_err("must refuse nesting under Super User");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Cannot nest the well-known Super User group"),
        "unexpected error: {msg}"
    );

    let err = remove_group_member_group(SUPER_USER_GROUP_ID, &child_id, &v)
        .await
        .expect_err("must refuse un-nest involving Super User");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Cannot nest the well-known Super User group"),
        "unexpected error: {msg}"
    );
    Ok(())
}
