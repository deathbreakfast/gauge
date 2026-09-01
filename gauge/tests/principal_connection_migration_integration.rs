#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use chrono::Utc;
use common::{record_pk_id, seed_user, test_valence};
use gauge::scripts::migrate_principal_connections::migrate_permission_principal_connections_with_valence;
use gauge::service;
use gauge::super_user::SUPER_USER_GROUP_NAME;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
    PermissionRequestCreateInput, PermissionRequestDecision, PermissionRequestDecisionInput,
    PermissionRequestTargetKind,
};
use valence::{Actor, Model, RecordId, Valence};

async fn harness_valence(actor: Actor) -> Valence {
    gauge::touch_schema_inventory();
    test_valence(actor).await
}

fn system_ctx(v: &Valence, operation: &str) -> Valence {
    v.with_actor(Actor::System {
        operation: operation.to_string(),
    })
}

fn parse_record(record: &str) -> anyhow::Result<RecordId> {
    let (table, id) = record
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid record id: {record}"))?;
    Ok(RecordId::new(table, id))
}

async fn edge_count(v: &Valence, edge_table: &str, from: &str, to: &str) -> anyhow::Result<usize> {
    let from_record = parse_record(from)?;
    let to_record = parse_record(to)?;
    let targets = v
        .get_many_to_many_target_record_ids(&from_record, edge_table)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(targets
        .iter()
        .filter(|t| t.table() == to_record.table() && t.id() == to_record.id())
        .count())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn migration_script_backfills_principal_edges_idempotently() -> anyhow::Result<()> {
    let system = harness_valence(Actor::System {
        operation: "permission_principal_migration_test".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("member", "member@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Legacy Members".to_string(),
            description: "legacy membership source".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let group_id = record_pk_id(group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Legacy".to_string(),
            description: "legacy migration scope".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "Legacy Granted".to_string(),
            description: "legacy permission edge source".to_string(),
            owners_group_id: group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &owner_ctx,
    )
    .await?;
    let permission_id = record_pk_id(permission.id());

    // Simulate pre-migration legacy edges only.
    system
        .relate_edge(
            "permission_group_member_user",
            &RecordId::new("permission_group", group_id.as_str()),
            &RecordId::new("user", "member"),
        )
        .await?;
    system
        .relate_edge(
            "permission_group_owner_user",
            &RecordId::new("permission_group", group_id.as_str()),
            &RecordId::new("user", "owner"),
        )
        .await?;
    system
        .relate_edge(
            "permission_allowed_user",
            &RecordId::new("permission", permission_id.as_str()),
            &RecordId::new("user", "member"),
        )
        .await?;

    assert!(
        !service::user_can(&system, "member", "Legacy Granted").await?,
        "without migration, new principal-path checks should not resolve legacy edges"
    );

    migrate_permission_principal_connections_with_valence(&system_ctx(&system, "migrate_1"))
        .await?;
    migrate_permission_principal_connections_with_valence(&system_ctx(&system, "migrate_2"))
        .await?;

    assert!(
        service::user_can(&system, "member", "Legacy Granted").await?,
        "after migration, principal edges should grant the permission"
    );

    let from_permission = format!("permission:{permission_id}");
    let from_group = format!("permission_group:{group_id}");
    let to_user_principal = "permission_user_principal:user:member".to_string();

    assert_eq!(
        edge_count(
            &system,
            "permission_allowed_principal",
            &from_permission,
            &to_user_principal,
        )
        .await?,
        1,
        "permission principal edge should be present once after idempotent reruns"
    );
    assert_eq!(
        edge_count(
            &system,
            "permission_group_member_principal",
            &from_group,
            &to_user_principal,
        )
        .await?,
        1,
        "group principal edge should be present once after idempotent reruns"
    );
    assert_eq!(
        edge_count(
            &system,
            "permission_group_owner_principal",
            &from_group,
            "permission_user_principal:user:owner",
        )
        .await?,
        1,
        "group owner principal edge should be present once after idempotent reruns"
    );

    Ok(())
}

#[tokio::test]
async fn migration_fails_when_legacy_user_edge_targets_missing_user_sad() -> anyhow::Result<()> {
    let system = harness_valence(Actor::System {
        operation: "permission_principal_migration_missing_user".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Ghost Edge Group".to_string(),
            description: "migration sad".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let group_id = record_pk_id(group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Ghost Domain".to_string(),
            description: "migration sad".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let domain_id = record_pk_id(domain.id());
    let permission = service::create_permission(
        PermissionCreateInput {
            name: "Ghost Perm".to_string(),
            description: "migration sad".to_string(),
            owners_group_id: group_id,
            domain_id,
        },
        &owner_ctx,
    )
    .await?;
    let permission_id = record_pk_id(permission.id());

    system
        .relate_edge(
            "permission_allowed_user",
            &RecordId::new("permission", permission_id.as_str()),
            &RecordId::new("user", "ghost_missing_user"),
        )
        .await?;

    let err = migrate_permission_principal_connections_with_valence(&system_ctx(
        &system,
        "migrate_missing_user",
    ))
    .await
    .expect_err("missing legacy user must fail migration");
    let msg = err.to_string();
    assert!(msg.contains("User not found during migration"), "got {msg}");

    let principal_edges = edge_count(
        &system,
        "permission_allowed_principal",
        &format!("permission:{permission_id}"),
        "permission_user_principal:user:ghost_missing_user",
    )
    .await?;
    assert_eq!(
        principal_edges, 0,
        "failed migration must not create principal edge for missing user"
    );
    assert!(
        !service::user_can(&system, "ghost_missing_user", "Ghost Perm").await?,
        "missing user must not gain access after failed migration"
    );

    Ok(())
}

#[tokio::test]
async fn super_user_review_queue_hidden_but_direct_approval_allowed() -> anyhow::Result<()> {
    let system = harness_valence(Actor::System {
        operation: "permission_super_review_visibility_test".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("requestor", "requestor@example.com", &system).await;
    seed_user("super", "super@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let requestor_ctx = system.with_actor(Actor::User {
        user_id: "requestor".to_string(),
    });
    let super_ctx = system.with_actor(Actor::User {
        user_id: "super".to_string(),
    });

    // Create super-user group and add "super" as owner/member.
    let super_group = gauge::generated::PermissionGroup::upsert(
        "super_user_group",
        gauge::generated::PermissionGroup::new(
            SUPER_USER_GROUP_NAME.to_string(),
            Some("super users".to_string()),
            Utc::now(),
            Utc::now(),
        )?,
        &system,
    )
    .await?;
    let super_user = lepton::generated::User::get("super", &system)
        .await?
        .expect("super user exists");
    let super_principal = gauge::generated::PermissionUserPrincipal::upsert(
        "user:super",
        gauge::generated::PermissionUserPrincipal::new(
            super_user.id().expect("super id exists").clone(),
            "super".to_string(),
        )?,
        &system,
    )
    .await?;
    super_group
        .relate_to_owner_record(super_principal.id().expect("principal id exists"), &system)
        .await?;
    super_group
        .relate_to_member_record(super_principal.id().expect("principal id exists"), &system)
        .await?;

    let owners_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Request Target Owners".to_string(),
            description: "owners".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let owners_group_id = record_pk_id(owners_group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Queue Visibility".to_string(),
            description: "domain for review queue test".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "Review Visibility".to_string(),
            description: "target permission".to_string(),
            owners_group_id,
            domain_id,
        },
        &owner_ctx,
    )
    .await?;

    let request = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: record_pk_id(permission.id()),
            reason: "Need access".to_string(),
        },
        &requestor_ctx,
    )
    .await?;

    let review_rows = service::list_permission_requests_for_review(&super_ctx).await?;
    assert!(
        review_rows.is_empty(),
        "super user queue should be empty by design"
    );

    let decided = service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: request.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &super_ctx,
    )
    .await?;
    assert_eq!(
        decided.status,
        gauge::types::PermissionRequestStatusDto::Approved
    );

    Ok(())
}
