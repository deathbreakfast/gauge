#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{record_pk_id, seed_user, test_valence};
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
    PermissionRequestCreateInput, PermissionRequestDecision, PermissionRequestDecisionInput,
    PermissionRequestTargetKind,
};
use serde::Deserialize;
use valence::{Actor, RecordId, RecordPredicate, SortDirection, StringPredicate, Valence};

#[derive(Debug, Deserialize)]
struct NotificationRow {
    user: RecordId,
    kind: String,
    title: String,
    message: String,
    url: Option<String>,
}

async fn permission_request_notifications_for_user(
    v: &Valence,
    user_id: &str,
) -> anyhow::Result<Vec<NotificationRow>> {
    let lookup = v.with_actor(Actor::System {
        operation: "gauge_notification_test_query".to_string(),
    });
    let rows = uf_notifications_core::generated::Notification::query(&lookup)
        .where_user(RecordPredicate::Equals(RecordId::new("user", user_id)))
        .where_kind(StringPredicate::Equals("permission_request".to_string()))
        .order_by_created_at(SortDirection::Desc)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| NotificationRow {
            user: row.user().clone(),
            kind: row.kind().clone(),
            title: row.title().clone(),
            message: row.message().clone(),
            url: row.url().cloned(),
        })
        .collect())
}

#[tokio::test]
async fn create_permission_request_notifies_permission_owners() -> anyhow::Result<()> {
    let system = test_valence(Actor::System {
        operation: "permission_request_create_notify_test".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("requestor", "requestor@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let requestor_ctx = system.with_actor(Actor::User {
        user_id: "requestor".to_string(),
    });

    let owners_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Permission Owners".to_string(),
            description: "owners".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let owners_group_id = record_pk_id(owners_group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Delivery".to_string(),
            description: "delivery permissions".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "Deploy".to_string(),
            description: "Allow deploys".to_string(),
            owners_group_id,
            domain_id,
        },
        &owner_ctx,
    )
    .await?;
    let permission_id = record_pk_id(permission.id());

    let request = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: permission_id.clone(),
            reason: "Need deploy access".to_string(),
        },
        &requestor_ctx,
    )
    .await?;

    let owner_notifications = permission_request_notifications_for_user(&system, "owner").await?;
    assert_eq!(
        owner_notifications.len(),
        1,
        "owner should receive one create notification"
    );

    let created = &owner_notifications[0];
    assert_eq!(created.user.table(), "user");
    assert_eq!(created.kind, "permission_request");
    assert_eq!(created.title, "Permission request submitted");
    assert!(
        created
            .message
            .contains(&format!("permission:{permission_id}.")),
        "notification should include target record id"
    );
    let expected_url = format!("/permission/requests/{}", request.id);
    assert_eq!(created.url.as_deref(), Some(expected_url.as_str()));

    Ok(())
}

#[tokio::test]
async fn create_permission_request_does_not_notify_non_owners_sad() -> anyhow::Result<()> {
    let system = test_valence(Actor::System {
        operation: "permission_request_notify_containment_test".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("requestor", "requestor@example.com", &system).await;
    seed_user("outsider", "outsider@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let requestor_ctx = system.with_actor(Actor::User {
        user_id: "requestor".to_string(),
    });

    let owners_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Notify Owners".to_string(),
            description: "owners".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let owners_group_id = record_pk_id(owners_group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Notify Domain".to_string(),
            description: "notify".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "NotifyPerm".to_string(),
            description: "notify".to_string(),
            owners_group_id,
            domain_id,
        },
        &owner_ctx,
    )
    .await?;
    let permission_id = record_pk_id(permission.id());

    service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Permission,
            target_id: permission_id,
            reason: "Need access".to_string(),
        },
        &requestor_ctx,
    )
    .await?;

    let owner_notifications = permission_request_notifications_for_user(&system, "owner").await?;
    assert_eq!(owner_notifications.len(), 1, "owner must be notified");

    let outsider_notifications =
        permission_request_notifications_for_user(&system, "outsider").await?;
    assert!(
        outsider_notifications.is_empty(),
        "non-owner must not receive create notifications: {outsider_notifications:?}"
    );

    let requestor_notifications =
        permission_request_notifications_for_user(&system, "requestor").await?;
    assert!(
        requestor_notifications.is_empty(),
        "requestor must not receive create-fanout owner notifications: {requestor_notifications:?}"
    );

    Ok(())
}

#[tokio::test]
#[allow(clippy::similar_names)]
async fn decide_permission_request_notifies_requestor_for_terminal_statuses() -> anyhow::Result<()>
{
    let system = test_valence(Actor::System {
        operation: "permission_request_decision_notify_test".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("requestor", "requestor@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let requestor_ctx = system.with_actor(Actor::User {
        user_id: "requestor".to_string(),
    });

    let group_a = service::create_group(
        PermissionGroupCreateInput {
            name: "Team Alpha".to_string(),
            description: "group A".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let group_a_id = record_pk_id(group_a.id());

    let request_a = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Group,
            target_id: group_a_id,
            reason: "Need access to alpha".to_string(),
        },
        &requestor_ctx,
    )
    .await?;
    service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: request_a.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &owner_ctx,
    )
    .await?;

    let group_b = service::create_group(
        PermissionGroupCreateInput {
            name: "Team Beta".to_string(),
            description: "group B".to_string(),
        },
        &owner_ctx,
    )
    .await?;
    let group_b_id = record_pk_id(group_b.id());

    let request_b = service::create_permission_request(
        PermissionRequestCreateInput {
            target_kind: PermissionRequestTargetKind::Group,
            target_id: group_b_id,
            reason: "Need access to beta".to_string(),
        },
        &requestor_ctx,
    )
    .await?;
    service::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: request_b.id.clone(),
            decision: PermissionRequestDecision::Deny,
        },
        &owner_ctx,
    )
    .await?;

    let requestor_notifications =
        permission_request_notifications_for_user(&system, "requestor").await?;
    let decision_notifications: Vec<&NotificationRow> = requestor_notifications
        .iter()
        .filter(|n| n.title == "Permission request updated")
        .collect();
    assert_eq!(
        decision_notifications.len(),
        2,
        "requestor should receive one notification per decision"
    );

    assert!(
        decision_notifications
            .iter()
            .any(|n| n.message == "Your permission request was approved."
                && n.url.as_deref() == Some(&format!("/permission/requests/{}", request_a.id))),
        "expected approved decision notification"
    );
    assert!(
        decision_notifications
            .iter()
            .any(|n| n.message == "Your permission request was denied."
                && n.url.as_deref() == Some(&format!("/permission/requests/{}", request_b.id))),
        "expected denied decision notification"
    );

    Ok(())
}
