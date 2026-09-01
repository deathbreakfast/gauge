#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{seed_user, test_valence};
use gauge::service;
use gauge::types::PermissionGroupCreateInput;
use valence::Actor;

#[tokio::test]
async fn search_registry_dispatches_to_registered_sources() {
    let system = test_valence(Actor::System {
        operation: "search_source_dispatch_test".to_string(),
    })
    .await;

    seed_user("u1", "alice@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });
    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Platform Team".to_string(),
            description: "Platform maintainers".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    let registry = uf_search_core::SearchSourceRegistry::auto_discover();
    let keys = vec![
        gauge::search_sources::PermissionSearchSourceId::User.into(),
        gauge::search_sources::PermissionSearchSourceId::PermissionGroup.into(),
    ];

    let items = registry
        .query_many(&keys, &system, "Platform", 10)
        .await
        .expect("query search sources");

    assert!(
        items
            .iter()
            .any(|item| item.source_id == "permission_group_search_source" && item.id == group_id),
        "expected group source item to be returned"
    );
}

#[tokio::test]
async fn search_registry_no_match_returns_empty_sad() {
    let system = test_valence(Actor::System {
        operation: "search_source_no_match_test".to_string(),
    })
    .await;

    seed_user("u1", "alice@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });
    service::create_group(
        PermissionGroupCreateInput {
            name: "Platform Team".to_string(),
            description: "Platform maintainers".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");

    let registry = uf_search_core::SearchSourceRegistry::auto_discover();
    let keys = vec![
        gauge::search_sources::PermissionSearchSourceId::User.into(),
        gauge::search_sources::PermissionSearchSourceId::PermissionGroup.into(),
    ];

    let items = registry
        .query_many(&keys, &system, "zzz-no-such-principal-needle", 10)
        .await
        .expect("query with no match");

    assert!(
        items.is_empty(),
        "no-match query must return empty vec, got {items:?}"
    );
}
