#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{seed_user, test_valence};
use gauge::service;
use gauge::types::PermissionGroupCreateInput;
use record_history::RecordHistoryFields;
use valence::{Actor, Model};

#[tokio::test]
async fn history_tracks_description_and_membership_changes() {
    let system = test_valence(Actor::System {
        operation: "permission_history_test_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("member", "member@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "History Group".to_string(),
            description: "original".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");

    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    service::update_group(
        &group_id,
        "History Group".to_string(),
        "updated description".to_string(),
        &owner_ctx,
    )
    .await
    .expect("update group description");

    service::add_group_member_user(&group_id, "member", &owner_ctx)
        .await
        .expect("add member user");

    let history = service::list_history(
        &owner_ctx,
        Some("permission_group".to_string()),
        Some(group_id.clone()),
    )
    .await
    .expect("list history");

    assert!(
        history.iter().any(|entry| {
            entry.action == "update"
                && entry.diffs.iter().any(|d| {
                    d.field == "description"
                        && d.new_value
                            == serde_json::Value::String("updated description".to_string())
                })
        }),
        "expected description update in history"
    );

    assert!(
        history.iter().any(|entry| {
            entry.diffs.iter().any(|d| {
                d.field == "member_users"
                    && d.new_value == serde_json::Value::String("member".to_string())
            })
        }),
        "expected member_users edge add in history"
    );

    // Session actor is stored on the row (session Valence create; no System elevate).
    assert!(
        history.iter().all(|entry| {
            entry
                .actor_user_id
                .as_deref()
                .is_some_and(|id| id == "owner" || id.ends_with(":owner"))
        }),
        "history actor_user_id must be the session owner, got: {:?}",
        history
            .iter()
            .map(|e| e.actor_user_id.clone())
            .collect::<Vec<_>>()
    );

    // Platform history_for_source must see Gauge permission_history via TraitRegistry.
    let source = valence::RecordId::new("permission_group", &group_id);
    let rh_rows = record_history::history_for_source(&source, &owner_ctx)
        .await
        .expect("history_for_source includes permission_history");
    assert!(
        rh_rows.iter().any(|r| {
            r.field_name() == "description"
                && r.new_value() == "updated description"
                && r.id
                    .as_ref()
                    .is_some_and(|id| id.table() == "permission_history")
        }),
        "history_for_source must return permission_history rows for the group source, got: {:?}",
        rh_rows
            .iter()
            .map(|r| (r.field_name().clone(), r.new_value().clone(), r.id.clone()))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn list_history_hides_subjects_outsider_cannot_edit_sad() {
    let system = test_valence(Actor::System {
        operation: "permission_history_outsider_setup".to_string(),
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

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Private History Group".to_string(),
            description: "original".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    service::update_group(
        &group_id,
        "Private History Group".to_string(),
        "secret change".to_string(),
        &owner_ctx,
    )
    .await
    .expect("update group");

    let owner_rows = service::list_history(
        &owner_ctx,
        Some("permission_group".to_string()),
        Some(group_id.clone()),
    )
    .await
    .expect("owner history");
    assert!(
        !owner_rows.is_empty(),
        "owner should see history for owned group"
    );

    let outsider_rows = service::list_history(
        &outsider_ctx,
        Some("permission_group".to_string()),
        Some(group_id),
    )
    .await
    .expect("outsider history");
    assert!(
        outsider_rows.is_empty(),
        "outsider must not see history for groups they cannot edit"
    );
}

#[tokio::test]
async fn delete_group_keeps_session_actor_on_deleted_history() {
    use gauge::generated::PermissionHistory;

    let system = test_valence(Actor::System {
        operation: "permission_history_delete_actor_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Delete Actor Group".to_string(),
            description: "to be deleted".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    service::delete_group(&group_id, &owner_ctx)
        .await
        .expect("delete group");

    // Soft-delete keeps history until DAG finalize; harness uses noop dispatcher.
    // Query rows directly: list_history can-edit gates hide subjects after delete.
    let rows = PermissionHistory::query(&system, valence::use_!(r"**Test:** Fixture **Permission History** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("query permission_history");
    let deleted = rows
        .iter()
        .find(|row| row.source().id() == group_id && row.field_name() == "deleted");
    let deleted = deleted.expect("expected deleted lifecycle history row");
    let actor_id = deleted
        .actor()
        .and_then(|r| valence::extract_id_from_record(r).ok());
    assert!(
        actor_id
            .as_deref()
            .is_some_and(|id| id == "owner" || id.ends_with(":owner")),
        "deleted history must keep session actor, got: {actor_id:?}"
    );
}

/// Documents the Show History page ACL: `get_gauge_history_page` denies when
/// [`service::actor_can_view_history_subject`] is false (can-edit on the source).
#[tokio::test]
async fn actor_can_view_history_subject_denies_outsider_page_acl_sad() {
    let system = test_valence(Actor::System {
        operation: "permission_history_page_acl_setup".to_string(),
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

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Page ACL Group".to_string(),
            description: "acl".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    assert!(
        service::actor_can_view_history_subject("permission_group", &group_id, &owner_ctx)
            .await
            .expect("owner can-view check"),
        "owner must pass history page ACL (can-edit)"
    );
    assert!(
        !service::actor_can_view_history_subject("permission_group", &group_id, &outsider_ctx)
            .await
            .expect("outsider can-view check"),
        "outsider must fail history page ACL (actor_can_view_history_subject false → deny)"
    );
}

/// SM-24: `list_history` must not return more than [`service::MAX_HISTORY_LIST_ROWS`]
/// even when many history rows exist for one subject (DB-side `.limit`).
#[tokio::test]
async fn list_history_caps_at_max_history_list_rows() {
    use gauge::generated::PermissionHistory;
    use gauge::service::MAX_HISTORY_LIST_ROWS;

    let system = test_valence(Actor::System {
        operation: "permission_history_cap_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Cap History Group".to_string(),
            description: "seed".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = group
        .id()
        .and_then(|t| valence::extract_id_from_record(t).ok())
        .expect("group id");

    let source = valence::RecordId::new("permission_group", &group_id);
    let overflow = MAX_HISTORY_LIST_ROWS + 25;
    for i in 0..overflow {
        let row = PermissionHistory::new(
            source.clone(),
            "description".to_string(),
            format!("old-{i}"),
            format!("new-{i}"),
            chrono::Utc::now(),
            Some(valence::RecordId::new("user", "owner")),
        )
        .expect("history row");
        PermissionHistory::create(row, &owner_ctx, valence::use_!(r"**Test:** Fixture **Permission History** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .await
            .unwrap_or_else(|e| panic!("create history row {i}: {e}"));
    }

    let listed = service::list_history(
        &owner_ctx,
        Some("permission_group".to_string()),
        Some(group_id),
    )
    .await
    .expect("list history");
    assert!(
        listed.len() <= MAX_HISTORY_LIST_ROWS,
        "list_history must hard-cap at {MAX_HISTORY_LIST_ROWS}, got {}",
        listed.len()
    );
    assert_eq!(
        listed.len(),
        MAX_HISTORY_LIST_ROWS,
        "expected full page of {MAX_HISTORY_LIST_ROWS} when more rows exist"
    );
}

fn removed_ids(history: &[gauge::types::HistoryEntryDto], field: &str) -> Vec<Vec<String>> {
    history
        .iter()
        .flat_map(|e| e.diffs.iter())
        .filter(|d| d.field == field && d.new_value.is_null())
        .map(|d| {
            let text = d.old_value.as_str().expect("history text");
            let mut ids: Vec<String> = serde_json::from_str(text).expect("id array");
            ids.sort();
            ids
        })
        .collect()
}

#[tokio::test]
async fn clear_members_records_removed_ids_once_and_is_idempotent() {
    let system = test_valence(Actor::System {
        operation: "clear_history_setup".to_string(),
    })
    .await;
    for id in ["owner", "m1", "m2", "n1"] {
        seed_user(id, &format!("{id}@example.com"), &system).await;
    }
    let owner = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let input = |name: &str| PermissionGroupCreateInput {
        name: name.to_string(),
        description: String::new(),
    };
    let group_id = valence::extract_id_from_record(
        service::create_group_owner_only(input("Clear Me"), &owner)
            .await
            .expect("group")
            .id()
            .expect("id"),
    )
    .expect("pk");
    let nested_id = valence::extract_id_from_record(
        service::create_group_owner_only(input("Nested"), &owner)
            .await
            .expect("nested")
            .id()
            .expect("id"),
    )
    .expect("pk");
    service::add_group_member_user(&group_id, "m1", &owner)
        .await
        .unwrap();
    service::add_group_member_user(&group_id, "m2", &owner)
        .await
        .unwrap();
    service::add_group_member_group(&group_id, &nested_id, &owner)
        .await
        .unwrap();

    // Empty group: nothing to remove, nothing written.
    let empty = service::create_group_owner_only(input("Empty"), &owner)
        .await
        .unwrap();
    let empty_id = valence::extract_id_from_record(empty.id().unwrap()).unwrap();
    assert_eq!(
        service::clear_group_members(&empty_id, &owner)
            .await
            .unwrap(),
        0
    );
    let empty_history =
        service::list_history(&owner, Some("permission_group".into()), Some(empty_id))
            .await
            .unwrap();
    assert!(removed_ids(&empty_history, "member_users").is_empty());

    assert_eq!(
        service::clear_group_members(&group_id, &owner)
            .await
            .unwrap(),
        3
    );
    let history = service::list_history(
        &owner,
        Some("permission_group".into()),
        Some(group_id.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        removed_ids(&history, "member_users"),
        vec![vec!["m1".to_string(), "m2".to_string()]]
    );
    assert_eq!(
        removed_ids(&history, "member_groups"),
        vec![vec![nested_id]]
    );
    assert!(removed_ids(&history, "member_service_users").is_empty());
    for entry in history.iter().filter(|e| {
        e.diffs.iter().any(|d| {
            d.new_value.is_null() && d.old_value.as_str().is_some_and(|s| s.starts_with('['))
        })
    }) {
        assert_eq!(
            entry
                .actor_user_id
                .as_deref()
                .map(|id| id.trim_start_matches("user:")),
            Some("owner")
        );
    }

    // A second clear removes nothing and writes nothing.
    assert_eq!(
        service::clear_group_members(&group_id, &owner)
            .await
            .unwrap(),
        0
    );
    let again = service::list_history(&owner, Some("permission_group".into()), Some(group_id))
        .await
        .unwrap();
    assert_eq!(again.len(), history.len());
}
