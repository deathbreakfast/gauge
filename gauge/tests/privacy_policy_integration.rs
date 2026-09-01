#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use chrono::Utc;
use common::{seed_group_with_owner, seed_super_user_group_with_member, seed_user, test_valence};
use gauge::generated::{Permission, PermissionDomain, PermissionGroup, PermissionHistory};
use gauge::service;
use valence::{
    Actor, Model, PrivacyEvaluator, PrivacyOperation, QueryCore, SchemaRegistry, Valence,
};

async fn setup_valence() -> valence::Result<Valence> {
    Ok(test_valence(Actor::System {
        operation: "permission_policy_tests".to_string(),
    })
    .await)
}

fn user_ctx(v: &Valence, user_id: &str) -> Valence {
    let actor_user_id = user_id.strip_prefix("user:").unwrap_or(user_id).to_string();
    v.with_actor(Actor::User {
        user_id: actor_user_id,
    })
}

async fn seed_permission_owned_by_group(
    system: &Valence,
    permission_id: &str,
    owners_group_id: &str,
) -> anyhow::Result<Permission> {
    let domain = PermissionDomain::upsert(
        "domain_policy",
        PermissionDomain::new(
            false,
            None,
            "Privacy Policy Domain".to_string(),
            Some("domain for privacy policy tests".to_string()),
            Utc::now(),
            Utc::now(),
        )?,
        system,
    )
    .await?;
    let now = Utc::now();
    let permission = Permission::new(
        valence::RecordId::new("user", "owner_u1"),
        valence::RecordId::new("permission_group", owners_group_id),
        domain.id().expect("domain id exists").clone(),
        format!("perm-{permission_id}"),
        Some("permission for privacy tests".to_string()),
        now,
        now,
    )?;
    let created = Permission::upsert(permission_id, permission, system).await?;
    Ok(created)
}

async fn seed_permission_history_on_permission(
    owner_v: &Valence,
    history_id: &str,
    permission_id: &str,
    actor_user: &str,
) -> anyhow::Result<()> {
    let history = PermissionHistory::new(
        valence::RecordId::new("permission", permission_id),
        "description".to_string(),
        "old".to_string(),
        "new".to_string(),
        Utc::now(),
        Some(valence::RecordId::new("user", actor_user)),
    )?;
    PermissionHistory::upsert(history_id, history, owner_v).await?;
    Ok(())
}

async fn seed_permission_history_on_group(
    owner_v: &Valence,
    history_id: &str,
    group_id: &str,
    actor_user: &str,
) -> anyhow::Result<()> {
    let history = PermissionHistory::new(
        valence::RecordId::new("permission_group", group_id),
        "description".to_string(),
        "old".to_string(),
        "new".to_string(),
        Utc::now(),
        Some(valence::RecordId::new("user", actor_user)),
    )?;
    PermissionHistory::upsert(history_id, history, owner_v).await?;
    Ok(())
}

async fn ensure_super_user(system: &Valence, member_user_id: &str) {
    seed_user(
        member_user_id,
        &format!("{member_user_id}@example.test"),
        system,
    )
    .await;
    seed_super_user_group_with_member(system, member_user_id).await;
}

fn assert_privacy_denied(err: impl std::fmt::Display, context: &str) {
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("privac") || msg.contains("denied") || msg.contains("not authorized"),
        "{context}: expected privacy/denied classification, got `{msg}`"
    );
}

#[tokio::test]
async fn permission_group_policy_allows_owner_denies_non_owner_tm_sec_01_02() -> anyhow::Result<()>
{
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let non_owner_user = "other_u2";
    let group_id = "pg_policy_1";

    let group = seed_group_with_owner(&system, group_id, owner_user).await;
    seed_user(
        non_owner_user,
        &format!("{non_owner_user}@example.test"),
        &system,
    )
    .await;
    let schema = SchemaRegistry::global()
        .get_schema("permission_group")
        .expect("permission_group schema registered");
    let raw = QueryCore::get_record_json("permission_group", group_id, &system)
        .await?
        .expect("group record");

    let owner_v = user_ctx(&system, owner_user);
    let non_owner_v = user_ctx(&system, non_owner_user);

    assert!(service::can_edit_group(&group, &owner_v).await?);
    assert!(!service::can_edit_group(&group, &non_owner_v).await?);

    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &owner_v)
        .await
        .expect("TM-SEC-01 owner Valence update allowed");
    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Delete, &raw, &owner_v)
        .await
        .expect("TM-SEC-01 owner Valence delete allowed");

    assert_privacy_denied(
        PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &non_owner_v)
            .await
            .expect_err("TM-SEC-02 non-owner update"),
        "non-owner Valence group update",
    );
    assert_privacy_denied(
        PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Delete, &raw, &non_owner_v)
            .await
            .expect_err("TM-SEC-02 non-owner delete"),
        "non-owner Valence group delete",
    );

    Ok(())
}

#[tokio::test]
async fn permission_policy_enforces_model_mutation_paths_tm_sec_01_02() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let non_owner_user = "other_u2";

    let group_id = "pg_policy_2";
    seed_group_with_owner(&system, group_id, owner_user).await;
    seed_permission_owned_by_group(&system, "perm_policy_2", group_id).await?;
    seed_user(
        non_owner_user,
        &format!("{non_owner_user}@example.test"),
        &system,
    )
    .await;

    let owner_v = user_ctx(&system, owner_user);
    let non_owner_v = user_ctx(&system, non_owner_user);

    let existing = PermissionGroup::get(group_id, &system)
        .await?
        .expect("group exists");

    let owner_update = existing
        .clone()
        .get_mutable(&owner_v)
        .set_name("owner-updated-group".to_string())?
        .commit()
        .await
        .expect("TM-SEC-01 owner direct group mutate");
    assert_eq!(owner_update.name(), "owner-updated-group");
    assert!(
        matches!(owner_v.actor(), Actor::User { .. }),
        "session actor must remain User after mutate"
    );

    let non_owner_update = existing
        .get_mutable(&non_owner_v)
        .set_name("hijacked-group".to_string())?
        .commit()
        .await;
    assert_privacy_denied(
        non_owner_update.expect_err("non-owner direct mutate"),
        "TM-SEC-02 non-owner direct group mutate",
    );

    let after_denied = PermissionGroup::get(group_id, &system)
        .await?
        .expect("group remains");
    assert_eq!(
        after_denied.name(),
        "owner-updated-group",
        "non-owner mutate must not change name"
    );

    let non_owner_delete_permission = Permission::delete("perm_policy_2", &non_owner_v).await;
    assert_privacy_denied(
        non_owner_delete_permission.expect_err("non-owner delete"),
        "TM-SEC-02 non-owner permission delete",
    );

    // Owner is allowed by Valence Delete on `permission`; history cascade uses
    // delete `defer_to_edge` under the same session actor (no System elevate).
    let schema = SchemaRegistry::global()
        .get_schema("permission")
        .expect("permission schema");
    let raw = QueryCore::get_record_json("permission", "perm_policy_2", &system)
        .await?
        .expect("permission record");
    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Delete, &raw, &owner_v)
        .await
        .expect("TM-SEC-01 owner Valence delete allowed");

    gauge::side_effects::history_logger::delete_history_source(
        "permission",
        "perm_policy_2",
        &owner_v,
    )
    .await
    .expect("TM-SEC-01 owner permission delete via history cascade helper");

    match Permission::get("perm_policy_2", &system).await {
        Ok(None) => {}
        Err(err) if err.to_string().to_lowercase().contains("pending deletion") => {}
        Ok(Some(_)) => panic!("owner delete must remove permission"),
        Err(err) => return Err(err.into()),
    }

    Ok(())
}

#[tokio::test]
async fn permission_create_allowed_for_authenticated_and_denied_for_anonymous() -> anyhow::Result<()>
{
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let group_id = "pg_policy_create_1";

    // Seed owner identity to satisfy foreign-key constraints for created_by.
    seed_group_with_owner(&system, group_id, owner_user).await;
    PermissionDomain::upsert(
        "domain_policy",
        PermissionDomain::new(
            false,
            None,
            "Privacy Policy Domain".to_string(),
            Some("domain for privacy policy tests".to_string()),
            Utc::now(),
            Utc::now(),
        )?,
        &system,
    )
    .await?;

    let owner_v = user_ctx(&system, owner_user);
    let anonymous_v = system.with_actor(Actor::Anonymous);

    let create_group = PermissionGroup::new(
        "created-by-auth-user".to_string(),
        Some("created through authenticated actor".to_string()),
        Utc::now(),
        Utc::now(),
    )?;
    let group_created = PermissionGroup::create(create_group, &owner_v).await?;
    assert_eq!(group_created.name(), "created-by-auth-user");

    let permission = Permission::new(
        valence::RecordId::new("user", owner_user),
        valence::RecordId::new("permission_group", group_id),
        valence::RecordId::new("permission_domain", "domain_policy"),
        "perm-create-auth".to_string(),
        Some("auth create".to_string()),
        Utc::now(),
        Utc::now(),
    )?;
    let permission_created = Permission::create(permission, &owner_v).await?;
    assert_eq!(permission_created.name(), "perm-create-auth");

    let permission_anon = Permission::new(
        valence::RecordId::new("user", owner_user),
        valence::RecordId::new("permission_group", group_id),
        valence::RecordId::new("permission_domain", "domain_policy"),
        "perm-create-anon".to_string(),
        Some("anon create".to_string()),
        Utc::now(),
        Utc::now(),
    )?;
    let permission_created_anon = Permission::create(permission_anon, &anonymous_v).await;
    assert_privacy_denied(
        permission_created_anon.expect_err("anon create"),
        "anonymous permission create",
    );

    Ok(())
}

#[tokio::test]
async fn permission_history_update_delete_peer_denied_owner_allowed() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let outsider_user = "outsider_hist_upd";
    let group_id = "pg_hist_upd_1";
    let record_id = "ph_upd_deny_1";

    seed_group_with_owner(&system, group_id, owner_user).await;
    seed_permission_owned_by_group(&system, "perm_hist_upd_1", group_id).await?;
    seed_user(
        outsider_user,
        &format!("{outsider_user}@example.test"),
        &system,
    )
    .await;

    let owner_v = user_ctx(&system, owner_user);
    let outsider_v = user_ctx(&system, outsider_user);
    seed_permission_history_on_permission(&owner_v, record_id, "perm_hist_upd_1", owner_user)
        .await?;

    let schema = SchemaRegistry::global()
        .get_schema("permission_history")
        .expect("permission_history schema registered");
    let raw = QueryCore::get_record_json("permission_history", record_id, &system)
        .await?
        .expect("history record exists");

    assert_privacy_denied(
        PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &outsider_v)
            .await
            .expect_err("outsider history update"),
        "outsider history update",
    );
    assert_privacy_denied(
        PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Delete, &raw, &outsider_v)
            .await
            .expect_err("outsider history delete"),
        "outsider history delete",
    );

    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &owner_v)
        .await
        .expect("owner history update via defer→parent Update");
    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Delete, &raw, &owner_v)
        .await
        .expect("owner history delete via defer→parent Delete");

    Ok(())
}

#[tokio::test]
async fn super_user_policy_allows_permission_group_and_permission_mutations() -> anyhow::Result<()>
{
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let super_user = "super_u9";
    let group_id = "pg_super_policy_1";

    let group = seed_group_with_owner(&system, group_id, owner_user).await;
    ensure_super_user(&system, super_user).await;
    seed_permission_owned_by_group(&system, "perm_super_policy_1", group_id).await?;

    let super_user_v = user_ctx(&system, super_user);

    let super_group_update = group
        .get_mutable(&super_user_v)
        .set_name("super-user-updated-group".to_string())?
        .commit()
        .await
        .expect("TM-SEC-01 Super User Valence group mutate");
    assert_eq!(super_group_update.name(), "super-user-updated-group");

    let existing_permission = Permission::get("perm_super_policy_1", &system)
        .await?
        .expect("permission exists");
    let super_permission_update = existing_permission
        .get_mutable(&super_user_v)
        .set_name("super-user-updated-permission".to_string())?
        .commit()
        .await
        .expect("TM-SEC-01 Super User Valence permission mutate");
    assert_eq!(
        super_permission_update.name(),
        "super-user-updated-permission"
    );

    Ok(())
}

#[tokio::test]
async fn super_user_can_update_delete_permission_history_via_parent_happy() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let super_user = "super_u10";
    let group_id = "pg_hist_super_1";
    let record_id = "ph_super_upd_1";

    seed_group_with_owner(&system, group_id, owner_user).await;
    seed_permission_owned_by_group(&system, "perm_hist_super_1", group_id).await?;
    ensure_super_user(&system, super_user).await;

    let owner_v = user_ctx(&system, owner_user);
    seed_permission_history_on_permission(&owner_v, record_id, "perm_hist_super_1", owner_user)
        .await?;

    let schema = SchemaRegistry::global()
        .get_schema("permission_history")
        .expect("permission_history schema registered");
    let raw = QueryCore::get_record_json("permission_history", record_id, &system)
        .await?
        .expect("history record exists");
    let super_user_v = user_ctx(&system, super_user);

    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &super_user_v)
        .await
        .expect("Super User history update via defer→parent Update");
    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Delete, &raw, &super_user_v)
        .await
        .expect("Super User history delete via defer→parent Delete");

    Ok(())
}

#[tokio::test]
async fn permission_request_update_maintainer_only_tm_sec_05() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let outsider_user = "outsider_u3";
    let group_id = "pg_req_policy_1";

    seed_group_with_owner(&system, group_id, owner_user).await;
    seed_user(
        outsider_user,
        &format!("{outsider_user}@example.test"),
        &system,
    )
    .await;
    seed_permission_owned_by_group(&system, "perm_req_policy_1", group_id).await?;

    let owner_v = user_ctx(&system, owner_user);
    let outsider_v = user_ctx(&system, outsider_user);
    let request = service::create_permission_request(
        gauge::types::PermissionRequestCreateInput {
            target_kind: gauge::types::PermissionRequestTargetKind::Permission,
            target_id: "perm_req_policy_1".to_string(),
            reason: "need access".to_string(),
        },
        &outsider_v,
    )
    .await?;

    let schema = SchemaRegistry::global()
        .get_schema("permission_request")
        .expect("permission_request schema registered");
    let raw = QueryCore::get_record_json("permission_request", &request.id, &system)
        .await?
        .expect("request record");

    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &owner_v)
        .await
        .expect("TM-SEC-05 target maintainer Valence update");

    assert_privacy_denied(
        PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &outsider_v)
            .await
            .expect_err("requestor update"),
        "requestor is not REQUEST_TARGET_MAINTAINER",
    );

    let loaded = gauge::generated::PermissionRequest::get(&request.id, &system)
        .await?
        .expect("loaded under system");
    let outsider_commit = loaded
        .clone()
        .get_mutable(&outsider_v)
        .set_status(gauge::generated::PermissionRequestStatus::Approved)?
        .commit()
        .await;
    assert_privacy_denied(
        outsider_commit.expect_err("outsider approve mutate"),
        "outsider direct request approve",
    );

    loaded
        .get_mutable(&owner_v)
        .set_status(gauge::generated::PermissionRequestStatus::Denied)?
        .commit()
        .await
        .expect("TM-SEC-05 maintainer session decide via Valence");

    let decided = gauge::generated::PermissionRequest::get(&request.id, &system)
        .await?
        .expect("request remains");
    assert_eq!(
        *decided.status(),
        gauge::generated::PermissionRequestStatus::Denied
    );
    assert!(
        matches!(owner_v.actor(), Actor::User { .. }),
        "reviewer actor must stay User (no System elevate)"
    );

    Ok(())
}

#[tokio::test]
async fn permission_history_read_defers_to_parent_read_tm_sec_04() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let group_id = "pg_hist_read_1";
    let record_id = "ph_read_policy_1";

    seed_group_with_owner(&system, group_id, owner_user).await;
    let owner_v = user_ctx(&system, owner_user);
    seed_permission_history_on_group(&owner_v, record_id, group_id, owner_user).await?;
    seed_user("peer_reader", "peer_reader@example.test", &system).await;

    let schema = SchemaRegistry::global()
        .get_schema("permission_history")
        .expect("permission_history schema registered");
    let raw = QueryCore::get_record_json("permission_history", record_id, &system)
        .await?
        .expect("history record exists");
    let peer_v = user_ctx(&system, "peer_reader");

    // Parent group Read is AUTHENTICATED — Valence floor widens; list_history still filters.
    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Read, &raw, &peer_v)
        .await
        .expect("authenticated Valence read of history via defer→parent Read");

    Ok(())
}

#[tokio::test]
async fn session_owner_walk_reads_principals_without_system_tm_sec_08() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let group_id = "pg_policy_tm_sec_08";
    seed_group_with_owner(&system, group_id, owner_user).await;
    let owner_v = user_ctx(&system, owner_user);

    let schema = SchemaRegistry::global()
        .get_schema("permission_group")
        .expect("permission_group schema");
    let raw = QueryCore::get_record_json("permission_group", group_id, &system)
        .await?
        .expect("group");

    PrivacyEvaluator::check_entity_access(schema, PrivacyOperation::Update, &raw, &owner_v)
        .await
        .expect("TM-SEC-08 owner recursive policy under session Valence");

    let group = PermissionGroup::get(group_id, &owner_v)
        .await?
        .expect("session get group");
    let owners = group.get_owners_record_ids(&owner_v).await?;
    assert!(
        !owners.is_empty(),
        "session actor must resolve owner principal edges without System elevate"
    );

    Ok(())
}

#[tokio::test]
async fn permission_history_create_owner_happy_outsider_forge_denied_sad() -> anyhow::Result<()> {
    let system = setup_valence().await?;
    let owner_user = "owner_u1";
    let outsider_user = "outsider_hist_forge";
    let group_id = "pg_hist_forge_1";

    seed_group_with_owner(&system, group_id, owner_user).await;
    seed_permission_owned_by_group(&system, "perm_hist_forge_1", group_id).await?;
    seed_user(
        outsider_user,
        &format!("{outsider_user}@example.test"),
        &system,
    )
    .await;

    let owner_v = user_ctx(&system, owner_user);
    let outsider_v = user_ctx(&system, outsider_user);

    let owner_row = PermissionHistory::new(
        valence::RecordId::new("permission", "perm_hist_forge_1"),
        "note".to_string(),
        String::new(),
        "x".to_string(),
        Utc::now(),
        Some(valence::RecordId::new("user", owner_user)),
    )?;
    PermissionHistory::create(owner_row, &owner_v)
        .await
        .expect("owner may create permission_history via defer→parent Update");

    let forged = PermissionHistory::new(
        valence::RecordId::new("permission", "perm_hist_forge_1"),
        "forged_field".to_string(),
        String::new(),
        "spoof".to_string(),
        Utc::now(),
        Some(valence::RecordId::new("user", owner_user)),
    )?;
    let forge_attempt = PermissionHistory::create(forged, &outsider_v).await;
    assert!(
        forge_attempt.is_err(),
        "authenticated outsider PermissionHistory::create must fail without parent Update"
    );

    Ok(())
}
