#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{seed_user, test_valence};
use gauge::resource_permissions::{
    delete_resource_permission_bundle, ensure_resource_permission_bundle, permission_name,
    seed_resource_kind_catalog, ResourceAction, ResourceKind, ResourcePermissionError,
    ResourcePermissionPolicy, ResourcePermissionSpec, UmbrellaPolicy,
};
use gauge::service;
use valence::{Actor, JsonActorContext, Model, PolicyEvaluator, PrivacyOperation};

async fn system_valence() -> valence::Valence {
    test_valence(Actor::System {
        operation: "resource_permissions_tests".to_string(),
    })
    .await
}

fn user_valence(system: &valence::Valence, user_id: &str) -> valence::Valence {
    system.with_actor(Actor::User {
        user_id: user_id.to_string(),
    })
}

async fn seed_gluon_catalog(v: &valence::Valence) -> Result<(), ResourcePermissionError> {
    seed_resource_kind_catalog(
        v,
        ResourceKind::GluonApp,
        "rp_catalog_gluon_app",
        "Gluon application create",
        "rp_perm_create_gluon_applications",
    )
    .await?;
    seed_resource_kind_catalog(
        v,
        ResourceKind::GluonAppSet,
        "rp_catalog_gluon_app_set",
        "Gluon app set create",
        "rp_perm_create_gluon_app_sets",
    )
    .await?;
    Ok(())
}

async fn seed_neutrino_catalog(v: &valence::Valence) -> Result<(), ResourcePermissionError> {
    seed_resource_kind_catalog(
        v,
        ResourceKind::NeutrinoSecret,
        "rp_catalog_neutrino_secret",
        "Neutrino secret create",
        "rp_perm_create_neutrino_secrets",
    )
    .await
}

async fn seed_nucleus_catalog(v: &valence::Valence) -> Result<(), ResourcePermissionError> {
    seed_resource_kind_catalog(
        v,
        ResourceKind::NucleusStack,
        "rp_catalog_nucleus_stack",
        "Nucleus stack create",
        "rp_perm_create_nucleus_stacks",
    )
    .await
}

#[tokio::test]
async fn seed_resource_kind_catalog_gluon_idempotent_and_creator_holds_create() -> anyhow::Result<()>
{
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;
    seed_gluon_catalog(&system).await?;

    let creator = "creator_u1";
    seed_user(creator, "creator_u1@example.test", &system).await;

    // Grant creator membership in gluon.app.creators via service path: add as member.
    // Use System-related grant: add user to group members using generated relate after principal.
    let group = gauge::generated::PermissionGroup::get("gluon.app.creators", &system)
        .await?
        .expect("creators group");
    let user = lepton::generated::User::get(creator, &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{creator}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            creator.to_string(),
        )?,
        &system,
    )
    .await?;
    group
        .relate_to_member_record(principal.id().expect("pid"), &system)
        .await?;

    let uv = user_valence(&system, creator);
    assert!(
        service::actor_can(&uv, ResourceKind::GluonApp.create_permission_name()).await?,
        "creator group member should hold CreateGluonApplications"
    );

    let stranger = "stranger_u2";
    seed_user(stranger, "stranger_u2@example.test", &system).await;
    let sv = user_valence(&system, stranger);
    assert!(
        !service::actor_can(&sv, ResourceKind::GluonApp.create_permission_name()).await?,
        "non-member must not hold CreateGluonApplications"
    );
    Ok(())
}

#[tokio::test]
async fn ensure_creates_bundle_and_maintainer_owns_maintain() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;

    let maintainer = "maint_u1";
    seed_user(maintainer, "maint_u1@example.test", &system).await;

    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-42".into(),
            display_name: "App 42".into(),
            actions: vec![],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;

    // Idempotent second ensure
    let bundle2 = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-42".into(),
            display_name: "App 42".into(),
            actions: vec![],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    assert_eq!(bundle.domain_id, bundle2.domain_id);
    assert_eq!(bundle.owners_group_id, bundle2.owners_group_id);

    let maintain_name = permission_name(ResourceKind::GluonApp, "app-42", ResourceAction::Maintain);
    assert_eq!(
        bundle.name_for(ResourceAction::Maintain),
        Some(maintain_name.as_str())
    );

    let uv = user_valence(&system, maintainer);
    assert!(
        service::actor_can(&uv, &maintain_name).await?,
        "maintainer (owners group) should have Maintain"
    );

    let other = "other_u3";
    seed_user(other, "other_u3@example.test", &system).await;
    let ov = user_valence(&system, other);
    assert!(!service::actor_can(&ov, &maintain_name).await?);
    Ok(())
}

#[tokio::test]
async fn ensure_rejects_missing_maintainer() -> anyhow::Result<()> {
    let system = system_valence().await;
    let err = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::NucleusStack,
            resource_id: "stack-1".into(),
            display_name: "Stack".into(),
            actions: vec![ResourceAction::View],
            maintainer_actor: "  ".into(),
        },
    )
    .await
    .expect_err("missing maintainer");
    assert!(matches!(
        err,
        ResourcePermissionError::MissingMaintainer { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn ensure_rejects_invalid_resource_id() -> anyhow::Result<()> {
    let system = system_valence().await;
    let err = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "   ".into(),
            display_name: "Blank".into(),
            actions: vec![],
            maintainer_actor: "maint_u1".into(),
        },
    )
    .await
    .expect_err("invalid resource id");
    assert!(
        matches!(err, ResourcePermissionError::InvalidResourceId { .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("invalid resource_id"), "got {err}");
    Ok(())
}

#[tokio::test]
async fn default_groups_granted_on_view() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_neutrino_catalog(&system).await?;
    seed_nucleus_catalog(&system).await?;

    let maintainer = "maint_u4";
    seed_user(maintainer, "maint_u4@example.test", &system).await;

    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::NucleusStack,
            resource_id: "stk-9".into(),
            display_name: "Stack 9".into(),
            actions: ResourceKind::NucleusStack.default_actions(),
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;

    let view = bundle
        .name_for(ResourceAction::View)
        .expect("View permission")
        .to_string();

    // Put viewer in nucleus.stack.viewers
    let viewer = "viewer_u5";
    seed_user(viewer, "viewer_u5@example.test", &system).await;
    let group = gauge::generated::PermissionGroup::get("nucleus.stack.viewers", &system)
        .await?
        .expect("viewers");
    let user = lepton::generated::User::get(viewer, &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{viewer}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            viewer.to_string(),
        )?,
        &system,
    )
    .await?;
    group
        .relate_to_member_record(principal.id().expect("pid"), &system)
        .await?;

    let vv = user_valence(&system, viewer);
    assert!(service::actor_can(&vv, &view).await?);

    let edit = permission_name(ResourceKind::NucleusStack, "stk-9", ResourceAction::Edit);
    assert!(
        !service::actor_can(&vv, &edit).await?,
        "viewers must not get Edit"
    );
    Ok(())
}

#[tokio::test]
async fn resource_policy_allows_view_when_granted() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;
    let maintainer = "maint_u6";
    seed_user(maintainer, "maint_u6@example.test", &system).await;
    ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "pol-1".into(),
            display_name: "Pol".into(),
            actions: vec![],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;

    // Grant View to a user via owners Maintain path — put user in viewers group
    let viewer = "viewer_u7";
    seed_user(viewer, "viewer_u7@example.test", &system).await;
    let group = gauge::generated::PermissionGroup::get("gluon.app.viewers", &system)
        .await?
        .expect("viewers");
    let user = lepton::generated::User::get(viewer, &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{viewer}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            viewer.to_string(),
        )?,
        &system,
    )
    .await?;
    group
        .relate_to_member_record(principal.id().expect("pid"), &system)
        .await?;

    let vv = user_valence(&system, viewer);
    let actor_ctx = JsonActorContext::new(serde_json::to_value(Actor::User {
        user_id: viewer.to_string(),
    })?);
    let record = serde_json::json!({ "id": "pol-1" });
    let gluon_app_resource = ResourcePermissionPolicy {
        rule_name: "test::GLUON_APP_RESOURCE",
        kind: ResourceKind::GluonApp,
        id_field: "id",
    };
    let allowed = gluon_app_resource
        .evaluate(PrivacyOperation::Read, &record, &actor_ctx, &vv)
        .await?;
    assert!(allowed);

    let denied = gluon_app_resource
        .evaluate(PrivacyOperation::Update, &record, &actor_ctx, &vv)
        .await?;
    assert!(!denied, "viewer must not Edit");
    Ok(())
}

#[tokio::test]
async fn neutrino_umbrella_grants_empty_operators_denied_without_per_secret_grant(
) -> anyhow::Result<()> {
    assert_eq!(
        ResourceKind::NeutrinoSecret.umbrella_policy(),
        UmbrellaPolicy::None
    );
    assert_eq!(
        ResourceKind::GluonApp.umbrella_policy(),
        UmbrellaPolicy::KindWide
    );

    let system = system_valence().await;
    seed_neutrino_catalog(&system).await?;

    let maintainer = "maint_nu1";
    seed_user(maintainer, "maint_nu1@example.test", &system).await;
    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::NeutrinoSecret,
            resource_id: "sec-1".into(),
            display_name: "Secret 1".into(),
            actions: ResourceKind::NeutrinoSecret.default_actions(),
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let reveal = bundle
        .name_for(ResourceAction::Reveal)
        .expect("Reveal")
        .to_string();

    let operator = "ops_nu1";
    seed_user(operator, "ops_nu1@example.test", &system).await;
    let group = gauge::generated::PermissionGroup::get("neutrino.secret.operators", &system)
        .await?
        .expect("operators");
    let user = lepton::generated::User::get(operator, &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{operator}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            operator.to_string(),
        )?,
        &system,
    )
    .await?;
    group
        .relate_to_member_record(principal.id().expect("pid"), &system)
        .await?;

    let ov = user_valence(&system, operator);
    assert!(
        !service::actor_can(&ov, &reveal).await?,
        "operators must not get Reveal after umbrella narrowing"
    );

    let mv = user_valence(&system, maintainer);
    assert!(
        service::actor_can(&mv, &reveal).await?,
        "owners-group maintainer should still Reveal"
    );
    Ok(())
}

#[tokio::test]
async fn colliding_resource_ids_get_distinct_bundles() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_neutrino_catalog(&system).await?;
    let maintainer = "maint_col";
    seed_user(maintainer, "maint_col@example.test", &system).await;

    let a = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::NeutrinoSecret,
            resource_id: "abc-123".into(),
            display_name: "Dash".into(),
            actions: vec![ResourceAction::Reveal],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let b = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::NeutrinoSecret,
            resource_id: "abc_123".into(),
            display_name: "Underscore".into(),
            actions: vec![ResourceAction::Reveal],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    assert_ne!(a.domain_id, b.domain_id);
    assert_ne!(
        a.name_for(ResourceAction::Reveal),
        b.name_for(ResourceAction::Reveal)
    );

    let stranger = "stranger_col";
    seed_user(stranger, "stranger_col@example.test", &system).await;
    // Grant stranger Reveal on A only.
    let reveal_a = a.name_for(ResourceAction::Reveal).unwrap().to_string();
    let reveal_b = b.name_for(ResourceAction::Reveal).unwrap().to_string();
    let perm_a = gauge::generated::Permission::query(&system)
        .where_name(valence::StringPredicate::Equals(reveal_a.clone()))
        .limit(1)
        .first()
        .await?
        .expect("perm a");
    let user = lepton::generated::User::get(stranger, &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{stranger}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            stranger.to_string(),
        )?,
        &system,
    )
    .await?;
    perm_a
        .relate_to_allowed_principal_record(principal.id().expect("pid"), &system)
        .await?;

    let sv = user_valence(&system, stranger);
    assert!(service::actor_can(&sv, &reveal_a).await?);
    assert!(
        !service::actor_can(&sv, &reveal_b).await?,
        "grant on colliding-sanitized id A must not authorize B"
    );
    Ok(())
}

#[tokio::test]
async fn delete_resource_permission_bundle_tears_down_and_is_idempotent() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;
    let maintainer = "maint_del";
    seed_user(maintainer, "maint_del@example.test", &system).await;

    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-del".into(),
            display_name: "Delete Me".into(),
            actions: vec![],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;

    let domain = gauge::generated::PermissionDomain::get(&bundle.domain_id, &system)
        .await?
        .expect("domain");
    assert!(*domain.resource_scoped());
    assert_eq!(domain.resource_id().map(String::as_str), Some("app-del"));

    delete_resource_permission_bundle(&system, ResourceKind::GluonApp, "app-del").await?;
    assert!(
        gauge::generated::PermissionDomain::get(&bundle.domain_id, &system)
            .await?
            .is_none()
    );
    assert!(
        gauge::generated::PermissionGroup::get(&bundle.owners_group_id, &system)
            .await?
            .is_none()
    );
    for action in ResourceKind::GluonApp.default_actions() {
        let name = permission_name(ResourceKind::GluonApp, "app-del", action);
        assert!(
            gauge::generated::Permission::query(&system)
                .where_name(valence::StringPredicate::Equals(name))
                .limit(1)
                .first()
                .await?
                .is_none(),
            "permission for {action:?} should be gone"
        );
    }

    // Umbrella groups and catalog Create* survive.
    assert!(
        gauge::generated::PermissionGroup::get("gluon.app.creators", &system)
            .await?
            .is_some()
    );
    assert!(
        gauge::generated::Permission::get("rp_perm_create_gluon_applications", &system)
            .await?
            .is_some()
    );

    // Idempotent second delete + never-ensured resource.
    delete_resource_permission_bundle(&system, ResourceKind::GluonApp, "app-del").await?;
    delete_resource_permission_bundle(&system, ResourceKind::GluonApp, "never-ensured").await?;
    Ok(())
}

#[tokio::test]
async fn resource_permission_list_browsable_for_outsider_happy() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;

    let maintainer = "maint_list";
    seed_user(maintainer, "maint_list@example.test", &system).await;
    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-list".into(),
            display_name: "Listable App".into(),
            actions: vec![ResourceAction::View],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let view = bundle.name_for(ResourceAction::View).unwrap().to_string();

    let outsider = "outsider_list";
    seed_user(outsider, "outsider_list@example.test", &system).await;
    let ov = user_valence(&system, outsider);

    let listed = service::list_permissions(&ov, Some(view.clone())).await?;
    let row = listed
        .iter()
        .find(|d| d.name == view)
        .expect("outsider must see resource permission in list");
    assert!(
        row.description.contains("Listable"),
        "listed row must include description; got {:?}",
        row.description
    );
    assert!(
        row.allow_list.is_empty(),
        "outsider list row must omit grant graph; got {:?}",
        row.allow_list
    );
    assert!(
        !service::actor_can(&ov, &view).await?,
        "outsider must not act on listed permission"
    );
    Ok(())
}

#[tokio::test]
async fn actor_can_raw_deep_nest_allows_with_bounded_reads() -> anyhow::Result<()> {
    const DEPTH: usize = 5;
    /// Super-user probe + permission query + principals + nested group hops.
    const RAW_READ_CEILING: usize = 64;

    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;

    let maintainer = "maint_nest";
    seed_user(maintainer, "maint_nest@example.test", &system).await;
    let member = "nest_member";
    seed_user(member, "nest_member@example.test", &system).await;

    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-nest".into(),
            display_name: "Nest".into(),
            actions: vec![ResourceAction::View],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let view = bundle.name_for(ResourceAction::View).unwrap().to_string();

    let mut groups = Vec::with_capacity(DEPTH);
    for i in 0..DEPTH {
        let gid = format!("nest_g{i}");
        let g = gauge::generated::PermissionGroup::upsert(
            &gid,
            gauge::generated::PermissionGroup::new(
                format!("Nest {i}"),
                None,
                chrono::Utc::now(),
                chrono::Utc::now(),
            )?,
            &system,
        )
        .await?;
        groups.push(g);
    }

    for i in 0..DEPTH - 1 {
        let child_principal = gauge::generated::PermissionGroupPrincipal::upsert(
            &format!("permission_group:nest_g{}", i + 1),
            gauge::generated::PermissionGroupPrincipal::new(
                groups[i + 1].id().expect("id").clone(),
                format!("nest_g{}", i + 1),
            )?,
            &system,
        )
        .await?;
        groups[i]
            .relate_to_member_record(child_principal.id().expect("pid"), &system)
            .await?;
    }

    let member_user = lepton::generated::User::get(member, &system)
        .await?
        .expect("member");
    let member_principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{member}"),
        gauge::generated::PermissionUserPrincipal::new(
            member_user.id().expect("id").clone(),
            member.to_string(),
        )?,
        &system,
    )
    .await?;
    groups[DEPTH - 1]
        .relate_to_member_record(member_principal.id().expect("pid"), &system)
        .await?;

    let outer_principal = gauge::generated::PermissionGroupPrincipal::upsert(
        "permission_group:nest_g0",
        gauge::generated::PermissionGroupPrincipal::new(
            groups[0].id().expect("id").clone(),
            "nest_g0".into(),
        )?,
        &system,
    )
    .await?;
    let perm = gauge::generated::Permission::query(&system)
        .where_name(valence::StringPredicate::Equals(view.clone()))
        .limit(1)
        .first()
        .await?
        .expect("perm");
    perm.relate_to_allowed_principal_record(outer_principal.id().expect("pid"), &system)
        .await?;

    let mv = user_valence(&system, member);
    gauge::actor_can_raw::__test_reset_raw_read_count();
    assert!(
        gauge::actor_can_raw::actor_can_raw(&mv, &view).await?,
        "deep nested member must inherit grant"
    );
    let reads = gauge::actor_can_raw::__test_raw_read_count();
    assert!(
        reads <= RAW_READ_CEILING,
        "raw walk must stay bounded; got {reads} reads (ceiling {RAW_READ_CEILING})"
    );
    Ok(())
}

#[tokio::test]
async fn actor_can_raw_matches_actor_can_and_terminates_on_cycle() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;
    let maintainer = "maint_raw";
    seed_user(maintainer, "maint_raw@example.test", &system).await;
    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-raw".into(),
            display_name: "Raw".into(),
            actions: vec![ResourceAction::View],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let view = bundle.name_for(ResourceAction::View).unwrap().to_string();

    let mv = user_valence(&system, maintainer);
    assert!(service::actor_can(&mv, &view).await?);
    assert!(gauge::actor_can_raw::actor_can_raw(&mv, &view).await?);

    let stranger = "stranger_raw";
    seed_user(stranger, "stranger_raw@example.test", &system).await;
    let sv = user_valence(&system, stranger);
    assert!(!service::actor_can(&sv, &view).await?);
    assert!(!gauge::actor_can_raw::actor_can_raw(&sv, &view).await?);

    // Cyclic group membership must terminate (visited set), not hang.
    let g1 = gauge::generated::PermissionGroup::upsert(
        "cycle_g1",
        gauge::generated::PermissionGroup::new(
            "Cycle 1".into(),
            None,
            chrono::Utc::now(),
            chrono::Utc::now(),
        )?,
        &system,
    )
    .await?;
    let g2 = gauge::generated::PermissionGroup::upsert(
        "cycle_g2",
        gauge::generated::PermissionGroup::new(
            "Cycle 2".into(),
            None,
            chrono::Utc::now(),
            chrono::Utc::now(),
        )?,
        &system,
    )
    .await?;
    let p1 = gauge::generated::PermissionGroupPrincipal::upsert(
        "permission_group:cycle_g1",
        gauge::generated::PermissionGroupPrincipal::new(
            g1.id().expect("id").clone(),
            "cycle_g1".into(),
        )?,
        &system,
    )
    .await?;
    let p2 = gauge::generated::PermissionGroupPrincipal::upsert(
        "permission_group:cycle_g2",
        gauge::generated::PermissionGroupPrincipal::new(
            g2.id().expect("id").clone(),
            "cycle_g2".into(),
        )?,
        &system,
    )
    .await?;
    g1.relate_to_member_record(p2.id().expect("pid"), &system)
        .await?;
    g2.relate_to_member_record(p1.id().expect("pid"), &system)
        .await?;
    // Grant view to the cyclic group — stranger is not a member, so still deny,
    // but the walk must finish.
    let perm = gauge::generated::Permission::query(&system)
        .where_name(valence::StringPredicate::Equals(view.clone()))
        .limit(1)
        .first()
        .await?
        .expect("perm");
    perm.relate_to_allowed_principal_record(p1.id().expect("pid"), &system)
        .await?;
    assert!(!gauge::actor_can_raw::actor_can_raw(&sv, &view).await?);
    Ok(())
}

#[tokio::test]
async fn docs_per_kind_grant_table_matches_umbrella_policy() {
    // GD2 / TM-RP-12: published table cells vs code.
    assert_eq!(
        ResourceKind::NeutrinoSecret.umbrella_policy(),
        UmbrellaPolicy::None
    );
    assert_eq!(
        ResourceKind::GluonApp.umbrella_policy(),
        UmbrellaPolicy::KindWide
    );
    assert_eq!(
        ResourceKind::GluonAppSet.umbrella_policy(),
        UmbrellaPolicy::KindWide
    );
    assert_eq!(
        ResourceKind::NucleusStack.umbrella_policy(),
        UmbrellaPolicy::KindWide
    );
}

#[tokio::test]
async fn revoke_neutrino_secret_umbrella_grants_is_surgical_and_idempotent() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_neutrino_catalog(&system).await?;
    seed_gluon_catalog(&system).await?;

    let maintainer = "maint_rev";
    seed_user(maintainer, "maint_rev@example.test", &system).await;
    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::NeutrinoSecret,
            resource_id: "sec-rev".into(),
            display_name: "Revoke me".into(),
            actions: ResourceKind::NeutrinoSecret.default_actions(),
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let reveal = bundle
        .name_for(ResourceAction::Reveal)
        .expect("Reveal")
        .to_string();

    // Simulate a pre-narrowing edge: grant operators on this secret's Reveal.
    let perm = gauge::generated::Permission::query(&system)
        .where_name(valence::StringPredicate::Equals(reveal.clone()))
        .limit(1)
        .first()
        .await?
        .expect("reveal perm");
    let ops = gauge::generated::PermissionGroup::get("neutrino.secret.operators", &system)
        .await?
        .expect("operators");
    let ops_principal = gauge::generated::PermissionGroupPrincipal::upsert(
        "permission_group:neutrino.secret.operators",
        gauge::generated::PermissionGroupPrincipal::new(
            ops.id().expect("id").clone(),
            "neutrino.secret.operators".into(),
        )?,
        &system,
    )
    .await?;
    perm.relate_to_allowed_principal_record(ops_principal.id().expect("pid"), &system)
        .await?;

    let operator = "ops_rev";
    seed_user(operator, "ops_rev@example.test", &system).await;
    let user = lepton::generated::User::get(operator, &system)
        .await?
        .expect("user");
    let user_principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{operator}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            operator.to_string(),
        )?,
        &system,
    )
    .await?;
    ops.relate_to_member_record(user_principal.id().expect("pid"), &system)
        .await?;

    let ov = user_valence(&system, operator);
    assert!(service::actor_can(&ov, &reveal).await?);

    let groups = ResourceKind::NeutrinoSecret.descriptor().groups;
    let first = gauge::resource_permissions::revoke_umbrella_grants(
        &system,
        ResourceKind::NeutrinoSecret,
        &[groups.viewers, groups.operators],
    )
    .await?;
    assert!(first >= 1, "expected at least one revoke, got {first}");
    assert!(!service::actor_can(&ov, &reveal).await?);

    // Catalog Create*, creators, and Gluon rows survive.
    assert!(
        gauge::generated::Permission::get("rp_perm_create_neutrino_secrets", &system)
            .await?
            .is_some()
    );
    assert!(
        gauge::generated::PermissionGroup::get("neutrino.secret.creators", &system)
            .await?
            .is_some()
    );
    assert!(
        gauge::generated::PermissionGroup::get("gluon.app.viewers", &system)
            .await?
            .is_some()
    );

    let second = gauge::resource_permissions::revoke_umbrella_grants(
        &system,
        ResourceKind::NeutrinoSecret,
        &[groups.viewers, groups.operators],
    )
    .await?;
    assert_eq!(second, 0, "idempotent re-run must revoke nothing");
    Ok(())
}

#[tokio::test]
async fn super_user_acts_on_foreign_bundle_without_grant() -> anyhow::Result<()> {
    let system = system_valence().await;
    seed_gluon_catalog(&system).await?;

    let maintainer = "maint_su";
    seed_user(maintainer, "maint_su@example.test", &system).await;
    let bundle = ensure_resource_permission_bundle(
        &system,
        ResourcePermissionSpec {
            kind: ResourceKind::GluonApp,
            resource_id: "app-su".into(),
            display_name: "Foreign".into(),
            actions: vec![],
            maintainer_actor: maintainer.into(),
        },
    )
    .await?;
    let maintain = bundle
        .name_for(ResourceAction::Maintain)
        .expect("Maintain")
        .to_string();

    let su = "super_rp";
    seed_user(su, "super_rp@example.test", &system).await;
    common::seed_super_user_group_with_member(&system, su).await;

    let stranger = "stranger_su";
    seed_user(stranger, "stranger_su@example.test", &system).await;

    let su_v = user_valence(&system, su);
    let stranger_v = user_valence(&system, stranger);
    assert!(service::actor_can(&su_v, &maintain).await?);
    assert!(!service::actor_can(&stranger_v, &maintain).await?);

    // Duplicate display-name group confers nothing.
    let fake = gauge::generated::PermissionGroup::upsert(
        "fake_super_display_only",
        gauge::generated::PermissionGroup::new(
            gauge::super_user::SUPER_USER_GROUP_NAME.to_string(),
            None,
            chrono::Utc::now(),
            chrono::Utc::now(),
        )?,
        &system,
    )
    .await?;
    let stranger_user = lepton::generated::User::get(stranger, &system)
        .await?
        .expect("user");
    let stranger_principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{stranger}"),
        gauge::generated::PermissionUserPrincipal::new(
            stranger_user.id().expect("id").clone(),
            stranger.to_string(),
        )?,
        &system,
    )
    .await?;
    fake.relate_to_member_record(stranger_principal.id().expect("pid"), &system)
        .await?;
    assert!(!service::actor_can(&stranger_v, &maintain).await?);
    Ok(())
}
