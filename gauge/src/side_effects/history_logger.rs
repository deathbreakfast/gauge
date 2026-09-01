//! [`valence::SideEffect`] that appends `permission_history` audit rows on every
//! Permission / PermissionGroup mutation.

use async_trait::async_trait;
use chrono::Utc;
use record_history::{history_created, history_deleted, history_field_changed, HistoryWriteParts};
use valence::{Actor, Model, Mutation, MutationKind, RecordId, SideEffect};

use crate::generated::{Permission, PermissionGroup, PermissionHistory};

/// Writes one [`PermissionHistory`] row per changed field (or a single
/// `created`/`deleted` row) whenever a permission or group is mutated.
pub struct PermissionHistoryWriter;

fn permission_source_id(id: &str) -> RecordId {
    RecordId::new("permission", id)
}

fn group_source_id(id: &str) -> RecordId {
    RecordId::new("permission_group", id)
}

fn actor_record(actor: &Actor) -> Option<RecordId> {
    actor.user_id().map(|uid| {
        let bare = valence::ownership::normalize_record_id_for_ownership(uid);
        RecordId::new("user", bare)
    })
}

fn display_opt(value: Option<&Option<String>>) -> String {
    value
        .and_then(|inner| inner.as_ref())
        .map_or("", String::as_str)
        .to_string()
}

fn record_id_display(value: Option<&RecordId>) -> String {
    value.map_or_else(String::new, |r| {
        valence::extract_id_from_record(r).unwrap_or_else(|_| r.to_string())
    })
}

fn resolve_permission_id(
    mutation: &Mutation<'_, Permission>,
    explicit: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(id) = explicit.filter(|s| !s.is_empty()) {
        return Ok(id.to_string());
    }
    let from_model = mutation
        .after()
        .or_else(|| mutation.before())
        .and_then(|t| t.id().and_then(|r| valence::extract_id_from_record(r).ok()))
        .filter(|s| !s.is_empty());
    from_model.ok_or_else(|| {
        anyhow::anyhow!("permission history: missing permission record id on mutation snapshot")
    })
}

fn resolve_group_id(
    mutation: &Mutation<'_, PermissionGroup>,
    explicit: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(id) = explicit.filter(|s| !s.is_empty()) {
        return Ok(id.to_string());
    }
    let from_model = mutation
        .after()
        .or_else(|| mutation.before())
        .and_then(|t| t.id().and_then(|r| valence::extract_id_from_record(r).ok()))
        .filter(|s| !s.is_empty());
    from_model.ok_or_else(|| {
        anyhow::anyhow!("permission history: missing group record id on mutation snapshot")
    })
}

/// Append a single history row under the session Valence actor.
///
/// Create policy uses `defer_to_edge` → parent Update (no System elevate).
pub async fn append_history_row(
    source: RecordId,
    parts: HistoryWriteParts,
    actor: Option<RecordId>,
    valence: &valence::Valence,
) -> anyhow::Result<()> {
    let row = PermissionHistory::new(
        source.clone(),
        parts.field_name.clone(),
        parts.old_value.clone(),
        parts.new_value.clone(),
        Utc::now(),
        actor,
    )?;
    if let Err(e) = PermissionHistory::create(row, valence).await {
        log::warn!(
            "permission history append failed: source={source} field={}: {e}",
            parts.field_name
        );
        return Err(e.into());
    }
    Ok(())
}

async fn append_parts(
    source: RecordId,
    parts: HistoryWriteParts,
    actor: Option<RecordId>,
    valence: &valence::Valence,
) -> anyhow::Result<()> {
    append_history_row(source, parts, actor, valence).await
}

#[async_trait]
impl SideEffect<Permission> for PermissionHistoryWriter {
    async fn on_mutation(&self, mutation: &Mutation<'_, Permission>) -> valence::Result<()> {
        self.on_permission_mutation(mutation, None)
            .await
            .map_err(|e| valence::Error::Internal(e.to_string()))
    }
}

#[async_trait]
impl SideEffect<PermissionGroup> for PermissionHistoryWriter {
    async fn on_mutation(&self, mutation: &Mutation<'_, PermissionGroup>) -> valence::Result<()> {
        self.on_group_mutation(mutation, None)
            .await
            .map_err(|e| valence::Error::Internal(e.to_string()))
    }
}

impl PermissionHistoryWriter {
    /// Write history for a permission mutation.
    pub async fn on_permission_mutation(
        &self,
        mutation: &Mutation<'_, Permission>,
        explicit_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let actor = actor_record(mutation.valence().actor());
        let id = resolve_permission_id(mutation, explicit_id)?;
        let source = permission_source_id(&id);
        let valence = mutation.valence();

        match *mutation.kind() {
            MutationKind::Create => {
                let after = mutation
                    .after()
                    .ok_or_else(|| anyhow::anyhow!("create mutation missing after snapshot"))?;
                append_parts(source, history_created(after.name()), actor, valence).await?;
            }
            MutationKind::Update => {
                let fields = mutation.fields();
                if fields.name.has_changed() {
                    append_parts(
                        source.clone(),
                        history_field_changed(
                            "name",
                            fields.name.before().map_or("", String::as_str),
                            fields.name.after().map_or("", String::as_str),
                        ),
                        actor.clone(),
                        valence,
                    )
                    .await?;
                }
                if fields.description.has_changed() {
                    append_parts(
                        source.clone(),
                        history_field_changed(
                            "description",
                            &display_opt(fields.description.before()),
                            &display_opt(fields.description.after()),
                        ),
                        actor.clone(),
                        valence,
                    )
                    .await?;
                }
                if fields.owners_group.has_changed() {
                    append_parts(
                        source.clone(),
                        history_field_changed(
                            "owners_group",
                            &record_id_display(fields.owners_group.before()),
                            &record_id_display(fields.owners_group.after()),
                        ),
                        actor.clone(),
                        valence,
                    )
                    .await?;
                }
                if fields.domain.has_changed() {
                    append_parts(
                        source.clone(),
                        history_field_changed(
                            "domain",
                            &record_id_display(fields.domain.before()),
                            &record_id_display(fields.domain.after()),
                        ),
                        actor.clone(),
                        valence,
                    )
                    .await?;
                }
            }
            MutationKind::Delete => {
                // Session-path delete writes this row under the request actor
                // (`delete_history_source`). Queued physical delete may restore
                // System from `requested_by` — skip that pass so delete is not
                // attributed to System.
                if matches!(mutation.valence().actor(), Actor::System { .. }) {
                    return Ok(());
                }
                let before = mutation.before();
                append_parts(
                    source,
                    history_deleted(before.map_or("", |t| t.name().as_str())),
                    actor,
                    valence,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Write history for a permission-group mutation.
    pub async fn on_group_mutation(
        &self,
        mutation: &Mutation<'_, PermissionGroup>,
        explicit_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let actor = actor_record(mutation.valence().actor());
        let id = resolve_group_id(mutation, explicit_id)?;
        let source = group_source_id(&id);
        let valence = mutation.valence();

        match *mutation.kind() {
            MutationKind::Create => {
                let after = mutation
                    .after()
                    .ok_or_else(|| anyhow::anyhow!("create mutation missing after snapshot"))?;
                append_parts(source, history_created(after.name()), actor, valence).await?;
            }
            MutationKind::Update => {
                let fields = mutation.fields();
                if fields.name.has_changed() {
                    append_parts(
                        source.clone(),
                        history_field_changed(
                            "name",
                            fields.name.before().map_or("", String::as_str),
                            fields.name.after().map_or("", String::as_str),
                        ),
                        actor.clone(),
                        valence,
                    )
                    .await?;
                }
                if fields.description.has_changed() {
                    append_parts(
                        source.clone(),
                        history_field_changed(
                            "description",
                            &display_opt(fields.description.before()),
                            &display_opt(fields.description.after()),
                        ),
                        actor.clone(),
                        valence,
                    )
                    .await?;
                }
            }
            MutationKind::Delete => {
                if matches!(mutation.valence().actor(), Actor::System { .. }) {
                    return Ok(());
                }
                let before = mutation.before();
                append_parts(
                    source,
                    history_deleted(before.map_or("", |t| t.name().as_str())),
                    actor,
                    valence,
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// Delete a permission or group after service-layer authz.
///
/// Appends the `deleted` history row under the session Valence, then deletes the
/// source with the same actor so history cascade uses delete `defer_to_edge`
/// (parent Delete) — no System elevate.
pub async fn delete_history_source(
    table: &str,
    id: &str,
    valence: &valence::Valence,
) -> anyhow::Result<()> {
    match table {
        "permission" => {
            if let Some(before) = Permission::get(id, valence).await? {
                let field_changes =
                    crate::generated::PermissionFieldChanges::compute(Some(&before), None);
                let mutation = valence::Mutation::new(
                    valence::MutationKind::Delete,
                    Some(before),
                    None,
                    field_changes,
                    valence,
                );
                PermissionHistoryWriter
                    .on_permission_mutation(&mutation, Some(id))
                    .await?;
            }
            Permission::delete(id, valence).await?;
        }
        "permission_group" => {
            if let Some(before) = PermissionGroup::get(id, valence).await? {
                let field_changes =
                    crate::generated::PermissionGroupFieldChanges::compute(Some(&before), None);
                let mutation = valence::Mutation::new(
                    valence::MutationKind::Delete,
                    Some(before),
                    None,
                    field_changes,
                    valence,
                );
                PermissionHistoryWriter
                    .on_group_mutation(&mutation, Some(id))
                    .await?;
            }
            PermissionGroup::delete(id, valence).await?;
        }
        other => anyhow::bail!("unsupported history source table: {other}"),
    }
    Ok(())
}
