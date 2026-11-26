//! Change log reads: Gauge's record history in words, for the Activity page and a resource's
//! Activity tab.
//!
//! Rows come from the `permission_history` table (permissions, groups and their members and
//! owners) and from access requests (filed, decided, withdrawn). Each row names people and
//! records by name ("Removed Ravi Menon from the group"), never by id. Every read runs on the
//! caller's Valence; nothing switches to System.

use std::collections::HashMap;

use valence::{RecordId, Valence};

use crate::actor_can_raw::model_pk_id;
use crate::generated::{PermissionHistory, PermissionRequest, PermissionRequestStatus};
use crate::resource_permissions::{
    owners_group_id, permission_name, permission_record_id, ResourceAction, ResourceKindDescriptor,
};
use crate::types::{ActivityFilter, ActivityKind, ActivityRow, Page, RecordKind, RecordRef};

use super::access::{actor_can, actor_is_gauge_admin};
use super::helpers::{canonical_user_id, get_group_raw, get_permission_raw, user_label};
use super::permissions::permission_display_name;
use super::GaugeServiceError;

/// Rows per page of [`list_activity`] and [`list_resource_activity`].
pub const ACTIVITY_PAGE_SIZE: usize = 50;

/// Most rows read from each source per call. The change log covers the newest changes up to
/// this many history rows and this many requests.
const MAX_SOURCE_ROWS: u32 = 2000;

/// Gauge's change log, newest first, one page at a time.
///
/// Covers permissions (created, renamed, edited, deleted, allow list changes), groups (created,
/// edited, deleted, owners and members) and access requests (filed, decided, withdrawn).
/// `filter` narrows by kind, time, actor, record and text; empty fields match everything. Pass
/// the previous page's `next_cursor` as `cursor` for the next page.
///
/// # Who may call it
///
/// Gauge admins only. A record's owners read that record's history through
/// [`list_history`](super::list_history).
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for anyone else; `Validation` for a cursor this function
/// didn't hand out. Valence failures otherwise.
pub async fn list_activity(
    filter: ActivityFilter,
    cursor: Option<&str>,
    v: &Valence,
) -> anyhow::Result<Page<ActivityRow>> {
    if !actor_is_gauge_admin(v).await? {
        return Err(GaugeServiceError::not_authorized("read the change log").into());
    }
    let offset = parse_cursor(cursor)?;
    let mut labels = Labels::default();
    let mut rows = Vec::new();

    let history = PermissionHistory::query(v, valence::use_!(r"When a Gauge admin opens the **Activity** page, **Gauge** **reads the record history of permissions and groups** to list each change in words, with who made it and when. Only Gauge admins see the page."))
        .order_by_changed_at(valence::SortDirection::Desc)
        .limit(MAX_SOURCE_ROWS)
        .await?;
    for row in &history {
        if let Some(row) = history_row(row, &mut labels, v).await? {
            rows.push(row);
        }
    }

    let requests = PermissionRequest::query(v, valence::use_!(r"When a Gauge admin opens the **Activity** page, **Gauge** **reads access requests** to list who asked for what and how each was decided. Only Gauge admins see the page."))
        .order_by_updated_at(valence::SortDirection::Desc)
        .limit(MAX_SOURCE_ROWS)
        .await?;
    for request in &requests {
        rows.extend(request_rows(request, &mut labels, v).await?);
    }

    let needle = filter
        .query
        .as_deref()
        .map(|q| q.trim().to_lowercase())
        .filter(|q| !q.is_empty());
    let actor = filter.actor.as_deref().map(canonical_user_id);
    rows.retain(|(row, actor_id)| {
        (filter.kinds.is_empty() || filter.kinds.contains(&row.kind))
            && filter.since.is_none_or(|since| row.at >= since)
            && actor
                .as_ref()
                .is_none_or(|want| actor_id.as_ref() == Some(want))
            && filter
                .record
                .as_ref()
                .is_none_or(|want| want.kind == row.record.kind && want.id == row.record.id)
            && needle.as_ref().is_none_or(|needle| {
                row.summary.to_lowercase().contains(needle)
                    || row.actor_label.to_lowercase().contains(needle)
                    || row.record.label.to_lowercase().contains(needle)
            })
    });
    Ok(page(rows.into_iter().map(|(row, _)| row).collect(), offset))
}

/// The access changes on one resource's permission bundle, newest first.
///
/// Covers grants given and removed on each of its actions, and owners added and removed.
/// Neutrino merges these rows into a secret's Activity tab.
///
/// # Who may call it
///
/// Principals holding `Maintain` or `Audit` on that resource, and Gauge admins.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for anyone else; `Validation` for a cursor this function
/// didn't hand out. Valence failures otherwise.
pub async fn list_resource_activity<K>(
    v: &Valence,
    kind: K,
    resource_id: &str,
    cursor: Option<&str>,
) -> anyhow::Result<Page<ActivityRow>>
where
    K: Into<ResourceKindDescriptor>,
{
    let kind = kind.into();
    let allowed = actor_can(
        v,
        &permission_name(kind, resource_id, ResourceAction::Maintain),
    )
    .await?
        || actor_can(
            v,
            &permission_name(kind, resource_id, ResourceAction::Audit),
        )
        .await?
        || actor_is_gauge_admin(v).await?;
    if !allowed {
        return Err(GaugeServiceError::not_authorized("read this resource's activity").into());
    }
    let offset = parse_cursor(cursor)?;

    let mut sources: Vec<RecordId> = kind
        .actions
        .iter()
        .map(|action| {
            RecordId::new(
                "permission",
                permission_record_id(kind, resource_id, *action),
            )
        })
        .collect();
    sources.push(RecordId::new(
        "permission_group",
        owners_group_id(kind, resource_id),
    ));

    let mut labels = Labels::default();
    let mut rows = Vec::new();
    for source in sources {
        let history = PermissionHistory::query(v, valence::use_!(r"When an owner, or someone they let audit it, opens a **resource's activity**, **Gauge** **reads the history of the resource's permissions and owners group** to list who was given or lost access, and by whom. Only those people and Gauge admins see it."))
            .where_source(valence::RecordPredicate::Equals(source))
            .order_by_changed_at(valence::SortDirection::Desc)
            .limit(MAX_SOURCE_ROWS)
            .await?;
        for row in &history {
            if let Some((row, _)) = history_row(row, &mut labels, v).await? {
                if matches!(
                    row.kind,
                    ActivityKind::Grant | ActivityKind::Group | ActivityKind::Membership
                ) {
                    rows.push(row);
                }
            }
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.at));
    Ok(page(rows, offset))
}

/// Display names looked up once per call.
#[derive(Default)]
struct Labels {
    users: HashMap<String, String>,
    records: HashMap<(RecordKind, String), String>,
}

impl Labels {
    async fn user(&mut self, user_id: &str, v: &Valence) -> String {
        let key = canonical_user_id(user_id);
        if let Some(label) = self.users.get(&key) {
            return label.clone();
        }
        let label = user_label(&key, v).await;
        self.users.insert(key, label.clone());
        label
    }

    async fn record(&mut self, kind: RecordKind, id: &str, v: &Valence) -> anyhow::Result<String> {
        if let Some(label) = self.records.get(&(kind, id.to_string())) {
            return Ok(label.clone());
        }
        let label = match kind {
            RecordKind::Permission => get_permission_raw(id, v)
                .await?
                .map(|p| permission_display_name(&p)),
            RecordKind::Group => get_group_raw(id, v).await?.map(|g| g.name().clone()),
            RecordKind::Domain | RecordKind::Request => None,
        }
        .unwrap_or_else(|| match kind {
            RecordKind::Permission => "a deleted permission".to_string(),
            RecordKind::Group => "a deleted group".to_string(),
            RecordKind::Domain => "a domain".to_string(),
            RecordKind::Request => "a request".to_string(),
        });
        self.records.insert((kind, id.to_string()), label.clone());
        Ok(label)
    }

    async fn service_user(&mut self, id: &str, v: &Valence) -> String {
        let key = format!("svc:{id}");
        if let Some(label) = self.users.get(&key) {
            return label.clone();
        }
        let label = match crate::actor_can_raw::raw_get_json("service_user_account", id, v).await {
            Ok(Some(row)) => serde_json::from_value::<lepton::generated::ServiceUserAccount>(row)
                .map_or_else(|_| "a service user".to_string(), |a| a.handle().clone()),
            _ => "a service user".to_string(),
        };
        self.users.insert(key, label.clone());
        label
    }
}

/// One history row in words, with the actor's bare id for filtering. `None` for a source this
/// log doesn't cover.
async fn history_row(
    row: &PermissionHistory,
    labels: &mut Labels,
    v: &Valence,
) -> anyhow::Result<Option<(ActivityRow, Option<String>)>> {
    let source = row.source();
    let record_kind = match source.table() {
        "permission" => RecordKind::Permission,
        "permission_group" => RecordKind::Group,
        _ => return Ok(None),
    };
    let record_id = source.id().to_string();
    let field = row.field_name().as_str();
    let old = row.old_value().as_str();
    let new = row.new_value().as_str();
    // A deleted record's own name is in the `deleted` row.
    let record_label = if field == "deleted" && !old.is_empty() {
        old.to_string()
    } else {
        labels.record(record_kind, &record_id, v).await?
    };
    let (kind, summary) =
        describe_change(record_kind, &record_label, field, old, new, labels, v).await?;
    let actor_id = row.actor().map(|a| canonical_user_id(a.id()));
    let actor_label = match &actor_id {
        Some(id) => labels.user(id, v).await,
        None => "Gauge".to_string(),
    };
    Ok(Some((
        ActivityRow {
            at: *row.changed_at(),
            actor_label,
            summary,
            record: RecordRef {
                kind: record_kind,
                id: record_id,
                label: record_label,
            },
            kind,
        },
        actor_id,
    )))
}

/// What a history row's field change means, in words, and which kind of change it is.
async fn describe_change(
    record_kind: RecordKind,
    record_label: &str,
    field: &str,
    old: &str,
    new: &str,
    labels: &mut Labels,
    v: &Valence,
) -> anyhow::Result<(ActivityKind, String)> {
    let noun = match record_kind {
        RecordKind::Permission => "permission",
        _ => "group",
    };
    let added = old.is_empty() && !new.is_empty();
    let value = if added { new } else { old };

    Ok(match field {
        "created" => (
            base_kind(record_kind),
            format!("Created the {noun} {record_label}"),
        ),
        "deleted" => (
            base_kind(record_kind),
            format!("Deleted the {noun} {record_label}"),
        ),
        "name" | "display_name" => (
            base_kind(record_kind),
            format!("Renamed the {noun} {old} to {new}"),
        ),
        "description" => (
            base_kind(record_kind),
            format!("Edited the description of {record_label}"),
        ),
        "owners_group" => (
            ActivityKind::Permission,
            format!("Changed who owns {record_label}"),
        ),
        "domain" => (
            ActivityKind::Permission,
            format!("Moved {record_label} to another domain"),
        ),
        "granted_users" | "granted_groups" | "granted_service_users" => {
            let who = match field {
                "granted_users" => labels.user(value, v).await,
                "granted_groups" => format!(
                    "the group {}",
                    labels.record(RecordKind::Group, value, v).await?
                ),
                _ => labels.service_user(value, v).await,
            };
            let summary = if added {
                format!("Gave {who} {record_label}")
            } else {
                format!("Removed {who} from {record_label}")
            };
            (ActivityKind::Grant, summary)
        }
        "member_users" | "member_groups" | "member_service_users" => {
            let who = match field {
                "member_users" => labels.user(value, v).await,
                "member_groups" => format!(
                    "the group {}",
                    labels.record(RecordKind::Group, value, v).await?
                ),
                _ => labels.service_user(value, v).await,
            };
            let summary = if added {
                format!("Added {who} to the group")
            } else {
                format!("Removed {who} from the group")
            };
            (ActivityKind::Membership, summary)
        }
        "owner_users" | "owner_groups" => {
            let who = if field == "owner_users" {
                labels.user(value, v).await
            } else {
                format!(
                    "the group {}",
                    labels.record(RecordKind::Group, value, v).await?
                )
            };
            let summary = if added {
                format!("Made {who} an owner of the group")
            } else {
                format!("Removed {who} as an owner of the group")
            };
            (ActivityKind::Group, summary)
        }
        other => (
            base_kind(record_kind),
            format!("Changed {} on {record_label}", other.replace('_', " ")),
        ),
    })
}

const fn base_kind(kind: RecordKind) -> ActivityKind {
    match kind {
        RecordKind::Permission => ActivityKind::Permission,
        RecordKind::Domain => ActivityKind::Domain,
        RecordKind::Request => ActivityKind::Request,
        RecordKind::Group => ActivityKind::Group,
    }
}

/// A request's events in words: filed, then decided or withdrawn when it was.
async fn request_rows(
    request: &PermissionRequest,
    labels: &mut Labels,
    v: &Valence,
) -> anyhow::Result<Vec<(ActivityRow, Option<String>)>> {
    let target = request.target();
    let target_kind = match target.table() {
        "permission" => RecordKind::Permission,
        "permission_group" => RecordKind::Group,
        _ => return Ok(Vec::new()),
    };
    let target_label = labels.record(target_kind, target.id(), v).await?;
    let requester_id = canonical_user_id(request.requestor().id());
    let requester = labels.user(&requester_id, v).await;
    let record = RecordRef {
        kind: RecordKind::Request,
        id: model_pk_id(request.id()),
        label: format!("{requester}'s request for {target_label}"),
    };
    let mut out = vec![(
        ActivityRow {
            at: *request.created_at(),
            actor_label: requester.clone(),
            summary: format!("Asked for {target_label}"),
            record: record.clone(),
            kind: ActivityKind::Request,
        },
        Some(requester_id.clone()),
    )];
    let decided_at = request
        .decided_at()
        .copied()
        .unwrap_or_else(|| *request.updated_at());
    let decider_id = request
        .approver()
        .as_ref()
        .map(|a| canonical_user_id(a.id()));
    let decider = match &decider_id {
        Some(id) => labels.user(id, v).await,
        None => "Gauge".to_string(),
    };
    let summary = match request.status() {
        PermissionRequestStatus::Pending => None,
        PermissionRequestStatus::Approved => {
            Some(format!("Approved {requester}'s request for {target_label}"))
        }
        PermissionRequestStatus::Denied => {
            Some(format!("Denied {requester}'s request for {target_label}"))
        }
        PermissionRequestStatus::Withdrawn => {
            Some(format!("Withdrew the request for {target_label}"))
        }
    };
    if let Some(summary) = summary {
        out.push((
            ActivityRow {
                at: decided_at,
                actor_label: decider,
                summary,
                record,
                kind: ActivityKind::Request,
            },
            decider_id,
        ));
    }
    Ok(out)
}

/// Newest first, then one page from `offset`.
fn page(mut rows: Vec<ActivityRow>, offset: usize) -> Page<ActivityRow> {
    rows.sort_by_key(|row| std::cmp::Reverse(row.at));
    let total = rows.len();
    let items = rows
        .into_iter()
        .skip(offset)
        .take(ACTIVITY_PAGE_SIZE)
        .collect();
    let next = offset + ACTIVITY_PAGE_SIZE;
    Page {
        items,
        next_cursor: (next < total).then(|| next.to_string()),
    }
}

/// Offset encoded in a cursor this module handed out; `0` for none.
fn parse_cursor(cursor: Option<&str>) -> anyhow::Result<usize> {
    cursor
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map_or(Ok(0), |c| {
            c.parse()
                .map_err(|_| GaugeServiceError::validation("That page link is not valid").into())
        })
}
