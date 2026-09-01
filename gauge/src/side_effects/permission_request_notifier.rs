use async_trait::async_trait;
use uf_notifications_core::{send_notification, SendNotification};
use valence::{Model, Mutation, MutationKind, RecordId, SideEffect};

use crate::generated::{
    Permission, PermissionGroup, PermissionGroupPrincipal, PermissionRequest,
    PermissionRequestStatus, PermissionUserPrincipal,
};

fn record_id_part(r: &RecordId) -> String {
    valence::extract_id_from_record(r).unwrap_or_default()
}

async fn target_owner_user_ids(
    target: &RecordId,
    valence: &valence::Valence,
) -> anyhow::Result<Vec<RecordId>> {
    let lookup = valence;
    let table = target.table().to_string();
    let id = record_id_part(target);
    let mut out: Vec<RecordId> = Vec::new();

    if table == "permission" {
        if let Some(permission) = Permission::get(&id, lookup).await? {
            let owners_group = permission.get_owners_group(lookup).await?;
            collect_owner_user_ids_from_group(&owners_group, lookup, &mut out).await?;
        }
    } else if table == "permission_group" {
        if let Some(group) = PermissionGroup::get(&id, lookup).await? {
            collect_owner_user_ids_from_group(&group, lookup, &mut out).await?;
        }
    }

    out.sort_by_key(std::string::ToString::to_string);
    out.dedup_by(|a, b| a == b);
    Ok(out)
}

async fn collect_owner_user_ids_from_group(
    group: &PermissionGroup,
    valence: &valence::Valence,
    out: &mut Vec<RecordId>,
) -> anyhow::Result<()> {
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![group.clone()];
    while let Some(current) = queue.pop() {
        let current_id = current
            .id()
            .and_then(|id| valence::extract_id_from_record(id).ok())
            .unwrap_or_default();
        if current_id.is_empty() || !visited.insert(current_id) {
            continue;
        }

        for owner in current.get_owners_record_ids(valence).await? {
            let owner_id = owner.id().to_string();
            match owner.table() {
                "permission_user_principal" => {
                    if let Some(principal) =
                        PermissionUserPrincipal::get(&owner_id, valence).await?
                    {
                        out.push(principal.user().clone());
                    }
                }
                "permission_group_principal" => {
                    if let Some(principal) =
                        PermissionGroupPrincipal::get(&owner_id, valence).await?
                    {
                        let nested_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(nested_group) =
                            PermissionGroup::get(&nested_id, valence).await?
                        {
                            queue.push(nested_group);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn status_changed_to_terminal(
    before: Option<&PermissionRequest>,
    after: Option<&PermissionRequest>,
) -> bool {
    let Some(after) = after else {
        return false;
    };
    let status = after.status();
    let is_terminal = matches!(
        status,
        PermissionRequestStatus::Approved | PermissionRequestStatus::Denied
    );
    if !is_terminal {
        return false;
    }

    let before_status = before.map(super::super::generated::PermissionRequest::status);
    before_status != Some(status)
}

/// Notifies target owners when a request is submitted, and notifies the requestor
/// when their request is approved or denied.
pub struct PermissionRequestNotifier;

#[async_trait]
impl SideEffect<PermissionRequest> for PermissionRequestNotifier {
    async fn on_mutation(&self, mutation: &Mutation<'_, PermissionRequest>) -> valence::Result<()> {
        match mutation.kind() {
            MutationKind::Create => {
                let Some(after) = mutation.after() else {
                    return Ok(());
                };
                let Some(request_id_thing) = after.id() else {
                    return Ok(());
                };

                let request_id = record_id_part(request_id_thing);
                let target = after.target();
                let target_table = target.table().to_string();
                let target_id = record_id_part(target);
                let owners = target_owner_user_ids(target, mutation.valence())
                    .await
                    .map_err(|e| valence::Error::Internal(e.to_string()))?;
                let notify_as = mutation.valence();

                for owner_user_id in owners {
                    if let Err(e) = send_notification(
                        SendNotification {
                            user_id: owner_user_id,
                            kind: "permission_request".to_string(),
                            title: "Permission request submitted".to_string(),
                            message: format!(
                                "A new request is waiting for review for {target_table}:{target_id}."
                            ),
                            url: Some(format!("/permission/requests/{request_id}")),
                            data_json: None,
                        },
                        notify_as,
                    )
                    .await
                    {
                        log::warn!(
                            "permission request owner notification failed (request_id={request_id}): {e}"
                        );
                    }
                }
            }
            MutationKind::Update => {
                if !status_changed_to_terminal(mutation.before(), mutation.after()) {
                    return Ok(());
                }
                let Some(after) = mutation.after() else {
                    return Ok(());
                };
                let Some(request_id_thing) = after.id() else {
                    return Ok(());
                };

                let request_id = record_id_part(request_id_thing);
                let decision = match after.status() {
                    PermissionRequestStatus::Approved => "approved",
                    PermissionRequestStatus::Denied => "denied",
                    PermissionRequestStatus::Pending => return Ok(()),
                };

                if let Err(e) = send_notification(
                    SendNotification {
                        user_id: after.requestor().clone(),
                        kind: "permission_request".to_string(),
                        title: "Permission request updated".to_string(),
                        message: format!("Your permission request was {decision}."),
                        url: Some(format!("/permission/requests/{request_id}")),
                        data_json: None,
                    },
                    mutation.valence(),
                )
                .await
                {
                    log::warn!(
                        "permission request decision notification failed (request_id={request_id}): {e}"
                    );
                }
            }
            MutationKind::Delete => {}
        }
        Ok(())
    }
}
