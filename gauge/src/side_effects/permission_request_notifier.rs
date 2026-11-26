use async_trait::async_trait;
use std::sync::Once;

use uf_notifications_core::{register_notification_audience, send_notification, SendNotification};
use valence::{Model, Mutation, MutationKind, RecordId, SideEffect};

use crate::generated::{
    Permission, PermissionGroup, PermissionGroupPrincipal, PermissionRequest,
    PermissionRequestStatus, PermissionUserPrincipal,
};
use lepton_identity::service_users::ServiceUserId;

/// Notification kind for "you were added to / removed from" messages.
pub const ACCESS_CHANGE_KIND: &str = "gauge_access_change";

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
        if let Some(permission) = Permission::get(&id, lookup, valence::use_!(r"In **Gauge permissions**, we **load Permission** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await? {
            let owners_group = permission.get_owners_group(lookup, valence::use_!(r"When a **permission request** needs its **owners**, we **load the permission's owners group** so Gauge can find who should be notified. The notifier uses those owner user ids; the group row itself is not shown on this path.")).await?;
            collect_owner_user_ids_from_group(&owners_group, lookup, &mut out).await?;
        }
    } else if table == "permission_group" {
        if let Some(group) = PermissionGroup::get(&id, lookup, valence::use_!(r"In **Gauge permissions**, we **load Permission Group** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await? {
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

        for owner in current.get_owners_record_ids(valence, valence::use_!(r"When **Gauge** needs the **owners of a permission group**, we **follow the owner edges** so the product can show owners on the group detail or decide who may edit. Editors see that list; access checks use it only to allow or deny.")).await? {
            let owner_id = owner.id().to_string();
            match owner.table() {
                "permission_user_principal" => {
                    if let Some(principal) =
                        PermissionUserPrincipal::get(&owner_id, valence, valence::use_!(r"In **Gauge permissions**, we **load Permission User Principal** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await?
                    {
                        out.push(principal.user().clone());
                    }
                }
                "permission_group_principal" => {
                    if let Some(principal) =
                        PermissionGroupPrincipal::get(&owner_id, valence, valence::use_!(r"In **Gauge permissions**, we **load Permission Group Principal** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await?
                    {
                        let nested_id =
                            valence::extract_id_from_record(principal.group()).unwrap_or_default();
                        if let Some(nested_group) =
                            PermissionGroup::get(&nested_id, valence, valence::use_!(r"In **Gauge permissions**, we **load Permission Group** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await?
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
    // A withdrawal is the requester's own act; nobody needs telling.
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

/// Register the audience check that scopes permission-request notifications.
///
/// Hosts call this once at boot, before serving. A recipient is in a request's
/// audience when they are the requestor (decision notices) or, while the
/// request is pending, an owner of the requested resource (new-request
/// notices). The check runs under the sender's own session and answers for one
/// recipient; it never returns or logs the owner list.
pub fn register_permission_request_audience() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        register_access_change_audience();
        register_notification_audience("permission_request", None, |subject, recipient, v| {
            Box::pin(async move {
                let Some(request_id) = subject.strip_prefix("permission_request:") else {
                    return Ok(false);
                };
                let Some(request) = PermissionRequest::get(request_id, v, valence::use_!(r"When a **permission request** notification is sent, we **load the request** so Gauge can check that the recipient is the requestor or an owner of the requested resource. The request is not shown on this path; the result only allows or denies the notification.")).await? else {
                    return Ok(false);
                };
                if record_id_part(request.requestor()) == recipient {
                    return Ok(true);
                }
                if *request.status() != PermissionRequestStatus::Pending {
                    return Ok(false);
                }
                let owners = target_owner_user_ids(request.target(), v)
                    .await
                    .map_err(|e| valence::Error::Internal(e.to_string()))?;
                Ok(owners.iter().any(|o| record_id_part(o) == recipient))
            })
        });
    });
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
                let target_label = target_label(target, mutation.valence()).await;
                let subject = format!("permission_request:{request_id}");
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
                                "A new request for {target_label} is waiting for your review."
                            ),
                            url: Some(format!("/permission/requests/{request_id}")),
                            data_json: None,
                            subject: Some(subject.clone()),
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
                let target_label = target_label(after.target(), mutation.valence()).await;
                let message = match after.status() {
                    PermissionRequestStatus::Approved => {
                        format!("Your request for {target_label} was approved.")
                    }
                    PermissionRequestStatus::Denied => match after.deny_reason() {
                        Some(reason) if !reason.trim().is_empty() => format!(
                            "Your request for {target_label} was denied: {}",
                            reason.trim()
                        ),
                        _ => format!("Your request for {target_label} was denied."),
                    },
                    PermissionRequestStatus::Pending | PermissionRequestStatus::Withdrawn => {
                        return Ok(())
                    }
                };

                if let Err(e) = send_notification(
                    SendNotification {
                        user_id: after.requestor().clone(),
                        kind: "permission_request".to_string(),
                        title: "Permission request updated".to_string(),
                        message,
                        url: Some(format!("/permission/requests/{request_id}")),
                        data_json: None,
                        subject: Some(format!("permission_request:{request_id}")),
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

/// The name people read for a request target: the permission's display name or the group's
/// name. Falls back to "a permission" / "a group" when the row can't be read, never an id.
async fn target_label(target: &RecordId, v: &valence::Valence) -> String {
    let id = record_id_part(target);
    match target.table() {
        "permission" => match crate::service::helpers::get_permission_raw(&id, v).await {
            Ok(Some(permission)) => crate::service::permission_display_name(&permission),
            _ => "a permission".to_string(),
        },
        "permission_group" => match crate::service::helpers::get_group_raw(&id, v).await {
            Ok(Some(group)) => group.name().clone(),
            _ => "a group".to_string(),
        },
        _ => "this access".to_string(),
    }
}

/// Who an access change is about.
#[derive(Clone, Debug)]
enum Affected {
    /// A person, by bare user id.
    User(String),
    /// A service user; its owner is told.
    ServiceUser(ServiceUserId),
}

/// A change to someone's access worth telling them about: added to or removed from a group, or
/// a permission's allow list. Build one with the constructors and pass it to
/// [`notify_access_change`].
#[derive(Clone, Debug)]
pub struct AccessChange {
    subject: RecordId,
    affected: Affected,
    /// Sentence for the person affected.
    for_person: String,
    /// Sentence for a service user's owner; `<handle>` is replaced with the handle.
    for_owner: String,
    url: String,
}

impl AccessChange {
    fn permission(
        permission: &Permission,
        affected: Affected,
        for_person: impl FnOnce(&str) -> String,
        for_owner: impl FnOnce(&str) -> String,
    ) -> Self {
        let id = permission.id().map(record_id_part).unwrap_or_default();
        let label = crate::service::permission_display_name(permission);
        Self {
            subject: RecordId::new("permission", &id),
            affected,
            for_person: for_person(&label),
            for_owner: for_owner(&label),
            url: format!("/permission/permissions/{id}"),
        }
    }

    fn group(
        group: &PermissionGroup,
        affected: Affected,
        for_person: impl FnOnce(&str) -> String,
        for_owner: impl FnOnce(&str) -> String,
    ) -> Self {
        let id = group.id().map(record_id_part).unwrap_or_default();
        let label = group.name().clone();
        Self {
            subject: RecordId::new("permission_group", &id),
            affected,
            for_person: for_person(&label),
            for_owner: for_owner(&label),
            url: format!("/permission/groups/{id}"),
        }
    }

    /// `user_id` was put on `permission`'s allow list.
    #[must_use]
    pub fn user_granted(permission: &Permission, user_id: &str) -> Self {
        Self::permission(
            permission,
            Affected::User(user_id.to_string()),
            |p| format!("You were given {p}."),
            |p| format!("<handle> was given {p}."),
        )
    }

    /// `user_id` was taken off `permission`'s allow list.
    #[must_use]
    pub fn user_revoked(permission: &Permission, user_id: &str) -> Self {
        Self::permission(
            permission,
            Affected::User(user_id.to_string()),
            |p| format!("You were removed from the allow list of {p}."),
            |p| format!("<handle> was removed from the allow list of {p}."),
        )
    }

    /// `service_user` was put on `permission`'s allow list; its owner is told.
    #[must_use]
    pub fn service_user_granted(permission: &Permission, service_user: &ServiceUserId) -> Self {
        let mut change = Self::user_granted(permission, "");
        change.affected = Affected::ServiceUser(service_user.clone());
        change
    }

    /// `service_user` was taken off `permission`'s allow list; its owner is told.
    #[must_use]
    pub fn service_user_revoked(permission: &Permission, service_user: &ServiceUserId) -> Self {
        let mut change = Self::user_revoked(permission, "");
        change.affected = Affected::ServiceUser(service_user.clone());
        change
    }

    /// `user_id` was added to `group` as a member.
    #[must_use]
    pub fn user_added(group: &PermissionGroup, user_id: &str) -> Self {
        Self::group(
            group,
            Affected::User(user_id.to_string()),
            |g| format!("You were added to {g}."),
            |g| format!("<handle> was added to {g}."),
        )
    }

    /// `user_id` was removed from `group`'s members.
    #[must_use]
    pub fn user_removed(group: &PermissionGroup, user_id: &str) -> Self {
        Self::group(
            group,
            Affected::User(user_id.to_string()),
            |g| format!("You were removed from {g}."),
            |g| format!("<handle> was removed from {g}."),
        )
    }
}

/// Tell the person an access change affects, or a service user's owner, through the same
/// notification delivery as access requests.
///
/// Sent under the caller's own Valence (the editor who made the change, never System); the
/// audience check registered by [`register_permission_request_audience`] admits it because the
/// sender can edit the permission or group. A change the caller made to their own access sends
/// nothing. Delivery failures are logged and never fail the change itself.
pub async fn notify_access_change(v: &valence::Valence, change: AccessChange) {
    let (recipient, message) = match &change.affected {
        Affected::User(user_id) => (
            crate::service::helpers::canonical_user_id(user_id),
            change.for_person.clone(),
        ),
        Affected::ServiceUser(service_user) => match service_user_owner(service_user, v).await {
            Some((owner, handle)) => (owner, change.for_owner.replace("<handle>", &handle)),
            None => return,
        },
    };
    if recipient.is_empty()
        || v.actor()
            .user_id()
            .is_some_and(|me| crate::service::helpers::canonical_user_id(me) == recipient)
    {
        return;
    }
    if let Err(e) = send_notification(
        SendNotification {
            user_id: RecordId::new("user", &recipient),
            kind: ACCESS_CHANGE_KIND.to_string(),
            title: "Your access changed".to_string(),
            message,
            url: Some(change.url.clone()),
            data_json: None,
            subject: Some(change.subject.to_string()),
        },
        v,
    )
    .await
    {
        log::warn!(
            "gauge access change notification failed (subject={}): {e}",
            change.subject
        );
    }
}

/// The owning user's bare id and the handle of `service_user`, from control-plane raw reads
/// (an editor removing a service user need not be able to see it). `None` without an owner.
async fn service_user_owner(
    service_user: &ServiceUserId,
    v: &valence::Valence,
) -> Option<(String, String)> {
    let row = crate::actor_can_raw::raw_get_json("service_user_account", service_user.as_str(), v)
        .await
        .ok()??;
    let account: lepton::generated::ServiceUserAccount = serde_json::from_value(row).ok()?;
    let owner = account
        .user()
        .and_then(|owner| valence::extract_id_from_record(owner).ok())?;
    Some((owner, account.handle().clone()))
}

/// Admit an access-change notice when the sender can edit the permission or group it names.
fn register_access_change_audience() {
    register_notification_audience(
        "permission",
        Some(ACCESS_CHANGE_KIND),
        |subject, _recipient, v| {
            Box::pin(async move {
                let Some(id) = subject.strip_prefix("permission:") else {
                    return Ok(false);
                };
                let permission = crate::service::helpers::get_permission_raw(id, v)
                    .await
                    .map_err(|e| valence::Error::Internal(e.to_string()))?;
                match permission {
                    Some(permission) => crate::service::can_edit_permission(&permission, v)
                        .await
                        .map_err(|e| valence::Error::Internal(e.to_string())),
                    None => Ok(false),
                }
            })
        },
    );
    register_notification_audience(
        "permission_group",
        Some(ACCESS_CHANGE_KIND),
        |subject, _recipient, v| {
            Box::pin(async move {
                let Some(id) = subject.strip_prefix("permission_group:") else {
                    return Ok(false);
                };
                let group = crate::service::helpers::get_group_raw(id, v)
                    .await
                    .map_err(|e| valence::Error::Internal(e.to_string()))?;
                match group {
                    Some(group) => crate::service::can_edit_group(&group, v)
                        .await
                        .map_err(|e| valence::Error::Internal(e.to_string())),
                    None => Ok(false),
                }
            })
        },
    );
}
