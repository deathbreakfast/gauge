use std::collections::HashSet;

use anyhow::Context;
use chrono::Utc;
use lepton::generated::{AccountMembership, AccountMembershipRole};
use valence::{Actor, StringPredicate, Valence};

use crate::super_user::users_with_primary_email;

/// Host env listing platform owners; the run-once script keeps their `owner` role.
pub const SUPER_USER_EMAILS_ENV: &str = "UF_SUPER_USER_EMAILS";

/// Switch `owner` account memberships to `member`; returns how many changed.
///
/// Lepton used to give every new user `owner` on their own account, so
/// [`resync_eligible_super_user_group_members`](crate::super_user::resync_eligible_super_user_group_members)
/// promoted everyone who signed up. Sign-up now gives `member`, and `owner`
/// means platform owner. Rows written before that change still say `owner`;
/// this run-once pass corrects them.
///
/// Users whose primary email is in `keep_owner_emails` (the host's
/// `UF_SUPER_USER_EMAILS`) are the real platform owners and keep `owner`.
/// Super User group membership the old sync already granted is left alone for
/// an operator to review.
pub async fn demote_personal_account_owners_with_valence(
    valence: &Valence,
    keep_owner_emails: &[String],
) -> anyhow::Result<usize> {
    let system = valence.with_actor(Actor::System {
        operation: "demote_personal_account_owners".to_string(),
    });

    let mut keep_user_ids = HashSet::new();
    for email in keep_owner_emails {
        for user in users_with_primary_email(&system, email.trim()).await? {
            if let Some(id) = user.id() {
                keep_user_ids.insert(valence::extract_id_from_record(id)?);
            }
        }
    }

    let owners = AccountMembership::query(&system, valence::use_!(r"When the **personal-account owner migration** runs, we **list memberships with the owner role** so ones created by sign-up can be switched to member. Operators who run the migration use this."))
        .where_role(StringPredicate::Equals("owner".to_string()))
        .await?;

    let mut changed = 0;
    let mut kept = 0;
    for membership in owners {
        if keep_user_ids.contains(&valence::extract_id_from_record(membership.user())?) {
            kept += 1;
            continue;
        }
        membership
            .get_mutable(&system, valence::use_!(r"When the **personal-account owner migration** runs, we **change a sign-up membership from owner to member** so it no longer counts as platform owner. Operators who run the migration use this."))
            .set_role(AccountMembershipRole::Member)?
            .set_updated_at(Utc::now())?
            .commit()
            .await?;
        changed += 1;
    }
    log::info!("[gauge] demote_personal_account_owners: changed={changed} kept={kept}");
    Ok(changed)
}

/// Split a `UF_SUPER_USER_EMAILS` value on commas, semicolons, and whitespace.
fn parse_super_user_emails(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Chronon script (run-once) for [`demote_personal_account_owners_with_valence`],
/// keeping `owner` for the emails in [`SUPER_USER_EMAILS_ENV`].
#[chronon_coordinator_macros::script(
    name = "demote_personal_account_owners",
    default_job(job = "demote-personal-account-owners", run_once)
)]
pub async fn demote_personal_account_owners_script(
    ctx: Box<dyn chronon_core::ScriptContext>,
) -> anyhow::Result<()> {
    let valence = chronon_valence_identity::valence_from_context(&*ctx)?;
    let keep = parse_super_user_emails(std::env::var(SUPER_USER_EMAILS_ENV).ok().as_deref());
    demote_personal_account_owners_with_valence(&valence, &keep)
        .await
        .context("failed switching personal-account owner memberships to member")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_super_user_emails;

    #[test]
    fn parse_super_user_emails_splits_on_separators() {
        assert_eq!(
            parse_super_user_emails(Some(" a@x.com, b@y.com;c@z.com\td@w.com ")),
            ["a@x.com", "b@y.com", "c@z.com", "d@w.com"]
        );
    }

    #[test]
    fn parse_super_user_emails_unset_or_blank_is_empty() {
        assert!(parse_super_user_emails(None).is_empty());
        assert!(parse_super_user_emails(Some("  , ; ")).is_empty());
    }
}
