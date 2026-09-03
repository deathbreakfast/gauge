# Security Policy

## Supported versions

Security fixes are accepted against the latest published `0.1.x` release line of
this repository's `gauge` crate. The Orbital admin UI (`gauge-app`) lives in the
sibling [gauge-uf-app](https://github.com/unified-field-dev/gauge-uf-app) repo;
report UI-only issues there when the domain crate is not involved.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Prefer one of the following:

1. **GitHub Security Advisories** — use [Report a vulnerability](https://github.com/unified-field-dev/gauge/security/advisories/new) on this repository when available.
2. Contact the maintainers privately via the repository owner listed at https://github.com/unified-field-dev/gauge.

Include:

- a description of the issue and its impact
- steps to reproduce or a proof of concept when possible
- affected crate names and versions

We will acknowledge receipt as soon as practical and coordinate a fix and disclosure timeline with you.

## Scope

In scope: vulnerabilities in this repository's published crates and documentation that could cause unsafe production defaults, plus CI/supply-chain issues in this repository.

Out of scope: vulnerabilities solely in third-party dependencies unless this project mishandles them in a security-relevant way.

## Actor and Valence privacy (Model A)

Interactive `gauge::service` paths keep the **session actor**. They must not call
`with_actor(Actor::System { .. })` mid-request to bypass Valence. Chronon /
bootstrap jobs that **start** as System via their context factory are separate
(not session elevates).

**Permission history:** all four ops use `defer_to_edge: "source"` (Create →
parent Update; Update → Update; Delete → Delete; Read → Read).
`PermissionHistoryWriter` / `append_history_row` and `delete_history_source`
run under the **session** Valence — no mid-request System elevate. Parent
Permission / PermissionGroup Read is `AUTHENTICATED`, so Valence read of history
follows that floor; `list_history` and gauge-app `get_gauge_history_page` still
filter with can-edit / owner policies via `actor_can_view_history_subject`
(defense-in-depth). Denied viewers get `HISTORY_ACCESS_DENIED` and the dialog
MessageBar.

TM-SEC-06 forbids System elevates in `service/` and `side_effects/` (including
`history_logger.rs`).

Permission and permission-group **update/delete** succeed only for:

1. Super User (`SUPER_USER_GROUP_MEMBER`), or
2. Maintainers on the owners list (`PERMISSION_OWNER_RECURSIVE` / `GROUP_OWNER_RECURSIVE`).

Create may stay authenticated so the creator becomes the first maintainer.
Principal tables carry explicit AUTHENTICATED / SYSTEM_ONLY policies so ownership
walks do not need elevation.

## Super User role sync (F3)

Chronon script `sync_super_user_membership_roles` aligns Super User group membership with Lepton `owner` / `super_admin` account roles. The job binds System **from the script context**, then calls `resync_eligible_super_user_group_members`. Hosts that mint those roles must authorize role assignment in Lepton; gauge treats Super User membership as the break-glass gate for taxonomy mutates.

## CSRF (host-delegated)

gauge-app server functions rely on the host Higgs / Leptos CSRF and cookie posture. This crate does not invent a second CSRF layer. Operators should keep SameSite cookies and Higgs CSRF defaults on the host that mounts `PermissionRoutes`.

Request-submit / decide fanout uses `uf_notifications_core::send_notification` under the session actor. That requires notification Valence create to allow authenticated mint (see uf-notifications SECURITY.md). Do not reintroduce System elevate in the gauge notifier to make send succeed.

## Server function auth map (gauge-app / gauge-uf-app)

Expected contract when a host mounts `PermissionRoutes` from gauge-uf-app:

- **Session required** on every `gauge-app` server function (fail closed).
- **`GaugeAdmin`** required on admin mutations and principal search (`#[uf_product_macros::server(permission = "GaugeAdmin")]`). Runtime deny without GaugeAdmin is covered by gauge-uf-app e2e (`e2e.perm.detail.save_no_admin`, `e2e.group.detail.save_no_admin`, `e2e.search.principals_no_admin`, and related `*_no_admin` scenarios).
- **TOTP step-up (Tier A)** required on privilege-shaped mutations via
  `#[uf_product_macros::server(..., step_up)]` (window) or `step_up = "fresh"`:
  grant/revoke (`add_`/`remove_permission_*`), group membership and ownership,
  nested groups, `decide_permission_request`, `delete_permission` / `delete_group`,
  `update_permission`, and `create_permission`. Routine taxonomy (`create_domain`,
  `create_group`, `update_group`) and request create stay session + GaugeAdmin /
  owner only. Membership and ownership changes on `super_user_group` require a
  fresh TOTP code on that call (window alone is not enough).
- **Owner / Super User** enforced in Valence policies and mirrored in `gauge::service` for defense in depth.
- **Super User** is pinned to well-known group id `super_user_group`; duplicate groups that reuse the display name do not grant privilege. `delete_group` and nested-group membership on that well-known id are blocked in `gauge::service`.
- **`create_permission`** requires the actor to own/control an explicitly supplied `owners_group_id` (default owner group is created when omitted).
- **User-facing reads** (`list`/`get` for permissions, groups, domains) use session-scoped Valence. The grant graph (`allow_list` on permissions; owners and members on groups) is returned only to editors (owners-group maintainers and Super User). Every other authenticated reader gets an empty list — withheld, not "nobody holds this."
- **Catalog enumeration (accepted residual):** any authenticated user can browse every permission and group by name, including resource-scoped rows such as `neutrino_secret.{id}.Reveal`. That browsability is the access-request surface. Revisit if a deployment ever serves more than one tenant.
- **`search_principals`** clamps `max_results` (1..=50) and logs query length only (not the search string).
- **History pagination:** `list_history` must page at the query layer; loading every `PermissionHistory` row and filtering in Rust is not acceptable.
