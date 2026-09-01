#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction
)]
//! Valence-codegen output for the permission domain schemas (`build.rs` + `schemas/`).
//! Generated model types are not hand-documented; see `../schemas/*.rs` for the
//! source-of-truth field definitions.

#[cfg(feature = "ssr")]
use crate::privacy_policies::{
    GROUP_OWNER_RECURSIVE, PERMISSION_OWNER_RECURSIVE, REQUEST_TARGET_MAINTAINER,
    SUPER_USER_GROUP_MEMBER,
};
#[cfg(feature = "ssr")]
use crate::side_effects::history_logger::PermissionHistoryWriter;
#[cfg(feature = "ssr")]
use crate::side_effects::permission_request_notifier::PermissionRequestNotifier;
#[cfg(feature = "ssr")]
use valence::privacy_policies::common::{AUTHENTICATED, BLOCK_ALL, PUBLIC_READ, SYSTEM_ONLY};
#[cfg(feature = "ssr")]
use valence::privacy_policies::owner::{OWNER_BY_ID, OWNER_BY_USER_FIELD};

#[cfg(feature = "ssr")]
include!(concat!(env!("OUT_DIR"), "/generated_models.rs"));
