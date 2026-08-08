// `#[tonic::async_trait]` (used in `service.rs`) generates `#[must_use]` futures.
// Newer clippy (CI runs on nightly) flags this as `clippy::double_must_use` because
// `futures::Future` is already `#[must_use]`. This is a false positive on
// macro-generated code we don't control, so we allow it here.
#![allow(clippy::double_must_use)]

pub mod auth;
pub mod ca {
    pub mod v1 {
        tonic::include_proto!("gm.ca.v1");

        pub use ca_service_server::CaService;
    }
}
pub mod cert;
pub mod db;
pub mod error;
pub mod metrics;
pub mod service;
