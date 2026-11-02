//! Client side of the Verifiable Trust Network API. See the crate README.

mod client;
pub mod link;
pub mod status;

pub use client::{ClientError, VtnClient, encode_did, encode_query};
pub use link::SignInLink;
pub use status::{CredentialState, StatusChecker};
