//! The Verifiable Trust Network service.
//!
//! [`network::Network`] holds the logic, [`routes`] exposes it over HTTP, and [`store`]
//! persists it in a `vti-common` store (fjall), the same backend the VTA and VTC use. The
//! API is `vtn/*` Trust Tasks ([`tasks`]); [`routes`] serves only what is fetched by URL. The
//! network's identity is provisioned by a VTA ([`setup`], [`identity`]). Every request is
//! signed, and its signer is the caller ([`auth`]).

pub mod auth;
pub mod broadcast;
pub mod config;
pub mod error;
pub mod federation;
pub mod groups;
pub mod identity;
pub mod memberships;
pub mod network;
pub mod registry;
pub mod rooms;
pub mod routes;
pub mod setup;
pub mod store;
pub mod tasks;

use std::sync::Arc;

use anyhow::Context;
use vti_vtn::identity::Identity;
use vti_vtn::model::NetworkProfile;
use vti_vtn::verify::KeyResolver;

use crate::auth::Auth;
use crate::config::Config;
use crate::identity::VtaKeyResolver;
use crate::network::{Network, Settings};
use crate::routes::AppState;
use crate::store::VtnStore;

/// Create a development `did:key` seed if absent. Returns the network DID. A provisioned
/// network (`[identity]` in the configuration) is refused: its identity comes from its VTA.
pub fn init_dev(config: &Config) -> anyhow::Result<String> {
    if config.identity.is_some() {
        anyhow::bail!(
            "this network's identity is provisioned by its VTA ({}); `vtn init` is for a \
             development identity only",
            config
                .identity
                .as_ref()
                .map(|i| i.vta_did.as_str())
                .unwrap_or_default()
        );
    }
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating {}", config.data_dir.display()))?;
    if !config.seed_path().exists() {
        vti_common::secure_file::write_secret_file(
            &config.seed_path(),
            hex(&random_bytes()).as_bytes(),
        )
        .with_context(|| format!("writing {}", config.seed_path().display()))?;
    }
    let seed = std::fs::read_to_string(config.seed_path())?;
    let bytes = unhex(seed.trim()).context("identity seed is not hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity seed must be 32 bytes"))?;
    Ok(Identity::from_ed25519_seed(&seed).did().to_string())
}

/// Everything the router needs, from configuration, resolving parties over the network.
pub async fn build_state(config: &Config) -> anyhow::Result<AppState> {
    let resolver = VtaKeyResolver::network(config.resolver_url.as_deref()).await?;
    build_state_with(config, Arc::new(resolver)).await
}

/// [`build_state`] with a given resolver (tests use [`VtaKeyResolver::offline`]).
pub async fn build_state_with(
    config: &Config,
    resolver: Arc<dyn KeyResolver>,
) -> anyhow::Result<AppState> {
    config.validate()?;
    let identity = identity::load(config).await?;
    if config.admins.is_empty() {
        tracing::warn!("no admins configured: nobody can administer this network");
    }
    let store = VtnStore::open(&config.store_dir()).context("opening store")?;
    let profile = NetworkProfile {
        did: identity.did().to_string(),
        name: config.network.name.clone(),
        description: config.network.description.clone(),
        owner: config.network.owner.clone(),
        framework: config.network.framework.clone(),
    };
    let auth = Auth::new(config.admins.clone());
    let mut extra_roots = Vec::new();
    for path in &config.extra_root_certificates {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        extra_roots.extend(
            reqwest::Certificate::from_pem_bundle(&pem)
                .with_context(|| format!("{} is not a PEM certificate bundle", path.display()))?,
        );
    }
    let accepted = crate::tasks::accepted::StoreAcceptedIds::new(store.accepted_ids().clone());
    let network = Network::new(
        profile,
        identity,
        config.base_url.clone(),
        store,
        resolver,
        Settings {
            grant_validity: chrono::Duration::days(config.membership.grant_validity_days),
            roles: config.roles.clone(),
            relay: config.relay.clone(),
            directory: config.directory.clone(),
            rooms: config.rooms.clone(),
            status_cache: chrono::Duration::seconds(config.status_cache_seconds.max(0)),
            extra_roots,
        },
    );
    Ok(AppState {
        network: Arc::new(network),
        auth: Arc::new(auth),
        directory: config.directory.clone(),
        accepted,
        sign_in: config.auth.clone(),
        registry: config.registry.clone(),
    })
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    bytes
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}
