//! The network's identity, and resolving the identities of parties it deals with.
//!
//! **Provisioned:** a VTA mints the network's `did:webvh` from the `vtn-host` template (`vtn
//! setup`). Its keys are one [`DidSecretsBundle`], kept in the operator's `[secrets]` store
//! and never in `vtn.toml`. The VTA still custodies them; this is the service's working copy,
//! opened once from the sealed provisioning bundle. This follows the pattern of
//! `vti-voting-service` and `vti-witness`.
//!
//! **Development:** with no `[identity]`, a `did:key` from a seed under `data_dir`.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::sealed_transfer::DidKeyMaterialV2;
use vti_common::seed_store::SeedStore;
use vti_vtn::identity::Identity;

use crate::config::Config;

/// The network's identity, as configured.
pub async fn load(config: &Config) -> anyhow::Result<Identity> {
    match &config.identity {
        Some(provisioned) => {
            let secrets = config
                .secrets
                .as_ref()
                .context("[identity] needs a [secrets] store")?;
            let store = vti_secrets::create_seed_store(secrets, &config.data_dir)
                .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
            let bundle = load_keys(&*store).await?.ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no keys in the configured secret store; run `vtn setup --from`",
                    provisioned.did
                )
            })?;
            if bundle.did != provisioned.did {
                anyhow::bail!(
                    "the secret store holds keys for {}, not the configured {}",
                    bundle.did,
                    provisioned.did
                );
            }
            from_bundle(&bundle)
        }
        None => load_dev_seed(&config.seed_path()),
    }
}

/// The network's identity from its provisioned keys: the Ed25519 assertion key.
pub fn from_bundle(bundle: &DidSecretsBundle) -> anyhow::Result<Identity> {
    let signing = bundle
        .trust_task_signing_key()
        .ok_or_else(|| anyhow::anyhow!("{} has no Ed25519 signing key", bundle.did))?;
    Identity::from_private_key_multibase(
        &bundle.did,
        &signing.key_id,
        &signing.private_key_multibase,
    )
    .map_err(|e| anyhow::anyhow!("identity key: {e}"))
}

fn load_dev_seed(path: &Path) -> anyhow::Result<Identity> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {} (run `vtn init` for a development identity, or `vtn setup` to \
             provision one from a VTA)",
            path.display()
        )
    })?;
    let bytes = crate::unhex(text.trim()).context("identity seed is not hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity seed must be 32 bytes"))?;
    Ok(Identity::from_ed25519_seed(&seed))
}

// ------------------------------------------------------------- key store

#[derive(Serialize, Deserialize)]
struct StoredKeys {
    version: u32,
    identity: DidSecretsBundle,
}

const KEYS_VERSION: u32 = 1;

/// The provisioned identity's keys; `None` when nothing is stored yet.
/// The provisioned identity's keys as messaging secrets (its Ed25519 key and its X25519
/// key-agreement key), for its mediator session. `None` without an `[identity]`.
pub async fn session_secrets(
    config: &Config,
) -> anyhow::Result<Option<Vec<affinidi_secrets_resolver::secrets::Secret>>> {
    let Some(provisioned) = &config.identity else {
        return Ok(None);
    };
    let secrets = config
        .secrets
        .as_ref()
        .context("[identity] needs a [secrets] store")?;
    let store = vti_secrets::create_seed_store(secrets, &config.data_dir)
        .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
    let bundle = load_keys(&*store)
        .await?
        .ok_or_else(|| anyhow::anyhow!("{} has no keys in the secret store", provisioned.did))?;
    let secrets = vta_sdk::did_key::secrets_from_bundle(&bundle)
        .map_err(|e| anyhow::anyhow!("identity keys: {e}"))?;
    Ok(Some(secrets))
}

pub async fn load_keys(store: &dyn SeedStore) -> anyhow::Result<Option<DidSecretsBundle>> {
    let Some(bytes) = store
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("read the identity's keys from the secret store: {e}"))?
    else {
        return Ok(None);
    };
    let stored: StoredKeys = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("the stored identity keys do not parse: {e}"))?;
    if stored.version != KEYS_VERSION {
        anyhow::bail!(
            "the stored identity keys are version {}, this binary reads version {KEYS_VERSION}",
            stored.version
        );
    }
    Ok(Some(stored.identity))
}

pub async fn save_keys(store: &dyn SeedStore, identity: &DidSecretsBundle) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&StoredKeys {
        version: KEYS_VERSION,
        identity: identity.clone(),
    })?;
    store
        .set(&bytes)
        .await
        .map_err(|e| anyhow::anyhow!("write the identity's keys to the secret store: {e}"))
}

/// The working copy of the identity's keys from the sealed bundle's key material, each under
/// the verification-method id its DID document publishes.
pub fn bundle_from_material(material: &DidKeyMaterialV2) -> DidSecretsBundle {
    let entry = |key: &vta_sdk::sealed_transfer::SlotKeyPair| SecretEntry {
        key_id: key.key_id.clone(),
        key_type: key.key_type.clone(),
        private_key_multibase: key.private_key_multibase.clone(),
    };
    let mut secrets = vec![entry(&material.signing_key), entry(&material.ka_key)];
    secrets.extend(material.additional_signing_keys.iter().map(entry));
    DidSecretsBundle {
        did: material.did.clone(),
        secrets,
    }
}

// ---------------------------------------------------------------- resolver

/// Resolves parties' keys: `did:key` locally, `did:webvh` (what a VTA-provisioned VTC or VTN
/// is) over the network, accepting a key only if the DID document authorises it for the
/// proof's purpose (VTI-KEY-022). The resolver the VTC and the NNM verify with too.
pub use vti_vtn::resolve::VmKeyResolver as VtaKeyResolver;
