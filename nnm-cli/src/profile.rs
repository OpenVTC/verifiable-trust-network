//! The NNM profile: the operator's admin identity and the networks it administers.
//!
//! Kept at `$NNM_HOME/profile.json` (default `~/.nnm/profile.json`), owner-only.
//! **Assumption A11:** the admin key is held in this file. PNM and CNM keep keys in the OS
//! keyring or at a VTA; moving the NNM there is a storage change, not a protocol one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use vtn_core::identity::Identity;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminKey>,
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network: Option<String>,
}

/// The operator's admin DID and its Ed25519 key. A `did:key` the NNM generated, or a DID a
/// VTA minted and the operator imported.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AdminKey {
    pub did: String,
    pub key_id: String,
    pub private_key_multibase: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkRef {
    pub url: String,
    pub did: String,
}

impl AdminKey {
    pub fn generate() -> anyhow::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random seed: {e}"))?;
        let identity = Identity::from_ed25519_seed(&seed);
        let secret = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(
            Some(identity.verification_method()),
            Some(&seed),
        );
        Ok(Self {
            did: identity.did().to_string(),
            key_id: identity.verification_method().to_string(),
            private_key_multibase: secret
                .get_private_keymultibase()
                .map_err(|e| anyhow::anyhow!("encode key: {e}"))?,
        })
    }

    pub fn identity(&self) -> anyhow::Result<Identity> {
        Identity::from_private_key_multibase(&self.did, &self.key_id, &self.private_key_multibase)
            .map_err(|e| anyhow::anyhow!("admin key: {e}"))
    }
}

pub fn default_path() -> PathBuf {
    if let Ok(home) = std::env::var("NNM_HOME") {
        return PathBuf::from(home).join("profile.json");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".nnm").join("profile.json")
}

impl Profile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            file.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn admin(&self) -> anyhow::Result<&AdminKey> {
        self.admin
            .as_ref()
            .context("no admin key: run `nnm keys generate` or `nnm keys import`")
    }

    /// The network named `name`, or the default one.
    pub fn network(&self, name: Option<&str>) -> anyhow::Result<(&str, &NetworkRef)> {
        let name = name
            .or(self.default_network.as_deref())
            .context("no network selected: `nnm networks add <name> <url>`, or pass --network")?;
        let (name, net) = self
            .networks
            .get_key_value(name)
            .with_context(|| format!("no network named {name:?} (`nnm networks list`)"))?;
        Ok((name.as_str(), net))
    }
}
