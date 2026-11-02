//! Service configuration (`vtn.toml`).
//!
//! A provisioned network has an `[identity]` table and a `[secrets]` store, both written by
//! `vtn setup --from` once a VTA has minted the identity (VTI-VTN-001). Without `[identity]`
//! the service runs on a development `did:key` from a seed under `data_dir` (`vtn init`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vti_secrets::SecretsConfig;
use vtn_core::groups::RoleDef;
use vtn_core::model::{Framework, Visibility};
use vtn_core::relay::DEFAULT_MAX_HOPS;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Public base URL; status list URLs in issued credentials are built from it.
    pub base_url: String,
    /// Data directory for the store (and the development seed).
    pub data_dir: PathBuf,
    /// DIDs allowed to administer the network: the operators' NNM identities.
    #[serde(default)]
    pub admins: Vec<String>,
    /// A DID resolver sidecar. Unset: resolve directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_url: Option<String>,
    pub network: NetworkConfig,
    #[serde(default)]
    pub membership: MembershipConfig,
    #[serde(default)]
    pub directory: DirectoryConfig,
    /// The roles members register groups for, e.g. `admins`, `notifications`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleDef>,
    #[serde(default)]
    pub relay: RelayConfig,
    /// The VTA-provisioned identity. Absent: development `did:key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ProvisionedIdentity>,
    /// Where the provisioned identity's keys are kept. Required with `[identity]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedIdentity {
    /// The network's `did:webvh`, minted by the VTA.
    pub did: String,
    /// The VTA that minted it and custodies its keys.
    pub vta_did: String,
    /// The VTA context it lives in.
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Identified owner (VTI-VTN-002): a DID or a legal name.
    pub owner: String,
    pub framework: Framework,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipConfig {
    /// Validity of a membership grant, in days. Re-acknowledgement is needed after it
    /// (DTG Core's interim lifecycle control).
    #[serde(default = "default_grant_days")]
    pub grant_validity_days: i64,
}

impl Default for MembershipConfig {
    fn default() -> Self {
        Self {
            grant_validity_days: default_grant_days(),
        }
    }
}

/// Accepting broadcasts from networks this one is a member of, and passing them on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Relay broadcasts from parent networks into this network's groups. Off: deliveries
    /// to this network's network groups are refused.
    #[serde(default = "default_true")]
    pub accept: bool,
    /// Refuse an envelope that has already been through more hops than this.
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
    /// Lifetime of a broadcast this network originates, in hours.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            accept: true,
            max_hops: DEFAULT_MAX_HOPS,
            ttl_hours: default_ttl_hours(),
        }
    }
}

fn default_max_hops() -> usize {
    DEFAULT_MAX_HOPS
}

fn default_ttl_hours() -> i64 {
    72
}

/// Who can see the member directory (and the index and graph, which publish the same set).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    /// `public` (anyone), `members` (members of this network and admins), or `admins`.
    #[serde(default)]
    pub visibility: Visibility,
    /// Show member counts on the landing page even when the directory is restricted.
    #[serde(default = "default_true")]
    pub show_counts: bool,
    /// How many levels of member networks a federated search follows. 0 disables it.
    #[serde(default = "default_federate_depth")]
    pub federate_depth: usize,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            visibility: Visibility::default(),
            show_counts: true,
            federate_depth: default_federate_depth(),
        }
    }
}

fn default_federate_depth() -> usize {
    3
}

fn default_true() -> bool {
    true
}

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8400";

fn default_listen() -> String {
    DEFAULT_LISTEN.into()
}

fn default_grant_days() -> i64 {
    365
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let config: Self =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for admin in &self.admins {
            if !admin.starts_with("did:") {
                errors.push(format!("admins: {admin:?} is not a DID"));
            }
        }
        if self.identity.is_some() && self.secrets.is_none() {
            errors.push("[identity] needs a [secrets] store holding its keys".into());
        }
        let mut seen = std::collections::HashSet::new();
        for role in &self.roles {
            if !vtn_core::groups::valid_role_name(&role.name) {
                errors.push(format!(
                    "roles: {:?} must be lowercase letters, digits, '-' or '_'",
                    role.name
                ));
            }
            if !seen.insert(&role.name) {
                errors.push(format!("roles: {:?} is defined twice", role.name));
            }
        }
        if self.base_url.ends_with('/') {
            errors.push("base_url must not end with '/'".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("configuration errors:\n  - {}", errors.join("\n  - "))
        }
    }

    pub fn to_toml_string(&self) -> anyhow::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn seed_path(&self) -> PathBuf {
        self.data_dir.join("identity.seed")
    }

    pub fn store_dir(&self) -> PathBuf {
        self.data_dir.join("store")
    }
}
