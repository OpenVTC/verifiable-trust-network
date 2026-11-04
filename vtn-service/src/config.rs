//! Service configuration (`vtn.toml`).
//!
//! A provisioned network has an `[identity]` table and a `[secrets]` store, both written by
//! `vtn setup --from` once a VTA has minted the identity (VTI-VTN-001). Without `[identity]`
//! the service runs on a development `did:key` from a seed under `data_dir` (`vtn init`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vti_secrets::SecretsConfig;
use vti_vtn::groups::RoleDef;
use vti_vtn::model::{Framework, Visibility};
use vti_vtn::relay::DEFAULT_MAX_HOPS;

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
    /// How long a fetched status list (of a community or member network) is trusted before
    /// refetching. A revocation elsewhere can take this long to be seen here.
    #[serde(default = "default_status_cache")]
    pub status_cache_seconds: i64,
    /// A DID resolver sidecar. Unset: resolve directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_url: Option<String>,
    /// PEM files of certificate authorities to trust, beside the system's, when this
    /// network calls another party over HTTPS: a private CA in a closed deployment.
    /// Endpoints are always `https://` (`vtn/groups/register`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_root_certificates: Vec<PathBuf>,
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
    /// Browser sign-in (`auth/oob/*`, A13).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Rooms the network opens for a role (design §5.4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rooms: Vec<crate::rooms::RoomDef>,
    /// The VTA-provisioned identity. Absent: development `did:key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ProvisionedIdentity>,
    /// Where the provisioned identity's keys are kept. Required with `[identity]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsConfig>,
}

/// Browser sign-in: a wallet approves the landing page's key (`auth/oob/*`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// How long a browser key the wallet approved may sign as its approver, in hours: at
    /// most 24 (A20). The grant's own end is the other bound; the earlier one applies.
    #[serde(default = "default_browser_key_hours")]
    pub browser_key_hours: u64,
    /// The host of the trigger link the landing page shows a wallet (VTI-LNK-060): a
    /// universal-link domain, never this network's own (VTI-LNK-084).
    #[serde(default = "default_link_host")]
    pub link_host: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            browser_key_hours: default_browser_key_hours(),
            link_host: default_link_host(),
        }
    }
}

fn default_link_host() -> String {
    vti_oob_server::DEFAULT_LINK_HOST.to_string()
}

fn default_browser_key_hours() -> u64 {
    8
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
    /// Lifetime of a broadcast this network originates, in hours: at most 168 (7 days, A20).
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: i64,
    /// Delivery attempts per group before giving up (the first included).
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// First retry delay in seconds; doubles each attempt, capped at an hour.
    #[serde(default = "default_retry_base")]
    pub retry_base_seconds: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            accept: true,
            max_hops: DEFAULT_MAX_HOPS,
            ttl_hours: default_ttl_hours(),
            max_attempts: default_max_attempts(),
            retry_base_seconds: default_retry_base(),
        }
    }
}

fn default_max_hops() -> usize {
    DEFAULT_MAX_HOPS
}

fn default_ttl_hours() -> i64 {
    24
}

fn default_max_attempts() -> u32 {
    8
}

fn default_retry_base() -> i64 {
    30
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

fn default_status_cache() -> i64 {
    300
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
            if !vti_vtn::groups::valid_role_name(&role.name) {
                errors.push(format!(
                    "roles: {:?} must be lowercase letters, digits, '-' or '_'",
                    role.name
                ));
            }
            if !seen.insert(&role.name) {
                errors.push(format!("roles: {:?} is defined twice", role.name));
            }
        }
        let portal_host = self
            .base_url
            .split("://")
            .nth(1)
            .map(|rest| rest.split(['/', ':']).next().unwrap_or(rest));
        if let Err(e) = vti_oob_server::check_link_host(&self.auth.link_host, portal_host) {
            errors.push(format!("auth: link_host: {e}"));
        }
        if !(1..=24).contains(&self.auth.browser_key_hours) {
            errors.push(format!(
                "auth: browser_key_hours must be 1..=24 (A20), not {}",
                self.auth.browser_key_hours
            ));
        }
        if !(1..=24 * 7).contains(&self.relay.ttl_hours) {
            errors.push(format!(
                "relay: ttl_hours must be 1..=168 (a broadcast lasts at most 7 days), not {}",
                self.relay.ttl_hours
            ));
        }
        for room in &self.rooms {
            if !valid_room_id(&room.id) {
                errors.push(format!(
                    "rooms: id {:?} must start with a lowercase letter or digit, then up to 62 \
                     lowercase letters, digits or '-'",
                    room.id
                ));
            }
            if !self.roles.iter().any(|r| r.name == room.role) {
                errors.push(format!(
                    "rooms: {:?} is for role {:?}, which is not defined",
                    room.id, room.role
                ));
            }
            if room.pass_minutes <= 0 || room.pass_minutes > 24 * 60 {
                errors.push(format!(
                    "rooms: {:?} pass_minutes must be 1..=1440",
                    room.id
                ));
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

/// A room id as `vtn/_shared/0.1` `RoomDef.id` has it: `^[a-z0-9][a-z0-9-]{0,62}$`.
fn valid_room_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
