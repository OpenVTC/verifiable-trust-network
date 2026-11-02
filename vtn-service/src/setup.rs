//! `vtn setup`: provision the network's identity from a VTA (VTI-VTN-001). This is the
//! two-phase setup every VTI host service uses (`vti-voting-service`, `vti-witness`, the
//! VTC's headless path).
//!
//! 1. `vtn setup --setup-key-out <path> [--context <id>]` mints an ephemeral `did:key`,
//!    stores it (0600) and prints the `pnm` grant the operator runs at their VTA.
//! 2. *(out of band)* the operator grants that DID admin of the context, and registers the
//!    `vtn-host` DID template (`templates/vtn-host.json`) in it.
//! 3. `vtn setup --from <toml>` asks the VTA to mint the network's `did:webvh` from that
//!    template, opens the sealed bundle, keeps the keys in the `[secrets]` store and writes
//!    `vtn.toml`.
//!
//! The VTA derives the keys; the VTN never does (VTI-VTN-060). There is no admin hand-off:
//! the network administers nothing at the VTA, which is its key custodian and not a party.
//! The network's own administrators are the DIDs in `admins`, signing in with the NNM.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, ProvisionAsk, ProvisionResultV2, VtaEvent, VtaIntent,
    VtaReply, run_connection_test, run_provision_flight,
};
use vti_secrets::{SecretBackend, SecretsConfig};

use crate::config::{
    Config, DEFAULT_LISTEN, DirectoryConfig, MembershipConfig, NetworkConfig, ProvisionedIdentity,
};
use crate::identity::{bundle_from_material, load_keys, save_keys};

/// The VTA context the identity is provisioned into unless the operator names another.
pub const DEFAULT_CONTEXT: &str = "vtn";
/// The DID template the VTA renders the network's identity from.
pub const VTN_HOST_TEMPLATE: &str = "vtn-host";

pub struct VtnMessages;

impl OperatorMessages for VtnMessages {
    fn integration_label(&self) -> &str {
        "Verifiable Trust Network"
    }
    fn integration_label_lower(&self) -> &str {
        "verifiable trust network"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"Verifiable Trust Network\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h\n\n  \
             and register the DID template the network is minted from:\n\n    \
             pnm did-templates create templates/vtn-host.json --context {context_id}"
        )
    }
}

/// Phase 1: mint and store the ephemeral setup key, and print the grant.
pub async fn run_phase1(out_path: &Path, context: &str) -> anyhow::Result<()> {
    let finalise = format!(
        "vtn setup --from <your-setup.toml>   (with setup_key_file = \"{}\")",
        out_path.display()
    );
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut std::io::stderr(),
        out_path,
        context,
        &VtnMessages,
        Some(&finalise),
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint the setup key: {e}"))
}

/// The setup file for `vtn setup --from <toml>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInputs {
    /// Where to write `vtn.toml`. Setup refuses to overwrite one.
    pub config_path: PathBuf,
    /// The data directory. Defaults to `data/` beside `config_path`.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub listen: Option<String>,
    /// Public HTTPS base of the VTN API (no trailing slash). Advertised in the DID document.
    pub base_url: String,
    /// The operator's VTA, which mints the identity.
    pub vta_did: String,
    /// The VTA context to provision into. Defaults to `vtn`.
    #[serde(default = "default_context")]
    pub context: String,
    /// The DID template to render. Defaults to `vtn-host`.
    #[serde(default = "default_template")]
    pub template: String,
    /// The phase-1 key file, whose DID has been granted admin of `context`.
    pub setup_key_file: PathBuf,
    #[serde(default)]
    pub resolver_url: Option<String>,
    /// Where the identity's keys are kept.
    pub secrets: SecretsConfig,
    /// The network's administrators: the DIDs their NNMs sign in as. At least one.
    pub admins: Vec<String>,
    /// A registered DID-hosting server to publish the DID log to.
    #[serde(default)]
    pub webvh_server: Option<String>,
    /// Serverless: the URL the operator will serve the DID log from.
    #[serde(default)]
    pub url: Option<String>,
    pub network: NetworkConfig,
    #[serde(default)]
    pub membership: MembershipConfig,
    #[serde(default)]
    pub directory: DirectoryConfig,
}

fn default_context() -> String {
    DEFAULT_CONTEXT.to_string()
}

fn default_template() -> String {
    VTN_HOST_TEMPLATE.to_string()
}

impl SetupInputs {
    /// Parse and validate a setup file, refusing unknown keys at any depth.
    pub fn from_toml_str(raw: &str) -> anyhow::Result<Self> {
        let mut ignored = Vec::new();
        let de = toml::Deserializer::parse(raw)?;
        let inputs: Self = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))?;
        if !ignored.is_empty() {
            anyhow::bail!("unknown key(s) in the setup file: {}", ignored.join(", "));
        }
        inputs.validate()?;
        Ok(inputs)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        if !self.vta_did.starts_with("did:") {
            errors.push(format!("vta_did must be a DID (got {:?})", self.vta_did));
        }
        if !self.base_url.starts_with("https://") || self.base_url.ends_with('/') {
            errors.push(format!(
                "base_url must be https:// with no trailing slash (got {:?})",
                self.base_url
            ));
        }
        if self.admins.is_empty() {
            errors.push(
                "admins must name at least one DID (create one with `nnm keys generate`)".into(),
            );
        }
        for admin in &self.admins {
            if !admin.starts_with("did:") {
                errors.push(format!("admins: {admin:?} is not a DID"));
            }
        }
        if self.context.trim().is_empty() {
            errors.push("context must not be empty".into());
        }
        if matches!(self.secrets.backend, Some(SecretBackend::ConfigSeed)) {
            errors.push(
                "secrets.backend = \"config_seed\" would keep the identity's keys in vtn.toml"
                    .into(),
            );
        }
        match (&self.webvh_server, &self.url) {
            (None, None) => errors.push(
                "name webvh_server (a registered DID-hosting server) or url (where you will serve \
                 the DID log yourself): the VTA needs one to know where the log goes"
                    .into(),
            ),
            (_, Some(url)) if !url.starts_with("https://") => {
                errors.push(format!("url must start with https:// (got {url:?})"));
            }
            _ => {}
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "the setup file has {} error(s):\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            )
        }
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(|| {
            self.config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("data")
        })
    }

    /// The provisioning ask: the `vtn-host` template at the API URL, no admin hand-off.
    pub fn ask(&self) -> ProvisionAsk {
        let mut vars = BTreeMap::new();
        vars.insert("API_URL".to_string(), Value::String(self.base_url.clone()));
        for (key, value) in [("URL", &self.url), ("WEBVH_SERVER", &self.webvh_server)] {
            if let Some(value) = value {
                vars.insert(key.to_string(), Value::String(value.clone()));
            }
        }
        let mut ask = ProvisionAsk::for_template(&self.template, vars, &self.context)
            .with_label("vtn-service");
        ask.admin_template = None;
        ask.admin_template_vars.clear();
        ask
    }
}

/// Phase 2: provision the identity, keep its keys, write the configuration.
pub async fn run_from_file(path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let inputs =
        SetupInputs::from_toml_str(&raw).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if inputs.config_path.exists() {
        anyhow::bail!(
            "{} already exists. Setup does not overwrite a configuration; move it aside to \
             provision a new identity.",
            inputs.config_path.display()
        );
    }
    let setup_key = EphemeralSetupKey::load_from(&inputs.setup_key_file).map_err(|e| {
        anyhow::anyhow!(
            "load the setup key {}: {e}. Run `vtn setup --setup-key-out <path>` first and grant \
             the DID it prints.",
            inputs.setup_key_file.display()
        )
    })?;

    // The store first, so a misconfigured backend fails before anything is minted; and
    // empty, because these keys are this host's only copy.
    let data_dir = inputs.data_dir();
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", data_dir.display()))?;
    let store = vti_secrets::create_seed_store(&inputs.secrets, &data_dir)
        .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
    if load_keys(&*store).await?.is_some() {
        anyhow::bail!(
            "the configured secret store already holds identity keys. Setup does not overwrite \
             them; point [secrets] at an empty entry."
        );
    }

    eprintln!(
        "Provisioning the network identity from {} (template {}) ...",
        inputs.vta_did, inputs.template
    );
    let result = provision(&inputs.vta_did, &setup_key, inputs.ask()).await?;
    let (Some(did), Some(material)) = (result.integration_did(), result.integration_key()) else {
        anyhow::bail!("the VTA's bundle carries no integration DID or keys");
    };
    let did = did.to_string();

    save_keys(&*store, &bundle_from_material(material)).await?;
    if !store.set_persists_across_restart() {
        eprintln!(
            "warning: the configured secret store does not survive a restart; the identity's \
             keys will be lost with this process"
        );
    }
    let did_log = match result.webvh_log() {
        Some(log) => {
            let p = data_dir.join("did.jsonl");
            std::fs::write(&p, log).map_err(|e| anyhow::anyhow!("write {}: {e}", p.display()))?;
            Some(p)
        }
        None => None,
    };

    let config = Config {
        listen: inputs
            .listen
            .clone()
            .unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
        base_url: inputs.base_url.clone(),
        data_dir: data_dir.clone(),
        admins: inputs.admins.clone(),
        resolver_url: inputs.resolver_url.clone(),
        network: inputs.network.clone(),
        membership: inputs.membership.clone(),
        directory: inputs.directory.clone(),
        identity: Some(ProvisionedIdentity {
            did: did.clone(),
            vta_did: inputs.vta_did.clone(),
            context: inputs.context.clone(),
        }),
        secrets: Some(inputs.secrets.clone()),
    };
    config.validate()?;
    if let Some(parent) = inputs
        .config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&inputs.config_path, config.to_toml_string()?)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", inputs.config_path.display()))?;
    vti_common::secure_file::restrict_file_to_owner(&inputs.config_path)
        .map_err(|e| anyhow::anyhow!("restrict {}: {e}", inputs.config_path.display()))?;

    println!("VTN setup complete.");
    println!("config_path={}", inputs.config_path.display());
    println!("vtn_did={did}");
    if let Some(p) = did_log {
        println!(
            "did_log={}  (serve it at the URL the DID names)",
            p.display()
        );
    }
    println!(
        "The setup DID {} keeps its grant until --admin-expires; remove it sooner with \
         `pnm acl delete --did {}`.",
        setup_key.did, setup_key.did
    );
    println!(
        "Start the service: vtn --config {} serve",
        inputs.config_path.display()
    );
    println!(
        "Then sign in from the NNM: nnm networks add <name> {}",
        inputs.base_url
    );
    Ok(())
}

async fn provision(
    vta_did: &str,
    setup_key: &EphemeralSetupKey,
    ask: ProvisionAsk,
) -> anyhow::Result<ProvisionResultV2> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(run_connection_test(
        VtaIntent::FullSetup,
        vta_did.to_string(),
        setup_key.did.clone(),
        setup_key.private_key_multibase().to_string(),
        ask.clone(),
        None,
        tx,
    ));
    let reply = 'outer: loop {
        match rx.recv().await {
            Some(VtaEvent::Connected { reply, .. }) => break reply,
            Some(VtaEvent::Failed(msg)) => return Err(provision_failed(&msg)),
            Some(VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                ..
            }) => {
                let (ftx, mut frx) = mpsc::unbounded_channel();
                tokio::spawn(run_provision_flight(
                    vta_did.to_string(),
                    setup_key.did.clone(),
                    setup_key.private_key_multibase().to_string(),
                    mediator_did,
                    rest_url,
                    ask.clone(),
                    None,
                    None,
                    Arc::new(VtnMessages),
                    ftx,
                ));
                loop {
                    match frx.recv().await {
                        Some(VtaEvent::Connected { reply, .. }) => break 'outer reply,
                        Some(VtaEvent::Failed(msg)) => return Err(provision_failed(&msg)),
                        Some(_) => {}
                        None => {
                            return Err(provision_failed(
                                "provisioning ended without a terminal event",
                            ));
                        }
                    }
                }
            }
            Some(_) => {}
            None => {
                return Err(provision_failed(
                    "provisioning ended without a terminal event",
                ));
            }
        }
    };
    match reply {
        VtaReply::Full(result) => Ok(*result),
        VtaReply::AdminOnly(_) => Err(anyhow::anyhow!(
            "the VTA answered with an admin credential only; the vtn-host template needs a full \
             provisioning reply"
        )),
    }
}

fn provision_failed(msg: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "VTA provisioning failed: {msg}. Check the VTA DID; that the setup DID was granted admin \
         of the context (`pnm contexts create … --admin-did <setup DID>`, or `pnm acl create` if \
         the context exists); and that the `vtn-host` template is registered in it (`pnm \
         did-templates create templates/vtn-host.json --context <context>`)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETUP: &str = r#"
        config_path = "/etc/vtn/vtn.toml"
        base_url = "https://whn.example.org"
        vta_did = "did:webvh:QmVTA:vta.example.com"
        setup_key_file = "/etc/vtn/setup.key"
        url = "https://whn.example.org/did"
        admins = ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]

        [secrets]
        backend = "plaintext"

        [network]
        name = "World Health Network"
        owner = "WHN Secretariat"

        [network.framework]
        iri = "https://whn.example.org/gf"
        version = "1.0"
    "#;

    #[test]
    fn the_ask_names_the_vtn_host_template_and_api_url() {
        let inputs = SetupInputs::from_toml_str(SETUP).unwrap();
        assert_eq!(inputs.context, DEFAULT_CONTEXT);
        let ask = inputs.ask();
        assert_eq!(ask.integration_template.as_deref(), Some(VTN_HOST_TEMPLATE));
        let vars = &ask.integration_template_vars;
        assert_eq!(vars["API_URL"], "https://whn.example.org");
        assert_eq!(vars["URL"], "https://whn.example.org/did");
        assert!(
            ask.admin_template.is_none(),
            "no VTA credential reaches the VTN"
        );
    }

    #[test]
    fn setup_needs_an_admin_and_https() {
        let raw = SETUP
            .replace(
                "admins = [\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\"]",
                "admins = []",
            )
            .replace("https://whn.example.org\"\n", "http://whn.example.org\"\n");
        let err = SetupInputs::from_toml_str(&raw).unwrap_err().to_string();
        assert!(err.contains("admins"), "{err}");
        assert!(err.contains("base_url"), "{err}");
    }

    #[test]
    fn the_template_file_is_what_setup_asks_for() {
        let template: Value =
            serde_json::from_str(include_str!("../../templates/vtn-host.json")).unwrap();
        assert_eq!(template["name"], VTN_HOST_TEMPLATE);
        assert_eq!(template["requiredVars"], serde_json::json!(["API_URL"]));
    }
}
