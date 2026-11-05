//! `nnm`: the Network Network Manager. It is the operator's CLI for Verifiable Trust
//! Networks, as `pnm` is for a person and `cnm` for a community.

mod profile;
mod registry;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_rs::RequestPayload;
use vti_specs_vtn::vtn as specs;
use vti_vtn::VtnClient;
use vti_vtn::identity::Identity;
use vti_vtn::resolve::VmKeyResolver;

use crate::profile::{AdminKey, NetworkRef, Profile};

#[derive(Parser)]
#[command(
    name = "nnm",
    about = "Network Network Manager: administer Verifiable Trust Networks",
    version
)]
struct Cli {
    /// Profile file. Default: $NNM_HOME/profile.json, or ~/.nnm/profile.json.
    #[arg(long, global = true)]
    profile: Option<PathBuf>,
    /// The network to act on (a name from `nnm networks list`). Default: the selected one.
    #[arg(long, short, global = true)]
    network: Option<String>,
    /// A DID resolver to verify the network's answers through. Default: resolve directly.
    #[arg(long, global = true)]
    resolver_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The operator's admin identity.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// The networks this NNM administers.
    #[command(subcommand)]
    Networks(NetworksCommand),
    /// Show the selected network and check that it takes you as an administrator.
    Status,
    /// List entries, or show one in full.
    Entries {
        /// Show this entry, with its credentials and history.
        did: Option<String>,
    },
    /// List a community or network (one-sided, VTI-VTN-010).
    List {
        did: String,
        #[arg(long, value_enum)]
        kind: Kind,
        #[arg(long)]
        label: Option<String>,
        #[command(flatten)]
        profile: ProfileArgs,
    },
    /// Invite a community or network: list it (unless it is listed already), then print
    /// the invitation its administrator accepts. A community accepts in its operator
    /// console (Networks, Join), which `--console` links to directly.
    Invite {
        did: String,
        #[arg(long, value_enum, default_value = "community")]
        kind: Kind,
        #[arg(long)]
        label: Option<String>,
        /// The community's operator console (its public URL). Default: `--url`, or the
        /// URL already on its entry.
        #[arg(long)]
        console: Option<String>,
        #[command(flatten)]
        profile: ProfileArgs,
    },
    /// Edit an entry's directory profile (name, description, URL, tags). Changes only what
    /// you name (an empty value clears it); re-issues no credential.
    Profile {
        did: String,
        #[arg(long)]
        label: Option<String>,
        #[command(flatten)]
        profile: ProfileArgs,
    },
    /// Search the member directory, as the landing page does.
    Directory {
        /// Free text: every term must match the name, description, tags or DID.
        query: Vec<String>,
        #[arg(long, value_enum)]
        kind: Option<Kind>,
        /// Only acknowledged members.
        #[arg(long)]
        members_only: bool,
        /// Also search member networks' indexes, showing the path to each result.
        #[arg(long)]
        federated: bool,
    },
    /// The roles members register groups for.
    Roles,
    /// Groups members registered, optionally for one role.
    Groups {
        #[arg(long)]
        role: Option<String>,
    },
    /// Broadcast to every group registered for a role, cascading through member networks.
    Broadcast {
        #[arg(long)]
        role: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        body: String,
        /// notice, request-for-action, room-invite, …
        #[arg(long, default_value = "notice")]
        class: String,
        /// Where replies go, e.g. a network data room.
        #[arg(long)]
        reply_to: Option<String>,
    },
    /// Broadcasts sent and relayed, or one with its receipts.
    Broadcasts { id: Option<String> },
    /// The network's rooms.
    Rooms,
    /// Deliveries queued for retry.
    Outbox {
        /// Retry every queued delivery now.
        #[arg(long)]
        retry: bool,
    },
    /// This network's memberships of other networks.
    #[command(subcommand)]
    Memberships(MembershipsCommand),
    /// What the trust registry says about this network's members, asked of the registry.
    #[command(subcommand)]
    Registry(registry::RegistryCommand),
    /// Suspend a member.
    Suspend {
        did: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift a suspension.
    Reinstate {
        did: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Delist a party. Every credential the network issued for the entry is revoked.
    Remove {
        did: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// The network's DTG graph (JSON): one edge per credential.
    Graph {
        /// Include removed and departed entries.
        #[arg(long)]
        include_exited: bool,
        /// Write to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// The network's signed index (a public directory only; see `entries`).
    Index,
    /// The audit log.
    Audit,
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Generate a `did:key` admin identity. Put its DID in the network's `admins`.
    Generate {
        /// Replace an existing admin key.
        #[arg(long)]
        force: bool,
    },
    /// Import an admin DID's Ed25519 key, e.g. one a VTA minted for you.
    Import {
        #[arg(long)]
        did: String,
        /// Verification method, e.g. `did:webvh:…#key-0`.
        #[arg(long)]
        key_id: String,
        /// Multibase (base58btc, multicodec-prefixed) private key, as `pnm` exports it.
        #[arg(long)]
        private_key_multibase: String,
        #[arg(long)]
        force: bool,
    },
    /// Print the admin DID.
    Show,
}

#[derive(Subcommand)]
enum MembershipsCommand {
    /// Networks this one is a member of.
    List,
    /// Accept a parent network's listing of this network. Each role the parent requires
    /// is served by this network's role of the same name unless mapped with --role.
    Join {
        /// The parent network's URL.
        url: String,
        /// The parent's DID, if you know it: the network at `url` must answer as it.
        /// Default: whatever `url` answers as, which is printed.
        #[arg(long)]
        parent: Option<String>,
        /// `<parent role>=<local role>`, repeatable.
        #[arg(long = "role", value_parser = parse_mapping)]
        roles: Vec<(String, String)>,
    },
    /// Serve another of the parent's roles with one of this network's.
    Serve {
        parent: String,
        /// `<parent role>=<local role>`.
        #[arg(value_parser = parse_mapping)]
        mapping: (String, String),
    },
    /// Leave a parent network (repudiate its grant).
    Leave { parent: String },
    /// Repudiate a parent network's listing of this one.
    Repudiate {
        url: String,
        /// The parent's DID (default: whatever `url` answers as).
        #[arg(long)]
        parent: Option<String>,
    },
}

fn parse_mapping(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((p, l)) if !p.is_empty() && !l.is_empty() => Ok((p.into(), l.into())),
        _ if !s.is_empty() && !s.contains('=') => Ok((s.into(), s.into())),
        _ => Err(format!("expected <parent role>=<local role>, got {s:?}")),
    }
}

#[derive(Subcommand)]
enum NetworksCommand {
    /// Add a network by its URL, and select it.
    Add { name: String, url: String },
    /// List the networks.
    List,
    /// Select the network commands act on.
    Use { name: String },
    /// Forget a network.
    Remove { name: String },
}

#[derive(clap::Args, Default)]
struct ProfileArgs {
    #[arg(long)]
    description: Option<String>,
    /// The party's site, or a network's landing page.
    #[arg(long)]
    url: Option<String>,
    /// A search term (repeatable): sector, jurisdiction, specialty.
    #[arg(long = "tag")]
    tags: Vec<String>,
}

impl ProfileArgs {
    /// The fields given, and only those.
    fn json(&self) -> Value {
        let mut body = serde_json::Map::new();
        if let Some(d) = &self.description {
            body.insert("description".into(), json!(d));
        }
        if let Some(u) = &self.url {
            body.insert("url".into(), json!(u));
        }
        if !self.tags.is_empty() {
            body.insert("tags".into(), json!(self.tags));
        }
        Value::Object(body)
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Community,
    Network,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Community => "community",
            Kind::Network => "network",
        }
    }
}

fn print(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = cli.profile.clone().unwrap_or_else(profile::default_path);
    let mut profile = Profile::load(&path)?;

    match cli.command {
        Command::Keys(cmd) => keys(cmd, &mut profile, &path),
        Command::Networks(cmd) => networks(cmd, &mut profile, &path).await,
        command => {
            admin_command(
                command,
                &profile,
                cli.network.as_deref(),
                cli.resolver_url.as_deref(),
            )
            .await
        }
    }
}

fn keys(cmd: KeysCommand, profile: &mut Profile, path: &std::path::Path) -> anyhow::Result<()> {
    let replace = |force: bool, profile: &Profile| -> anyhow::Result<()> {
        if profile.admin.is_some() && !force {
            anyhow::bail!(
                "an admin key already exists ({}); pass --force to replace it",
                profile
                    .admin
                    .as_ref()
                    .map(|a| a.did.as_str())
                    .unwrap_or_default()
            );
        }
        Ok(())
    };
    match cmd {
        KeysCommand::Generate { force } => {
            replace(force, profile)?;
            let key = AdminKey::generate()?;
            println!("{}", key.did);
            eprintln!(
                "Add this DID to the network's `admins` (vtn.toml, or the setup file's `admins`)."
            );
            profile.admin = Some(key);
            profile.save(path)
        }
        KeysCommand::Import {
            did,
            key_id,
            private_key_multibase,
            force,
        } => {
            replace(force, profile)?;
            let key = AdminKey {
                did,
                key_id,
                private_key_multibase,
            };
            key.identity()?; // refuse a key that does not belong to the DID
            println!("{}", key.did);
            profile.admin = Some(key);
            profile.save(path)
        }
        KeysCommand::Show => {
            println!("{}", profile.admin()?.did);
            Ok(())
        }
    }
}

async fn networks(
    cmd: NetworksCommand,
    profile: &mut Profile,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    match cmd {
        NetworksCommand::Add { name, url } => {
            let url = url.trim_end_matches('/').to_string();
            let info = VtnClient::new(&url)
                .profile()
                .await
                .with_context(|| format!("reading {url}/.well-known/vtn"))?;
            let did = info["did"]
                .as_str()
                .context("the service did not name its DID")?
                .to_string();
            println!(
                "{name}: {} ({did})",
                info["profile"]["name"].as_str().unwrap_or("unnamed")
            );
            profile
                .networks
                .insert(name.clone(), NetworkRef { url, did });
            profile.default_network = Some(name);
            profile.save(path)
        }
        NetworksCommand::List => {
            for (name, net) in &profile.networks {
                let mark = if profile.default_network.as_deref() == Some(name) {
                    "*"
                } else {
                    " "
                };
                println!("{mark} {name}\t{}\t{}", net.url, net.did);
            }
            Ok(())
        }
        NetworksCommand::Use { name } => {
            profile.network(Some(&name))?;
            profile.default_network = Some(name);
            profile.save(path)
        }
        NetworksCommand::Remove { name } => {
            profile
                .networks
                .remove(&name)
                .with_context(|| format!("no network named {name:?}"))?;
            if profile.default_network.as_deref() == Some(name.as_str()) {
                profile.default_network = None;
            }
            profile.save(path)
        }
    }
}

/// One network, acted on as this NNM's administrator: every request a `vtn/*` Trust Task
/// signed by the admin key, for the network DID recorded in the profile.
struct Nnm {
    client: VtnClient,
    admin: Identity,
    network: String,
}

impl Nnm {
    /// Send task `P` with `payload`, and its response as JSON.
    async fn call<P>(&self, payload: Value) -> anyhow::Result<Value>
    where
        P: RequestPayload + DeserializeOwned,
        P::Response: Serialize,
    {
        let payload: P =
            serde_json::from_value(payload).with_context(|| format!("building {}", P::TYPE_URI))?;
        let answer = self
            .client
            .task(&self.admin, &self.network, &payload)
            .await?;
        Ok(serde_json::to_value(answer)?)
    }
}

/// Where a community's operator console takes an invitation: its Networks page, with the
/// network to join (VTI `vtc-service/admin-ui`).
const CONSOLE_JOIN_PATH: &str = "/admin/networks";

/// Percent-encode a query value: everything but RFC 3986 unreserved characters.
fn query_value(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The deep link into a community's console that opens the join for this network.
fn console_link(console: &str, network_url: &str, network_did: &str) -> String {
    format!(
        "{}{CONSOLE_JOIN_PATH}?join={}&network={}",
        console.trim_end_matches('/'),
        query_value(network_url),
        query_value(network_did)
    )
}

/// The invitation to print for the listed party's administrator.
fn invitation(
    network_url: &str,
    network_did: &str,
    entry: &Value,
    roles: &Value,
    kind: Kind,
    console: Option<&str>,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let who = entry["label"]
        .as_str()
        .or(entry["did"].as_str())
        .unwrap_or("?");
    match entry["state"].as_str() {
        Some("listed") => {
            let _ = writeln!(
                out,
                "{who} is listed, not yet acknowledged. It becomes a member when it accepts."
            );
        }
        state => {
            let _ = writeln!(out, "{who} is {}.", state.unwrap_or("?"));
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Send this to its administrator:");
    let _ = writeln!(out, "  network:  {network_url}");
    let _ = writeln!(out, "  DID:      {network_did}");
    let required: Vec<&str> = roles
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["required"] == true)
        .filter_map(|r| r["name"].as_str())
        .collect();
    if !required.is_empty() {
        let _ = writeln!(
            out,
            "  roles:    {} (assign a group to each)",
            required.join(", ")
        );
    }
    match (kind, console) {
        (Kind::Community, Some(console)) => {
            let _ = writeln!(
                out,
                "  accept:   {}",
                console_link(console, network_url, network_did)
            );
        }
        (Kind::Community, None) => {
            let _ = writeln!(
                out,
                "  accept:   in its operator console, Networks, Join, with the network URL above"
            );
        }
        (Kind::Network, _) => {
            let _ = writeln!(out, "  accept:   nnm memberships join {network_url}");
        }
    }
    out
}

/// The DID the network at `url` answers as, checked against `expected` when given.
async fn network_at(url: &str, expected: Option<String>) -> anyhow::Result<String> {
    let info = VtnClient::new(url.trim_end_matches('/')).profile().await?;
    let did = info["did"]
        .as_str()
        .with_context(|| format!("{url} names no DID"))?
        .to_string();
    if let Some(expected) = expected
        && expected != did
    {
        anyhow::bail!("{url} answers as {did}, not {expected}");
    }
    eprintln!(
        "parent: {} ({did})",
        info["profile"]["name"].as_str().unwrap_or("unnamed")
    );
    Ok(did)
}

async fn admin_command(
    command: Command,
    profile: &Profile,
    network: Option<&str>,
    resolver_url: Option<&str>,
) -> anyhow::Result<()> {
    let (name, net) = profile.network(network)?;
    // Every answer must be signed by the network recorded for this name.
    let resolver = VmKeyResolver::network(resolver_url).await?;
    let client = VtnClient::new(&net.url).verifying(std::sync::Arc::new(resolver));

    // The service must still be the network recorded for this name: every request names
    // that DID as its recipient, and is refused by any other.
    let info = client.profile().await?;
    if info["did"].as_str() != Some(net.did.as_str()) {
        anyhow::bail!(
            "{} now answers as {}, not the {} recorded for {name}",
            net.url,
            info["did"],
            net.did
        );
    }

    let nnm = Nnm {
        client,
        admin: profile.admin()?.identity()?,
        network: net.did.clone(),
    };

    match command {
        Command::Status => {
            // An administrator-only read: it succeeds only if the network takes this key.
            nnm.call::<specs::listings::list::v0_1::Payload>(json!({}))
                .await?;
            println!("network:  {name} ({})", net.did);
            println!("url:      {}", net.url);
            println!("admin:    {} (accepted)", nnm.admin.did());
            Ok(())
        }
        Command::Entries { did: Some(did) } => print(
            &nnm.call::<specs::listings::show::v0_1::Payload>(json!({ "did": did }))
                .await?["entry"],
        ),
        Command::Entries { did: None } => {
            let entries = nnm
                .call::<specs::listings::list::v0_1::Payload>(json!({}))
                .await?;
            for e in entries["entries"].as_array().into_iter().flatten() {
                println!(
                    "{:<13} {:<10} {}  {}",
                    e["state"].as_str().unwrap_or("?"),
                    e["kind"].as_str().unwrap_or("?"),
                    e["did"].as_str().unwrap_or("?"),
                    e["label"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Command::Index => print(&nnm.client.get("/v1/index").await?),
        Command::Roles => {
            let roles = nnm
                .call::<specs::roles::list::v0_1::Payload>(json!({}))
                .await?;
            for r in roles["roles"].as_array().into_iter().flatten() {
                println!(
                    "{:<20} {:<9} {}",
                    r["name"].as_str().unwrap_or("?"),
                    if r["required"] == true {
                        "required"
                    } else {
                        "optional"
                    },
                    r["description"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Command::Groups { role } => {
            let payload = match role {
                Some(r) => json!({ "role": r }),
                None => json!({}),
            };
            let groups = nnm
                .call::<specs::groups::list::v0_1::Payload>(payload)
                .await?;
            for g in groups["groups"].as_array().into_iter().flatten() {
                println!(
                    "{:<14} {}  {}  -> {}",
                    g["role"].as_str().unwrap_or("?"),
                    g["member"].as_str().unwrap_or("?"),
                    g["group"].as_str().unwrap_or("?"),
                    g["endpoint"].as_str().unwrap_or("?")
                );
            }
            Ok(())
        }
        Command::Broadcast {
            role,
            subject,
            body,
            class,
            reply_to,
        } => {
            let mut payload =
                json!({ "role": role, "subject": subject, "body": body, "class": class });
            if let Some(r) = reply_to {
                payload["replyTo"] = json!(r);
            }
            let answer = nnm
                .call::<specs::broadcasts::send::v0_1::Payload>(payload)
                .await?;
            let record = &answer["broadcast"];
            println!(
                "{}  reached {} group(s)",
                record["id"].as_str().unwrap_or("?"),
                record["reached"]
            );
            print_receipts(&record["receipts"], 1);
            Ok(())
        }
        Command::Broadcasts { id: Some(id) } => {
            let answer = nnm
                .call::<specs::broadcasts::show::v0_1::Payload>(json!({ "id": id }))
                .await?;
            let record = &answer["broadcast"];
            print(&record["message"])?;
            println!("reached {} group(s)", record["reached"]);
            print_receipts(&record["receipts"], 1);
            Ok(())
        }
        Command::Broadcasts { id: None } => {
            let answer = nnm
                .call::<specs::broadcasts::list::v0_1::Payload>(json!({}))
                .await?;
            for b in answer["broadcasts"].as_array().into_iter().flatten() {
                println!(
                    "{}  {:<8} {:<10} reached {:<4} {}  {}",
                    b["recordedAt"].as_str().unwrap_or("?"),
                    b["direction"].as_str().unwrap_or("?"),
                    b["role"].as_str().unwrap_or("?"),
                    b["reached"],
                    b["id"].as_str().unwrap_or("?"),
                    b["message"]["subject"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Command::Memberships(cmd) => memberships(&nnm, cmd).await,
        Command::Registry(cmd) => {
            let entries = match cmd {
                registry::RegistryCommand::Records => Some(
                    nnm.call::<specs::listings::list::v0_1::Payload>(json!({}))
                        .await?["entries"]
                        .clone(),
                ),
                _ => None,
            };
            registry::run(&info, entries, cmd).await
        }
        Command::Rooms => {
            let answer = nnm
                .call::<specs::rooms::list::v0_1::Payload>(json!({}))
                .await?;
            for r in answer["rooms"].as_array().into_iter().flatten() {
                println!(
                    "{:<16} {:<28} role {:<14} pass {} min",
                    r["id"].as_str().unwrap_or("?"),
                    r["name"].as_str().unwrap_or("?"),
                    r["role"].as_str().unwrap_or("?"),
                    r["passMinutes"]
                );
            }
            Ok(())
        }
        Command::Outbox { retry } => {
            if retry {
                let r = nnm
                    .call::<specs::outbox::retry::v0_1::Payload>(json!({}))
                    .await?;
                println!("attempted {}", r["attempted"]);
            }
            let answer = nnm
                .call::<specs::outbox::list::v0_1::Payload>(json!({}))
                .await?;
            for i in answer["items"].as_array().into_iter().flatten() {
                println!(
                    "{}  attempt {:<2} next {}  {}  {}",
                    i["messageId"].as_str().unwrap_or("?"),
                    i["attempts"],
                    i["nextAttemptAt"].as_str().unwrap_or("?"),
                    i["member"].as_str().unwrap_or("?"),
                    i["lastError"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Command::Directory {
            query,
            kind,
            members_only,
            federated,
        } => {
            let mut payload = json!({ "membersOnly": members_only });
            if !query.is_empty() {
                payload["q"] = json!(query.join(" "));
            }
            if let Some(kind) = kind {
                payload["kind"] = json!(kind.as_str());
            }
            let (rows, unreachable) = if federated {
                let found = nnm
                    .call::<specs::directory::federated::v0_1::Payload>(payload)
                    .await?;
                (found["results"].clone(), found["unreachable"].clone())
            } else {
                let found = nnm
                    .call::<specs::directory::search::v0_1::Payload>(payload)
                    .await?;
                (found["entries"].clone(), Value::Null)
            };
            for u in unreachable.as_array().into_iter().flatten() {
                eprintln!(
                    "indeterminate: {} ({})",
                    u["network"].as_str().unwrap_or("?"),
                    u["reason"].as_str().unwrap_or("?")
                );
            }
            for r in rows.as_array().into_iter().flatten() {
                let state = if r["acknowledged"] == true {
                    "member".to_string()
                } else {
                    r["state"].as_str().unwrap_or("?").to_string()
                };
                let via: Vec<&str> = r["path"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|h| h["name"].as_str().or(h["network"].as_str()).unwrap_or("?"))
                    .collect();
                println!(
                    "{:<12} {:<10} {:<32} {}{}",
                    state,
                    r["kind"].as_str().unwrap_or("?"),
                    r["label"].as_str().unwrap_or("-"),
                    r["did"].as_str().unwrap_or("?"),
                    if via.is_empty() {
                        String::new()
                    } else {
                        format!("  via {}", via.join(" > "))
                    }
                );
            }
            Ok(())
        }
        Command::Profile {
            did,
            label,
            profile,
        } => {
            let mut payload = profile.json();
            payload["did"] = json!(did);
            if let Some(label) = label {
                payload["label"] = json!(label);
            }
            nnm.call::<specs::listings::update::v0_1::Payload>(payload)
                .await?;
            println!("{did}: profile updated");
            Ok(())
        }
        Command::List {
            did,
            kind,
            label,
            profile,
        } => {
            let mut payload = profile.json();
            payload["did"] = json!(did);
            payload["kind"] = json!(kind.as_str());
            if let Some(label) = label {
                payload["label"] = json!(label);
            }
            let answer = nnm
                .call::<specs::listings::create::v0_1::Payload>(payload)
                .await?;
            println!(
                "{} listed as {} ({})",
                did,
                kind.as_str(),
                answer["entry"]["state"].as_str().unwrap_or("?")
            );
            println!(
                "It acknowledges with vtn/membership/offer and vtn/membership/acknowledge at {}",
                net.url
            );
            Ok(())
        }
        Command::Invite {
            did,
            kind,
            label,
            console,
            profile,
        } => {
            let shown = nnm
                .call::<specs::listings::show::v0_1::Payload>(json!({ "did": did }))
                .await
                .ok();
            let pending = shown
                .as_ref()
                .is_some_and(|s| s["entry"]["state"] == "listed");
            let entry = if pending {
                eprintln!("{did} is listed already; not listing it again");
                shown.map(|s| s["entry"].clone()).unwrap_or_default()
            } else {
                let mut payload = profile.json();
                payload["did"] = json!(did);
                payload["kind"] = json!(kind.as_str());
                if let Some(label) = label {
                    payload["label"] = json!(label);
                }
                nnm.call::<specs::listings::create::v0_1::Payload>(payload)
                    .await?["entry"]
                    .clone()
            };
            let roles = nnm
                .call::<specs::roles::list::v0_1::Payload>(json!({}))
                .await?;
            let console = console
                .or(profile.url.clone())
                .or_else(|| entry["profile"]["url"].as_str().map(str::to_string));
            print!(
                "{}",
                invitation(
                    &net.url,
                    &net.did,
                    &entry,
                    &roles["roles"],
                    kind,
                    console.as_deref()
                )
            );
            Ok(())
        }
        Command::Suspend { did, reason } => {
            transition::<specs::listings::suspend::v0_1::Payload>(&nnm, &did, reason).await
        }
        Command::Reinstate { did, reason } => {
            transition::<specs::listings::reinstate::v0_1::Payload>(&nnm, &did, reason).await
        }
        Command::Remove { did, reason } => {
            transition::<specs::listings::remove::v0_1::Payload>(&nnm, &did, reason).await
        }
        Command::Graph {
            include_exited,
            out,
        } => {
            let answer = nnm
                .call::<specs::graph::show::v0_1::Payload>(
                    json!({ "includeExited": include_exited }),
                )
                .await?;
            let graph = &answer["graph"];
            match out {
                Some(path) => {
                    std::fs::write(&path, serde_json::to_string_pretty(graph)?)?;
                    eprintln!(
                        "{} nodes, {} edges -> {}",
                        graph["nodes"].as_array().map_or(0, Vec::len),
                        graph["edges"].as_array().map_or(0, Vec::len),
                        path.display()
                    );
                    Ok(())
                }
                None => print(graph),
            }
        }
        Command::Audit => {
            let answer = nnm
                .call::<specs::audit::list::v0_1::Payload>(json!({}))
                .await?;
            for e in answer["events"].as_array().into_iter().flatten() {
                println!(
                    "{}  {:<11} {:<13} {}  by {}{}",
                    e["occurredAt"].as_str().unwrap_or("?"),
                    e["event"].as_str().unwrap_or("?"),
                    e["to"].as_str().unwrap_or("?"),
                    e["did"].as_str().unwrap_or("?"),
                    e["actor"].as_str().unwrap_or("?"),
                    e["reason"]
                        .as_str()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default()
                );
            }
            Ok(())
        }
        Command::Keys(_) | Command::Networks(_) => unreachable!("handled above"),
    }
}

async fn memberships(nnm: &Nnm, cmd: MembershipsCommand) -> anyhow::Result<()> {
    use specs::memberships as m;
    let show = |answer: &Value| {
        let m = &answer["membership"];
        println!(
            "{:<13} {}  {}  {}",
            m["state"].as_str().unwrap_or("?"),
            m["name"].as_str().unwrap_or("-"),
            m["network"].as_str().unwrap_or("?"),
            m["url"].as_str().unwrap_or("?")
        );
        for g in m["groups"].as_array().into_iter().flatten() {
            println!(
                "              serves {} with {}",
                g["parentRole"].as_str().unwrap_or("?"),
                g["localRole"].as_str().unwrap_or("?")
            );
        }
    };
    let mapping = |(p, l): (String, String)| json!({ "parentRole": p, "localRole": l });
    match cmd {
        MembershipsCommand::List => {
            let answer = nnm.call::<m::list::v0_1::Payload>(json!({})).await?;
            for membership in answer["memberships"].as_array().into_iter().flatten() {
                show(&json!({ "membership": membership }));
            }
        }
        MembershipsCommand::Join { url, parent, roles } => {
            let network = network_at(&url, parent).await?;
            let roles: Vec<Value> = roles.into_iter().map(mapping).collect();
            show(
                &nnm.call::<m::join::v0_1::Payload>(
                    json!({ "url": url, "network": network, "roles": roles }),
                )
                .await?,
            );
        }
        MembershipsCommand::Serve {
            parent,
            mapping: (p, l),
        } => {
            show(
                &nnm.call::<m::groups::add::v0_1::Payload>(
                    json!({ "network": parent, "parentRole": p, "localRole": l }),
                )
                .await?,
            );
        }
        MembershipsCommand::Leave { parent } => {
            show(
                &nnm.call::<m::leave::v0_1::Payload>(json!({ "network": parent }))
                    .await?,
            );
        }
        MembershipsCommand::Repudiate { url, parent } => {
            let network = network_at(&url, parent).await?;
            show(
                &nnm.call::<m::repudiate::v0_1::Payload>(json!({ "url": url, "network": network }))
                    .await?,
            );
        }
    }
    Ok(())
}

fn print_receipts(receipts: &Value, depth: usize) {
    for r in receipts.as_array().into_iter().flatten() {
        println!(
            "{}{:<10} {}{}",
            "  ".repeat(depth),
            r["status"].as_str().unwrap_or("?"),
            r["member"].as_str().unwrap_or("?"),
            r["detail"]
                .as_str()
                .map(|d| format!("  ({d})"))
                .unwrap_or_default()
        );
        print_receipts(&r["relayed"], depth + 1);
    }
}

/// Suspend, reinstate or remove `did`.
async fn transition<P>(nnm: &Nnm, did: &str, reason: Option<String>) -> anyhow::Result<()>
where
    P: RequestPayload + DeserializeOwned,
    P::Response: Serialize,
{
    let mut payload = json!({ "did": did });
    if let Some(reason) = reason {
        payload["reason"] = json!(reason);
    }
    let answer = nnm.call::<P>(payload).await?;
    println!(
        "{did}: {}",
        answer["entry"]["state"].as_str().unwrap_or("?")
    );
    Ok(())
}

#[cfg(test)]
mod invite_tests {
    use super::*;

    #[test]
    fn the_console_link_carries_the_network_url_and_did() {
        assert_eq!(
            console_link(
                "https://vtc.example/",
                "https://vtn.example",
                "did:webvh:Qm1:vtn.example"
            ),
            "https://vtc.example/admin/networks?join=https%3A%2F%2Fvtn.example\
             &network=did%3Awebvh%3AQm1%3Avtn.example"
        );
    }

    #[test]
    fn the_invitation_names_the_required_roles_and_how_to_accept() {
        let entry = json!({ "did": "did:web:msf", "label": "MSF", "state": "listed" });
        let roles = json!([
            { "name": "admins", "required": true },
            { "name": "news", "required": false },
        ]);
        let text = invitation(
            "https://vtn.example",
            "did:web:vtn",
            &entry,
            &roles,
            Kind::Community,
            Some("https://msf.example"),
        );
        assert!(
            text.contains("MSF is listed, not yet acknowledged"),
            "{text}"
        );
        assert!(text.contains("roles:    admins (assign"), "{text}");
        assert!(!text.contains("news"), "{text}");
        assert!(
            text.contains("https://msf.example/admin/networks?join="),
            "{text}"
        );
        let net = invitation(
            "https://vtn.example",
            "did:web:vtn",
            &entry,
            &json!([]),
            Kind::Network,
            None,
        );
        assert!(
            net.contains("nnm memberships join https://vtn.example"),
            "{net}"
        );
    }
}
