//! `nnm`: the Network Network Manager. It is the operator's CLI for Verifiable Trust
//! Networks, as `pnm` is for a person and `cnm` for a community.

mod profile;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

use crate::profile::{AdminKey, NetworkRef, Profile};
use vtn_client::{VtnClient, encode_did, encode_query};

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
    /// Show the selected network and check that you can sign in to it.
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
    /// Edit an entry's directory profile (name, description, URL, tags). Replaces the
    /// description, URL and tags; re-issues no credential.
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
    /// Print a session token, e.g. to open a restricted directory in the browser.
    Token,
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
    /// This network's memberships of other networks.
    #[command(subcommand)]
    Memberships(MembershipsCommand),
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
    /// The network's signed public index.
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
    Repudiate { url: String },
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
    fn json(&self) -> Value {
        json!({ "description": self.description, "url": self.url, "tags": self.tags })
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
        command => admin_command(command, &profile, cli.network.as_deref()).await,
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

async fn admin_command(
    command: Command,
    profile: &Profile,
    network: Option<&str>,
) -> anyhow::Result<()> {
    let (name, net) = profile.network(network)?;
    let mut client = VtnClient::new(&net.url);

    // The service must still be the network recorded for this name: the sign-in is bound
    // to that DID, and is refused for any other audience.
    let info = client.profile().await?;
    if info["did"].as_str() != Some(net.did.as_str()) {
        anyhow::bail!(
            "{} now answers as {}, not the {} recorded for {name}",
            net.url,
            info["did"],
            net.did
        );
    }

    let admin = profile.admin()?.identity()?;
    client.sign_in(&admin, &net.did, None).await?;

    match command {
        Command::Status => {
            let me = client.get("/v1/admin/whoami").await?;
            println!("network:  {name} ({})", net.did);
            println!("url:      {}", net.url);
            println!(
                "admin:    {} (signed in)",
                me["did"].as_str().unwrap_or("?")
            );
            Ok(())
        }
        Command::Entries { did: Some(did) } => print(
            &client
                .get(&format!("/v1/admin/entries/{}", encode_did(&did)))
                .await?,
        ),
        Command::Entries { did: None } => {
            let entries = client.get("/v1/admin/entries").await?;
            for e in entries.as_array().into_iter().flatten() {
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
        Command::Index => print(&client.get("/v1/index").await?),
        Command::Roles => {
            for r in client
                .get("/v1/admin/roles")
                .await?
                .as_array()
                .into_iter()
                .flatten()
            {
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
            let path = match role {
                Some(r) => format!("/v1/admin/groups?role={}", encode_query(&r)),
                None => "/v1/admin/groups".into(),
            };
            for g in client.get(&path).await?.as_array().into_iter().flatten() {
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
            let record = client
                .post(
                    "/v1/admin/broadcasts",
                    &json!({ "role": role, "subject": subject, "body": body, "class": class, "replyTo": reply_to }),
                )
                .await?;
            println!(
                "{}  reached {} group(s)",
                record["id"].as_str().unwrap_or("?"),
                record["reached"]
            );
            print_receipts(&record["receipts"], 1);
            Ok(())
        }
        Command::Broadcasts { id: Some(id) } => {
            let record = client
                .get(&format!("/v1/admin/broadcasts/{}", encode_query(&id)))
                .await?;
            print(&record["message"])?;
            println!("reached {} group(s)", record["reached"]);
            print_receipts(&record["receipts"], 1);
            Ok(())
        }
        Command::Broadcasts { id: None } => {
            for b in client
                .get("/v1/admin/broadcasts")
                .await?
                .as_array()
                .into_iter()
                .flatten()
            {
                println!(
                    "{}  {:<8} {:<10} reached {:<4} {}  {}",
                    b["at"].as_str().unwrap_or("?"),
                    b["direction"].as_str().unwrap_or("?"),
                    b["role"].as_str().unwrap_or("?"),
                    b["reached"],
                    b["id"].as_str().unwrap_or("?"),
                    b["message"]["subject"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Command::Memberships(cmd) => memberships(&client, cmd).await,
        Command::Token => {
            println!("{}", client.token().unwrap_or_default());
            eprintln!("Valid for an hour. Paste it into the landing page's session-token box.");
            Ok(())
        }
        Command::Directory {
            query,
            kind,
            members_only,
            federated,
        } => {
            let mut params = vec![format!("members_only={members_only}")];
            if !query.is_empty() {
                params.push(format!("q={}", encode_query(&query.join(" "))));
            }
            if let Some(kind) = kind {
                params.push(format!("kind={}", kind.as_str()));
            }
            let path = if federated {
                "/v1/directory/federated"
            } else {
                "/v1/directory"
            };
            let found = client.get(&format!("{path}?{}", params.join("&"))).await?;
            let rows = if federated {
                found["results"].clone()
            } else {
                found.clone()
            };
            for u in found["unreachable"].as_array().into_iter().flatten() {
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
            let mut body = profile.json();
            body["label"] = json!(label);
            client
                .post(
                    &format!("/v1/admin/entries/{}/profile", encode_did(&did)),
                    &body,
                )
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
            let mut body = profile.json();
            body["did"] = json!(did);
            body["kind"] = json!(kind.as_str());
            body["label"] = json!(label);
            let entry = client.post("/v1/admin/entries", &body).await?;
            println!(
                "{} listed as {} ({})",
                did,
                kind.as_str(),
                entry["state"].as_str().unwrap_or("?")
            );
            println!(
                "It acknowledges by fetching {}/v1/entries/{}/offer",
                net.url,
                encode_did(&did)
            );
            Ok(())
        }
        Command::Suspend { did, reason } => action(&client, &did, "suspend", reason).await,
        Command::Reinstate { did, reason } => action(&client, &did, "reinstate", reason).await,
        Command::Remove { did, reason } => action(&client, &did, "remove", reason).await,
        Command::Graph {
            include_exited,
            out,
        } => {
            let graph = client
                .get(&format!("/v1/admin/graph?include_exited={include_exited}"))
                .await?;
            match out {
                Some(path) => {
                    std::fs::write(&path, serde_json::to_string_pretty(&graph)?)?;
                    eprintln!(
                        "{} nodes, {} edges -> {}",
                        graph["nodes"].as_array().map_or(0, Vec::len),
                        graph["edges"].as_array().map_or(0, Vec::len),
                        path.display()
                    );
                    Ok(())
                }
                None => print(&graph),
            }
        }
        Command::Audit => {
            let audit = client.get("/v1/admin/audit").await?;
            for e in audit.as_array().into_iter().flatten() {
                println!(
                    "{}  {:<11} {:<13} {}  by {}{}",
                    e["at"].as_str().unwrap_or("?"),
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

async fn memberships(client: &VtnClient, cmd: MembershipsCommand) -> anyhow::Result<()> {
    let show = |m: &Value| {
        println!(
            "{:<13} {}  {}  {}",
            m["state"].as_str().unwrap_or("?"),
            m["parentName"].as_str().unwrap_or("-"),
            m["parent"].as_str().unwrap_or("?"),
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
            for m in client
                .get("/v1/admin/memberships")
                .await?
                .as_array()
                .into_iter()
                .flatten()
            {
                show(m);
            }
        }
        MembershipsCommand::Join { url, roles } => {
            let roles: Vec<Value> = roles.into_iter().map(mapping).collect();
            show(
                &client
                    .post(
                        "/v1/admin/memberships",
                        &json!({ "url": url, "roles": roles }),
                    )
                    .await?,
            );
        }
        MembershipsCommand::Serve { parent, mapping: m } => {
            show(
                &client
                    .post(
                        &format!("/v1/admin/memberships/{}/groups", encode_did(&parent)),
                        &mapping(m),
                    )
                    .await?,
            );
        }
        MembershipsCommand::Leave { parent } => {
            show(
                &client
                    .post(
                        &format!("/v1/admin/memberships/{}/leave", encode_did(&parent)),
                        &json!({}),
                    )
                    .await?,
            );
        }
        MembershipsCommand::Repudiate { url } => {
            show(
                &client
                    .post("/v1/admin/memberships/repudiate", &json!({ "url": url }))
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

async fn action(
    client: &VtnClient,
    did: &str,
    verb: &str,
    reason: Option<String>,
) -> anyhow::Result<()> {
    let entry = client
        .post(
            &format!("/v1/admin/entries/{}/{verb}", encode_did(did)),
            &json!({ "reason": reason }),
        )
        .await?;
    println!("{did}: {}", entry["state"].as_str().unwrap_or("?"));
    Ok(())
}
