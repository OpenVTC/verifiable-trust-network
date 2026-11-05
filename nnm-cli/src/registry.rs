//! `nnm registry …`: what the trust registry says about this network's members.
//!
//! - **Direct**, when the network advertises the registry's HTTPS query URL: asked of the
//!   registry itself (TRQP over its HTTPS binding, `trql-client`), never of the network.
//! - **Relayed**, for a registry that speaks DIDComm or TSP only: the network asks it over
//!   its own session (`vtn/registry/check`, `vtn/registry/status`) and returns the registry's
//!   answer; `check` shows whether that answer is signed by the registry's DID.
//!
//! The network advertises where to ask in its profile (`trustRegistry`, A23). Every answer
//! must name this network as its authority (`TrqlClient::referred_by`), so a registry
//! answering for someone else is refused rather than believed.

use std::sync::Arc;

use anyhow::Context;
use clap::Subcommand;
use serde_json::Value;
use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqpQuery};

#[derive(Subcommand)]
pub enum RegistryCommand {
    /// The registry this network publishes to, and whether it answers.
    Status,
    /// What the registry says about one party.
    Check { did: String },
    /// Every entry against what the registry says: missing, stale or matching.
    Records,
}

/// Where and what to ask, from the network's profile.
struct Target {
    registry_did: String,
    query_url: String,
    authority: String,
    resource: String,
    member: String,
    listed: String,
    publishes: String,
}

impl Target {
    fn from_profile(info: &Value) -> anyhow::Result<Self> {
        let tr = info
            .get("trustRegistry")
            .filter(|v| v.is_object())
            .context(
                "this network publishes to no trust registry: set [registry] in its vtn.toml \
                 (docs/trust-registry.md)",
            )?;
        let s = |p: &str| tr.pointer(p).and_then(Value::as_str).map(str::to_string);
        Ok(Self {
            registry_did: s("/did").context("trustRegistry names no registry DID")?,
            query_url: s("/queryUrl").context(
                "the registry's query URL is not advertised: set [registry] query_url in the \
                 network's vtn.toml so it can be checked",
            )?,
            authority: s("/authority").context("trustRegistry names no authority")?,
            resource: s("/resource").unwrap_or_else(|| "vtn".into()),
            member: s("/actions/member").unwrap_or_else(|| "member".into()),
            listed: s("/actions/listed").unwrap_or_else(|| "lists".into()),
            publishes: s("/publishes").unwrap_or_else(|| "members".into()),
        })
    }

    fn client(&self) -> anyhow::Result<TrqlClient> {
        let transport = HttpsTransport::new(HttpsTransportConfig::new(
            self.query_url.trim_end_matches('/'),
        ))
        .map_err(|e| anyhow::anyhow!("registry query URL {}: {e}", self.query_url))?;
        // Every answer must be for this network.
        Ok(TrqlClient::new(Arc::new(transport), &self.registry_did).referred_by(&self.authority))
    }

    /// Whether the registry says `did` holds `action` under this network.
    async fn holds(&self, client: &TrqlClient, did: &str, action: &str) -> anyhow::Result<bool> {
        let answer = client
            .authorization(TrqpQuery::new(did, &self.authority, action, &self.resource))
            .await
            .map_err(|e| anyhow::anyhow!("the registry did not answer for {did} {action}: {e}"))?;
        Ok(answer.authorized)
    }
}

/// What the network says an entry should be published as.
fn expected_action<'a>(entry: &Value, target: &'a Target) -> Option<&'a str> {
    match entry["state"].as_str() {
        Some("acknowledged") => Some(&target.member),
        Some("listed") if target.publishes == "members-and-listed" => Some(&target.listed),
        _ => None,
    }
}

/// Run `cmd`. `info` is the network's profile; `entries` its listings, for `records`.
pub async fn run(info: &Value, entries: Option<Value>, cmd: RegistryCommand) -> anyhow::Result<()> {
    let target = Target::from_profile(info)?;
    let client = target.client()?;
    match cmd {
        RegistryCommand::Status => {
            println!("registry:   {}", target.registry_did);
            println!("query URL:  {}", target.query_url);
            println!("authority:  {} (this network)", target.authority);
            println!("resource:   {}", target.resource);
            println!(
                "actions:    {} (members), {} (listed)",
                target.member, target.listed
            );
            println!("publishes:  {}", target.publishes);
            // A query about no one: an answer at all proves the registry serves this
            // network's queries.
            match target
                .holds(&client, "did:example:nnm-registry-probe", &target.member)
                .await
            {
                Ok(_) => println!("answers:    yes"),
                Err(e) => println!("answers:    no — {e}"),
            }
            Ok(())
        }
        RegistryCommand::Check { did } => {
            let member = target.holds(&client, &did, &target.member).await?;
            let listed = target.holds(&client, &did, &target.listed).await?;
            println!("{did}");
            println!(
                "  {:<8} {}",
                target.member,
                if member { "yes" } else { "no" }
            );
            println!(
                "  {:<8} {}",
                target.listed,
                if listed { "yes" } else { "no" }
            );
            if member && listed {
                println!(
                    "  both at once: the network replaces one with the other; reconcile is behind"
                );
            }
            Ok(())
        }
        RegistryCommand::Records => {
            let entries = entries.unwrap_or_default();
            let mut drift = 0;
            println!("{:<10} {:<14} {:<10} DID", "result", "state", "registry");
            for entry in entries.as_array().into_iter().flatten() {
                let did = entry["did"].as_str().unwrap_or("?");
                let state = entry["state"].as_str().unwrap_or("?");
                let want = expected_action(entry, &target);
                let member = target.holds(&client, did, &target.member).await?;
                let listed = target.holds(&client, did, &target.listed).await?;
                let held = match (member, listed) {
                    (true, false) => Some(target.member.as_str()),
                    (false, true) => Some(target.listed.as_str()),
                    (false, false) => None,
                    (true, true) => Some("both"),
                };
                let result = match (want, held) {
                    (Some(w), Some(h)) if w == h => "ok",
                    (None, None) => "ok",
                    (Some(_), None) => "missing",
                    (None, Some(_)) => "stale",
                    _ => "wrong",
                };
                if result != "ok" {
                    drift += 1;
                }
                println!("{result:<10} {state:<14} {:<10} {did}", held.unwrap_or("-"));
            }
            if drift > 0 {
                println!(
                    "\n{drift} entr{} not as the network says. The network reconciles at start, \
                     after each change and every sync_interval_secs; check its log for \
                     \"trust registry projection incomplete\".",
                    if drift == 1 { "y is" } else { "ies are" }
                );
            }
            Ok(())
        }
    }
}

/// Whether the network advertises an HTTPS query URL for its registry; without one, every
/// `nnm registry` command is relayed by the network.
pub fn is_direct(info: &Value) -> bool {
    info.pointer("/trustRegistry/queryUrl")
        .and_then(Value::as_str)
        .is_some()
}

/// Print a relayed `vtn/registry/check` answer.
pub fn print_relayed_check(answer: &Value) {
    let did = answer["did"].as_str().unwrap_or("?");
    println!("{did}");
    if answer["reachable"] != true {
        println!(
            "  indeterminate: the network could not ask the registry ({})",
            answer["reason"].as_str().unwrap_or("no reason given")
        );
        return;
    }
    let yes = |v: &Value| if *v == true { "yes" } else { "no" };
    let member = answer["actions"]["member"].as_str().unwrap_or("member");
    let listed = answer["actions"]["listed"].as_str().unwrap_or("lists");
    println!("  {member:<8} {}", yes(&answer["member"]));
    println!("  {listed:<8} {}", yes(&answer["listed"]));
    let registry = answer["registry"].as_str().unwrap_or("?");
    let reg_answer = &answer["answer"];
    let signer = reg_answer["proof"]["verificationMethod"]
        .as_str()
        .and_then(|vm| vm.split('#').next());
    match signer {
        Some(s) if s == registry && reg_answer["issuer"] == registry => println!(
            "  relayed by the network; the answer is signed by the registry's DID              (`nnm verify` checks the signature)"
        ),
        _ => println!("  relayed by the network; the answer is not signed by the registry"),
    }
}

/// Print a relayed `vtn/registry/status` answer: `records` too when asked.
pub fn print_relayed_status(answer: &Value, records: bool) {
    let s = |k: &str| answer[k].as_str().unwrap_or("?").to_string();
    if !records {
        println!("registry:   {}", s("registry"));
        println!("query:      relayed by the network (the registry speaks DIDComm or TSP)");
        println!("authority:  {} (this network)", s("authority"));
        println!("resource:   {}", s("resource"));
        println!(
            "actions:    {} (members), {} (listed)",
            answer["actions"]["member"].as_str().unwrap_or("member"),
            answer["actions"]["listed"].as_str().unwrap_or("lists")
        );
        println!("publishes:  {}", s("publishes"));
        println!("writer:     {}", s("writer"));
        println!(
            "connected:  {}",
            if answer["connected"] == true {
                "yes"
            } else {
                "no"
            }
        );
        match answer.get("lastSync") {
            Some(l) => {
                println!(
                    "last sync:  {} — {} expected, {} put, {} deleted, {} failed",
                    l["reconciledAt"].as_str().unwrap_or("?"),
                    l["expected"],
                    l["put"].as_array().map_or(0, Vec::len),
                    l["deleted"].as_array().map_or(0, Vec::len),
                    l["failed"].as_array().map_or(0, Vec::len),
                );
                if let Some(b) = l["blocked"].as_str() {
                    println!("            blocked: {b}");
                }
                for f in l["failed"].as_array().into_iter().flatten() {
                    println!("            failed: {}", f.as_str().unwrap_or("?"));
                }
            }
            None => println!("last sync:  none yet"),
        }
        println!(
            "answers:    {}",
            if answer["reachable"] == true {
                "yes".to_string()
            } else {
                format!("no — {}", answer["reason"].as_str().unwrap_or("?"))
            }
        );
        return;
    }
    if answer["reachable"] != true {
        println!(
            "the registry could not be read: {}",
            answer["reason"].as_str().unwrap_or("?")
        );
        return;
    }
    let mut drift = 0;
    println!(
        "{:<10} {:<10} {:<10} DID",
        "result", "projected", "registry"
    );
    for row in answer["records"].as_array().into_iter().flatten() {
        let result = row["result"].as_str().unwrap_or("?");
        if result != "ok" {
            drift += 1;
        }
        println!(
            "{result:<10} {:<10} {:<10} {}",
            row["projected"].as_str().unwrap_or("-"),
            row["held"].as_str().unwrap_or("-"),
            row["did"].as_str().unwrap_or("?")
        );
    }
    if drift > 0 {
        println!(
            "\n{drift} record{} not as the network projects. `nnm registry status` shows the last \
             reconcile and why it failed.",
            if drift == 1 { " is" } else { "s are" }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn target(publishes: &str) -> Target {
        Target::from_profile(&json!({ "trustRegistry": {
            "did": "did:web:r", "queryUrl": "https://r.example", "authority": "did:web:n",
            "resource": "vtn", "actions": { "member": "member", "listed": "lists" },
            "publishes": publishes,
        }}))
        .unwrap()
    }

    #[test]
    fn an_entry_is_expected_as_the_network_publishes_it() {
        let members = target("members");
        let both = target("members-and-listed");
        let acked = json!({ "state": "acknowledged" });
        let listed = json!({ "state": "listed" });
        let suspended = json!({ "state": "suspended" });
        assert_eq!(expected_action(&acked, &members), Some("member"));
        assert_eq!(expected_action(&listed, &members), None);
        assert_eq!(expected_action(&listed, &both), Some("lists"));
        assert_eq!(expected_action(&suspended, &both), None);
    }

    #[test]
    fn a_network_without_a_registry_says_how_to_add_one() {
        let err = Target::from_profile(&json!({})).err().unwrap().to_string();
        assert!(err.contains("[registry]"), "{err}");
        let err = Target::from_profile(&json!({ "trustRegistry": {
            "did": "did:web:r", "authority": "did:web:n" } }))
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("query_url"), "{err}");
    }
}
