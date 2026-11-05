//! `nnm registry …`: what the trust registry says about this network's members, asked of
//! the registry itself (TRQP over its HTTPS binding, `trql-client`), never of the network.
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
