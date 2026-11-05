//! `nnm verify`: check, as a third party, whether a DID is a member of a network.
//!
//! Nothing the network says is taken on its word:
//!
//! - the network's DID is resolved independently, and its profile must answer as it;
//! - the network's answer (`vtn/entries/show`) must be signed by that DID;
//! - every credential is verified against its issuer's resolved keys (`assertionMethod`):
//!   the listing and the grant against the network's, the acknowledgement against the
//!   party's; each must name the right subject, be inside its validity window, and not be
//!   revoked or suspended on its issuer's status lists;
//! - the trust registry the network publishes to is asked separately, over TRQP, whether
//!   it holds `(did, network, member, vtn)`.
//!
//! What cannot be determined is **indeterminate**, never "not a member" (VTI-REG-012). The
//! network and its registry disagreeing is indeterminate too: a verifier relying on both has
//! no answer.

use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
use vti_vtn::tasks::TRUST_TASKS_PATH;
use vti_vtn::verify::{
    ASSERTION_METHOD, AUTHENTICATION, KeyResolver, verify_document, verify_signed_by,
};
use vti_vtn::{ClientError, CredentialState, StatusChecker, VtnClient};

/// The `vtn/entries/show` Type URI.
const ENTRIES_SHOW: &str = "https://trusttasks.org/spec/vtn/entries/show/0.1";
/// The `vtn/registry/check` Type URI: the network relays the registry's signed answer.
const REGISTRY_CHECK: &str = "https://trusttasks.org/spec/vtn/registry/check/0.1";

/// The registry resource and actions a network publishes under (`docs/verifying.md`).
pub const RESOURCE: &str = "vtn";
pub const ACTION_MEMBER: &str = "member";
pub const ACTION_LISTED: &str = "lists";

/// The answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// Acknowledged, with verified evidence (or, for a directory an outsider cannot read,
    /// the registry's record).
    Member,
    /// Listed by the network, not acknowledged: not a member (VTI-VTN-013).
    Listed,
    /// A member whose membership is suspended.
    Suspended,
    /// Neither the network nor its registry holds it, or its credentials are revoked.
    NotMember,
    /// Could not be determined.
    Indeterminate,
}

impl Verdict {
    /// The process exit code: 0 member, 1 not a member, 2 indeterminate.
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Member => 0,
            Verdict::Listed | Verdict::Suspended | Verdict::NotMember => 1,
            Verdict::Indeterminate => 2,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Verdict::Member => "member",
            Verdict::Listed => "listed, not acknowledged (not a member)",
            Verdict::Suspended => "suspended (not a member while suspended)",
            Verdict::NotMember => "not a member",
            Verdict::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub outcome: Outcome,
    pub detail: String,
}

/// What the trust registry said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistryAnswer {
    Member,
    Listed,
    NotFound,
    /// No registry is published or given.
    NotPublished,
    Unreachable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub network: String,
    pub network_url: String,
    pub did: String,
    pub verdict: Verdict,
    /// What the network's own (verified) answer says, if it could be read.
    pub network_says: Option<String>,
    pub registry: RegistryAnswer,
    pub registry_url: Option<String>,
    /// How the registry was asked: `direct` (its HTTPS query URL) or `relayed` (through the
    /// network, `vtn/registry/check`, for a registry with no HTTPS), when it was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_via: Option<&'static str>,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{}: {}",
            self.did,
            self.verdict.describe().to_uppercase()
        );
        let _ = writeln!(out, "network:  {} ({})", self.network_url, self.network);
        let _ = writeln!(
            out,
            "network says:  {}",
            self.network_says.as_deref().unwrap_or("(could not read)")
        );
        let _ = writeln!(
            out,
            "registry says: {}{}",
            match self.registry {
                RegistryAnswer::Member => "member",
                RegistryAnswer::Listed => "listed",
                RegistryAnswer::NotFound => "no record",
                RegistryAnswer::NotPublished => "no registry published",
                RegistryAnswer::Unreachable => "unreachable",
            },
            match (self.registry_via, self.registry_url.as_deref()) {
                (Some("relayed"), _) =>
                    " (relayed by the network: weaker than asking directly)".to_string(),
                (_, Some(u)) => format!(" ({u})"),
                _ => String::new(),
            }
        );
        let _ = writeln!(out);
        for c in &self.checks {
            let mark = match c.outcome {
                Outcome::Pass => "ok  ",
                Outcome::Fail => "FAIL",
                Outcome::Unknown => "?   ",
            };
            let _ = writeln!(out, "  [{mark}] {}: {}", c.name, c.detail);
        }
        out
    }
}

/// Where to ask the registry: its TRQP query base (`<base>/authorization`).
#[derive(Debug, Clone)]
pub struct RegistryTarget {
    pub query_url: String,
}

/// The checks, collected as they run.
#[derive(Default)]
struct Checks(Vec<Check>);

impl Checks {
    fn add(&mut self, name: &str, outcome: Outcome, detail: impl Into<String>) -> Outcome {
        self.0.push(Check {
            name: name.into(),
            outcome,
            detail: detail.into(),
        });
        outcome
    }
}

/// The verifier: an HTTP client, a resolver for every DID it meets, and a status checker.
pub struct Verifier {
    pub http: reqwest::Client,
    pub resolver: Arc<dyn KeyResolver>,
    pub status: StatusChecker,
}

impl Verifier {
    pub fn new(http: reqwest::Client, resolver: Arc<dyn KeyResolver>) -> Self {
        let status =
            StatusChecker::with_client(VtnClient::with_http(http.clone(), ""), resolver.clone())
                .with_cache_ttl(chrono::Duration::zero());
        Self {
            http,
            resolver,
            status,
        }
    }

    /// Verify `did` at the network at `url`. `expected_network`, if given, is the DID the
    /// network must answer as; `registry` overrides the one the network's profile names.
    pub async fn verify(
        &self,
        url: &str,
        did: &str,
        expected_network: Option<&str>,
        registry: Option<RegistryTarget>,
    ) -> Report {
        let url = url.trim_end_matches('/').to_string();
        let mut checks = Checks::default();
        let client = VtnClient::with_http(self.http.clone(), &url);

        // 1. Who the network is.
        let profile = match client.profile().await {
            Ok(p) => p,
            Err(e) => {
                checks.add("network profile", Outcome::Fail, format!("{url}: {e}"));
                return self
                    .finish(url, String::new(), did, None, None, registry, checks)
                    .await;
            }
        };
        let network = profile["did"].as_str().unwrap_or_default().to_string();
        if network.is_empty() {
            checks.add("network profile", Outcome::Fail, "names no DID");
            return self
                .finish(url, network, did, None, Some(&profile), registry, checks)
                .await;
        }
        match expected_network {
            Some(expected) if expected != network => {
                checks.add(
                    "network identity",
                    Outcome::Fail,
                    format!("answers as {network}, not {expected}"),
                );
                return self
                    .finish(url, network, did, None, Some(&profile), registry, checks)
                    .await;
            }
            Some(_) => checks.add(
                "network identity",
                Outcome::Pass,
                format!("answers as {network}"),
            ),
            None => checks.add(
                "network identity",
                Outcome::Unknown,
                format!("answers as {network} (pass --expect to pin the DID you expect)"),
            ),
        };

        // 2. The network's own answer, signed by it.
        let entry = self.read_entry(&client, &network, did, &mut checks).await;
        self.finish(
            url,
            network,
            did,
            Some(entry),
            Some(&profile),
            registry,
            checks,
        )
        .await
    }

    /// `vtn/entries/show` for `did`, unsigned: `Ok(Some(entry))`, `Ok(None)` when the
    /// network holds no published entry, `Err(())` when it could not be read.
    async fn read_entry(
        &self,
        client: &VtnClient,
        network: &str,
        did: &str,
        checks: &mut Checks,
    ) -> Result<Option<Value>, ()> {
        let doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": ENTRIES_SHOW,
            "recipient": network,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "did": did },
        });
        let answer = match self
            .http
            .post(format!("{}{TRUST_TASKS_PATH}", client.base()))
            .json(&doc)
            .send()
            .await
        {
            Ok(res) => res.json::<Value>().await.unwrap_or(Value::Null),
            Err(e) => {
                checks.add("network answer", Outcome::Fail, format!("no answer: {e}"));
                return Err(());
            }
        };
        let signed =
            verify_document(&answer, network, AUTHENTICATION, self.resolver.as_ref()).await;
        let is_response = answer["type"] == format!("{ENTRIES_SHOW}#response");
        let code = answer["payload"]["code"].as_str().unwrap_or_default();
        if is_response {
            if let Err(e) = signed {
                checks.add(
                    "network answer",
                    Outcome::Fail,
                    format!("not signed by {network}: {e}"),
                );
                return Err(());
            }
            checks.add(
                "network answer",
                Outcome::Pass,
                format!("signed by {network}"),
            );
            return Ok(Some(answer["payload"]["entry"].clone()));
        }
        // A refusal. Signed or not, it grants nothing; it only says what the network says.
        let not_found = code.ends_with("notFound")
            || code.contains("notListed")
            || answer["payload"]["details"]["reason"] == "not_found";
        if not_found {
            checks.add(
                "network answer",
                if signed.is_ok() {
                    Outcome::Pass
                } else {
                    Outcome::Unknown
                },
                format!("the network holds no published entry for {did}"),
            );
            return Ok(None);
        }
        if code.ends_with("permissionDenied") || code.ends_with("forbidden") {
            checks.add(
                "network answer",
                Outcome::Unknown,
                "the directory is not public: an outsider cannot read the entry or its credentials",
            );
            return Err(());
        }
        checks.add(
            "network answer",
            Outcome::Unknown,
            format!(
                "refused: {}",
                if code.is_empty() { "no code" } else { code }
            ),
        );
        Err(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        url: String,
        network: String,
        did: &str,
        entry: Option<Result<Option<Value>, ()>>,
        profile: Option<&Value>,
        registry: Option<RegistryTarget>,
        mut checks: Checks,
    ) -> Report {
        let entry = entry.unwrap_or(Err(()));
        let (says, evidence) = match &entry {
            Ok(Some(e)) => {
                let (says, evidence) = self.assess(e, &network, did, &mut checks).await;
                (Some(says), evidence)
            }
            Ok(None) => (Some("not listed".to_string()), Evidence::NotListed),
            Err(()) => (None, Evidence::Unknown),
        };

        // 3. The registry, asked separately.
        let target = registry.or_else(|| {
            profile
                .and_then(|p| p["trustRegistry"]["queryUrl"].as_str())
                .map(|u| RegistryTarget {
                    query_url: u.to_string(),
                })
        });
        // No HTTPS query URL, but a registry named: ask through the network.
        let relay_registry = profile
            .filter(|_| target.is_none())
            .and_then(|p| p["trustRegistry"]["did"].as_str())
            .map(str::to_string);
        let mut registry_via = None;
        let mut relay_note = None;
        let registry_answer = match (&target, &relay_registry, network.is_empty()) {
            (Some(t), _, false) => {
                registry_via = Some("direct");
                self.ask_registry(&t.query_url, &network, did).await
            }
            (None, Some(reg), false) => {
                registry_via = Some("relayed");
                let (answer, note) = self.relay_registry(&url, &network, reg, did).await;
                relay_note = Some(note);
                answer
            }
            (Some(_), _, true) | (None, Some(_), true) => RegistryAnswer::Unreachable,
            (None, None, _) => RegistryAnswer::NotPublished,
        };
        let publishes_listed = profile
            .and_then(|p| p["trustRegistry"]["publishes"].as_str())
            .is_some_and(|p| p == "members-and-listed");
        match registry_answer {
            RegistryAnswer::NotPublished => {
                checks.add(
                    "trust registry",
                    Outcome::Unknown,
                    "the network publishes no trust registry",
                );
            }
            RegistryAnswer::Unreachable => {
                checks.add(
                    "trust registry",
                    Outcome::Unknown,
                    relay_note
                        .clone()
                        .unwrap_or_else(|| "the registry could not be asked".to_string()),
                );
            }
            a => {
                let agrees = match (evidence, a) {
                    (Evidence::Member, RegistryAnswer::Member) => true,
                    (Evidence::Listed, RegistryAnswer::Listed) => true,
                    (Evidence::Listed, RegistryAnswer::NotFound) => !publishes_listed,
                    (
                        Evidence::NotListed | Evidence::Revoked | Evidence::Suspended,
                        RegistryAnswer::NotFound,
                    ) => true,
                    (Evidence::Unknown | Evidence::Unverified, _) => true,
                    _ => false,
                };
                let said = match a {
                    RegistryAnswer::Member => "holds (did, network, member, vtn)",
                    RegistryAnswer::Listed => "holds (did, network, lists, vtn): listed only",
                    _ => "holds no record for it",
                };
                let said = match &relay_note {
                    Some(note) => format!("{said} ({note})"),
                    None => said.to_string(),
                };
                if agrees {
                    checks.add("trust registry", Outcome::Pass, said);
                } else {
                    checks.add(
                        "trust registry",
                        Outcome::Fail,
                        format!("{said}: THE NETWORK AND ITS TRUST REGISTRY DISAGREE"),
                    );
                }
            }
        }

        let verdict = verdict(evidence, registry_answer, &checks);
        Report {
            network,
            network_url: url,
            did: did.to_string(),
            verdict,
            network_says: says,
            registry: registry_answer,
            registry_url: target.map(|t| t.query_url),
            registry_via,
            checks: checks.0,
        }
    }

    /// Check an entry's credentials. Public so a test (or a verifier holding an entry it
    /// obtained elsewhere) can check one directly.
    pub async fn assess_entry(
        &self,
        entry: &Value,
        network: &str,
        did: &str,
    ) -> (Verdict, Vec<Check>) {
        let mut checks = Checks::default();
        let (_, evidence) = self.assess(entry, network, did, &mut checks).await;
        let v = verdict(evidence, RegistryAnswer::NotPublished, &checks);
        (v, checks.0)
    }

    async fn assess(
        &self,
        entry: &Value,
        network: &str,
        did: &str,
        checks: &mut Checks,
    ) -> (String, Evidence) {
        let state = entry["state"].as_str().unwrap_or("?").to_string();
        let acknowledged = entry["acknowledged"] == true;
        if entry["did"].as_str() != Some(did) {
            checks.add(
                "entry",
                Outcome::Fail,
                format!("the answer is about {}", entry["did"]),
            );
            return (state, Evidence::Unverified);
        }
        let now = Utc::now();
        let mut verified = true;
        let mut revoked = false;
        let mut suspended = false;

        // The listing and the grant: the network's, about the party.
        let credential = |name: &'static str, value: &Value, issuer: &str, subject: &str| {
            let value = value.clone();
            let issuer = issuer.to_string();
            let subject = subject.to_string();
            async move {
                let mut out = Vec::new();
                match verify_signed_by(&value, &issuer, self.resolver.as_ref(), now).await {
                    Ok(c) if c.subject() == subject => {
                        out.push((
                            name,
                            Outcome::Pass,
                            format!(
                                "issued by {issuer}, about {subject}, valid from {}{}",
                                c.valid_from().to_rfc3339(),
                                c.valid_until()
                                    .map(|u| format!(" until {}", u.to_rfc3339()))
                                    .unwrap_or_default()
                            ),
                        ));
                    }
                    Ok(c) => out.push((
                        name,
                        Outcome::Fail,
                        format!("names {} as its subject, not {subject}", c.subject()),
                    )),
                    Err(e) => out.push((name, Outcome::Fail, format!("does not verify: {e}"))),
                }
                let status = self.status.check(&value).await;
                (out, status)
            }
        };

        let listing = entry["listing"].clone();
        let (results, status) = credential("listing credential", &listing, network, did).await;
        for (n, o, d) in results {
            verified &= checks.add(n, o, d) == Outcome::Pass;
        }
        status_check(
            checks,
            "listing status",
            status,
            &mut revoked,
            &mut suspended,
            &mut verified,
        );

        if acknowledged || entry.get("grant").is_some_and(|g| !g.is_null()) {
            let grant = entry["grant"].clone();
            if grant.is_null() {
                verified &=
                    checks.add("membership grant", Outcome::Fail, "missing") == Outcome::Pass;
            } else {
                let (results, status) = credential("membership grant", &grant, network, did).await;
                for (n, o, d) in results {
                    verified &= checks.add(n, o, d) == Outcome::Pass;
                }
                status_check(
                    checks,
                    "grant status",
                    status,
                    &mut revoked,
                    &mut suspended,
                    &mut verified,
                );
            }
            let ack = entry["acknowledgement"].clone();
            if ack.is_null() {
                verified &=
                    checks.add("acknowledgement", Outcome::Fail, "missing") == Outcome::Pass;
            } else {
                let (results, status) = credential("acknowledgement", &ack, did, network).await;
                for (n, o, d) in results {
                    verified &= checks.add(n, o, d) == Outcome::Pass;
                }
                status_check(
                    checks,
                    "acknowledgement status",
                    status,
                    &mut revoked,
                    &mut suspended,
                    &mut verified,
                );
            }
        }

        let evidence = if revoked {
            Evidence::Revoked
        } else if !verified {
            Evidence::Unverified
        } else if suspended || state == "suspended" {
            Evidence::Suspended
        } else if acknowledged {
            Evidence::Member
        } else if state == "listed" {
            Evidence::Listed
        } else {
            Evidence::NotListed
        };
        (state, evidence)
    }

    /// The registry's answer relayed by the network (`vtn/registry/check`), for a registry with
    /// no HTTPS query surface. Only the registry's own signed answer counts: its proof must
    /// verify against the registry's DID, resolved here, and the member / listed decision is
    /// read from the records it carries, not from the network's summary. Anything less is
    /// indeterminate. The second value says how it was had, for the report.
    async fn relay_registry(
        &self,
        url: &str,
        network: &str,
        registry: &str,
        did: &str,
    ) -> (RegistryAnswer, String) {
        let doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": REGISTRY_CHECK,
            "recipient": network,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "did": did },
        });
        let relayed = match self
            .http
            .post(format!("{url}{TRUST_TASKS_PATH}"))
            .json(&doc)
            .send()
            .await
        {
            Ok(res) => res.json::<Value>().await.unwrap_or(Value::Null),
            Err(e) => {
                return (
                    RegistryAnswer::Unreachable,
                    format!("relayed by the network: no answer ({e})"),
                );
            }
        };
        let p = &relayed["payload"];
        if relayed["type"] != format!("{REGISTRY_CHECK}#response") {
            let code = p["code"].as_str().unwrap_or("no answer");
            return (
                RegistryAnswer::Unreachable,
                format!("relayed by the network: it did not relay ({code})"),
            );
        }
        if p["reachable"] != true {
            return (
                RegistryAnswer::Unreachable,
                format!(
                    "relayed by the network: it could not reach the registry ({})",
                    p["reason"].as_str().unwrap_or("no reason given")
                ),
            );
        }
        let answer = &p["answer"];
        if answer["issuer"].as_str() != Some(registry) {
            return (
                RegistryAnswer::Unreachable,
                "relayed by the network, but not answered by the registry it names".into(),
            );
        }
        // The registry signs its replies for `authentication`; accept `assertionMethod` too.
        let signed = match verify_document(answer, registry, AUTHENTICATION, self.resolver.as_ref())
            .await
        {
            Ok(v) => Ok(v),
            Err(_) => {
                verify_document(answer, registry, ASSERTION_METHOD, self.resolver.as_ref()).await
            }
        };
        if let Err(e) = signed {
            return (
                RegistryAnswer::Unreachable,
                format!("relayed by the network; the registry's signature does not verify ({e})"),
            );
        }
        let records = answer["payload"]["records"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let holds = |action: &str| {
            records.iter().any(|r| {
                r["entityId"] == did
                    && r["authorityId"] == network
                    && r["action"] == action
                    && r["resource"] == RESOURCE
                    && r["authorized"] == true
            })
        };
        let note = "relayed by the network; signed by the registry".to_string();
        if holds(ACTION_MEMBER) {
            (RegistryAnswer::Member, note)
        } else if holds(ACTION_LISTED) {
            (RegistryAnswer::Listed, note)
        } else {
            (RegistryAnswer::NotFound, note)
        }
    }

    /// TRQP `POST <base>/authorization` for `(did, network, action, vtn)`: the member record,
    /// then the listed one.
    async fn ask_registry(&self, base: &str, network: &str, did: &str) -> RegistryAnswer {
        match trqp_authorized(&self.http, base, network, did, ACTION_MEMBER).await {
            Some(true) => return RegistryAnswer::Member,
            Some(false) => {}
            None => return RegistryAnswer::Unreachable,
        }
        match trqp_authorized(&self.http, base, network, did, ACTION_LISTED).await {
            Some(true) => RegistryAnswer::Listed,
            Some(false) => RegistryAnswer::NotFound,
            None => RegistryAnswer::Unreachable,
        }
    }
}

/// One TRQP authorization query (TRQP v2.0 REST binding, as the Affinidi trust registry
/// serves it: snake_case members, `200 { authorized }`, `404` for no record). `Some(true)`
/// authorised, `Some(false)` no record or not authorised now, `None` the registry could not
/// answer. A plain reqwest call until the shared registry client lands in VTI.
pub async fn trqp_authorized(
    http: &reqwest::Client,
    base: &str,
    authority: &str,
    entity: &str,
    action: &str,
) -> Option<bool> {
    let res = http
        .post(format!("{}/authorization", base.trim_end_matches('/')))
        .json(&json!({
            "authority_id": authority,
            "entity_id": entity,
            "action": action,
            "resource": RESOURCE,
        }))
        .send()
        .await
        .ok()?;
    match res.status().as_u16() {
        200 => Some(res.json::<Value>().await.ok()?["authorized"] == true),
        404 => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Member,
    Listed,
    Suspended,
    NotListed,
    Revoked,
    /// A credential did not verify, or its status could not be determined.
    Unverified,
    /// The entry could not be read.
    Unknown,
}

fn status_check(
    checks: &mut Checks,
    name: &str,
    status: Result<CredentialState, ClientError>,
    revoked: &mut bool,
    suspended: &mut bool,
    verified: &mut bool,
) {
    match status {
        Ok(CredentialState::Valid) => {
            checks.add(
                name,
                Outcome::Pass,
                "not revoked or suspended (or carries no status)",
            );
        }
        Ok(CredentialState::Suspended) => {
            *suspended = true;
            checks.add(name, Outcome::Fail, "suspended on its issuer's status list");
        }
        Ok(CredentialState::Revoked) => {
            *revoked = true;
            checks.add(name, Outcome::Fail, "revoked on its issuer's status list");
        }
        Err(e) => {
            *verified = false;
            checks.add(name, Outcome::Unknown, format!("could not be checked: {e}"));
        }
    }
}

fn verdict(evidence: Evidence, registry: RegistryAnswer, checks: &Checks) -> Verdict {
    let disagree = checks
        .0
        .iter()
        .any(|c| c.name == "trust registry" && c.outcome == Outcome::Fail);
    if disagree {
        return Verdict::Indeterminate;
    }
    match evidence {
        Evidence::Member => Verdict::Member,
        Evidence::Listed => Verdict::Listed,
        Evidence::Suspended => Verdict::Suspended,
        Evidence::Revoked => Verdict::NotMember,
        Evidence::NotListed => match registry {
            RegistryAnswer::Unreachable => Verdict::Indeterminate,
            _ => Verdict::NotMember,
        },
        Evidence::Unverified => Verdict::Indeterminate,
        // The entry could not be read (a restricted directory): the registry alone answers.
        Evidence::Unknown => match registry {
            RegistryAnswer::Member => Verdict::Member,
            RegistryAnswer::Listed => Verdict::Listed,
            RegistryAnswer::NotFound => Verdict::NotMember,
            RegistryAnswer::NotPublished | RegistryAnswer::Unreachable => Verdict::Indeterminate,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checks(registry_fail: bool) -> Checks {
        let mut c = Checks::default();
        if registry_fail {
            c.add("trust registry", Outcome::Fail, "disagree");
        }
        c
    }

    #[test]
    fn indeterminate_is_never_not_a_member() {
        let c = checks(false);
        assert_eq!(
            verdict(Evidence::Unknown, RegistryAnswer::Unreachable, &c),
            Verdict::Indeterminate
        );
        assert_eq!(
            verdict(Evidence::Unknown, RegistryAnswer::NotPublished, &c),
            Verdict::Indeterminate
        );
        assert_eq!(
            verdict(Evidence::Unverified, RegistryAnswer::Member, &c),
            Verdict::Indeterminate
        );
        assert_eq!(
            verdict(Evidence::NotListed, RegistryAnswer::Unreachable, &c),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn a_restricted_directory_is_answered_by_the_registry() {
        let c = checks(false);
        assert_eq!(
            verdict(Evidence::Unknown, RegistryAnswer::Member, &c),
            Verdict::Member
        );
        assert_eq!(
            verdict(Evidence::Unknown, RegistryAnswer::NotFound, &c),
            Verdict::NotMember
        );
    }

    #[test]
    fn disagreement_is_indeterminate() {
        assert_eq!(
            verdict(Evidence::Member, RegistryAnswer::NotFound, &checks(true)),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn exit_codes() {
        assert_eq!(Verdict::Member.exit_code(), 0);
        assert_eq!(Verdict::Listed.exit_code(), 1);
        assert_eq!(Verdict::NotMember.exit_code(), 1);
        assert_eq!(Verdict::Indeterminate.exit_code(), 2);
    }
}
