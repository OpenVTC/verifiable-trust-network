//! `nnm verify` against an in-process network over HTTPS, and a mock TRQP registry.

#[path = "../../vtn-service/tests/support/tls.rs"]
mod tls;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use nnm_cli::verify::{RegistryAnswer, RegistryTarget, Verdict, Verifier};
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use vti_specs_vtn::vtn as specs;
use vti_vtn::credentials::member;
use vti_vtn::identity::Identity;
use vti_vtn::model::Visibility;
use vti_vtn::request::sign_request;
use vti_vtn::resolve::VmKeyResolver;
use vtn_service::config::{Config, DirectoryConfig, MembershipConfig, NetworkConfig};
use vtn_service::identity::VtaKeyResolver;

struct Net {
    _dir: tempfile::TempDir,
    url: String,
    did: String,
    operator: Identity,
    /// The trust-registry projection, when the network relays a DIDComm-only registry.
    syncer: Option<Arc<vtn_service::registry::Syncer>>,
}

async fn network(visibility: Visibility) -> Net {
    network_with(visibility, None).await
}

/// A network publishing to `relayed`, a registry it reaches over its session only (no HTTPS
/// query URL), so a verifier's registry check is relayed through `vtn/registry/check`.
async fn network_with(visibility: Visibility, relayed: Option<Arc<SessionRegistry>>) -> Net {
    let dir = tempfile::tempdir().unwrap();
    let operator = Identity::generate();
    let (listener, url) = tls::bind().await;
    let config = Config {
        listen: "127.0.0.1:0".into(),
        base_url: url.clone(),
        data_dir: dir.path().to_path_buf(),
        admins: vec![operator.did().to_string()],
        resolver_url: None,
        extra_root_certificates: vec![],
        status_cache_seconds: 0,
        network: NetworkConfig {
            name: "WHN".into(),
            description: None,
            owner: "WHN owner".into(),
            framework: vti_vtn::model::Framework {
                iri: format!("{url}/gf"),
                version: "1.0".into(),
            },
        },
        membership: MembershipConfig::default(),
        directory: DirectoryConfig {
            visibility,
            ..Default::default()
        },
        roles: vec![],
        relay: Default::default(),
        auth: Default::default(),
        rooms: vec![],
        identity: None,
        secrets: None,
        messaging: None,
        registry: relayed
            .as_ref()
            .map(|r| vtn_service::config::RegistryConfig {
                did: r.me.did().to_string(),
                query_url: None,
                publish: vtn_service::registry::Publish::Members,
                sync_interval_secs: 3600,
            }),
    };
    vtn_service::init_dev(&config).unwrap();
    let mut state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    let did = state.network.did().to_string();
    let mut syncer = None;
    if let (Some(reg), Some(rc)) = (relayed, config.registry.clone()) {
        reg.admins.lock().unwrap().push(did.clone());
        let asker = Arc::new(vtn_service::registry::MessagingWriter::new(
            state.network.clone(),
            reg.clone(),
            rc.did.clone(),
            "did:web:mediator.example".into(),
            std::time::Duration::from_secs(5),
        ));
        let s = Arc::new(vtn_service::registry::Syncer::new(
            state.network.clone(),
            asker.clone(),
            rc.clone(),
        ));
        state.registry_link = Some(Arc::new(vtn_service::registry::Link {
            config: rc,
            syncer: s.clone(),
            asker: Some(asker),
            connected: None,
        }));
        syncer = Some(s);
    }
    let app = vtn_service::routes::router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Net {
        _dir: dir,
        url,
        did,
        operator,
        syncer,
    }
}

impl Net {
    async fn task<P: Payload + serde::de::DeserializeOwned>(
        &self,
        who: &Identity,
        payload: Value,
    ) -> Value {
        let payload: P = serde_json::from_value(payload).unwrap();
        let doc = sign_request(who, &self.did, &payload).await.unwrap();
        tls::client()
            .post(format!("{}/v1/trust-tasks", self.url))
            .json(&doc)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn list(&self, party: &Identity) {
        let a = self
            .task::<specs::listings::create::v0_1::Payload>(
                &self.operator,
                json!({ "did": party.did(), "kind": "community", "label": "MSF" }),
            )
            .await;
        assert!(a["type"].as_str().unwrap().ends_with("#response"), "{a:#}");
    }

    async fn join(&self, party: &Identity) {
        self.list(party).await;
        let offered = self
            .task::<specs::membership::offer::v0_1::Payload>(party, json!({}))
            .await;
        let ack = member::acknowledge(
            &offered["payload"]["offer"],
            party,
            Utc::now() - Duration::seconds(5),
            None,
        )
        .await
        .unwrap();
        let a = self
            .task::<specs::membership::acknowledge::v0_1::Payload>(
                party,
                json!({ "acknowledgement": ack }),
            )
            .await;
        assert!(a["type"].as_str().unwrap().ends_with("#response"), "{a:#}");
    }
}

fn verifier() -> Verifier {
    Verifier::new(tls::client(), Arc::new(VmKeyResolver::offline()))
}

/// A TRQP registry that holds `(entity, authority, action)` statements.
async fn registry(records: &[(String, String, &str)]) -> RegistryTarget {
    let held: Arc<Mutex<HashSet<(String, String, String)>>> = Arc::new(Mutex::new(
        records
            .iter()
            .map(|(e, a, act)| (e.clone(), a.clone(), act.to_string()))
            .collect(),
    ));
    let app = Router::new().route(
        "/authorization",
        post(move |Json(q): Json<Value>| {
            let held = held.clone();
            async move {
                assert_eq!(q["resource"], "vtn");
                let key = (
                    q["entity_id"].as_str().unwrap().to_string(),
                    q["authority_id"].as_str().unwrap().to_string(),
                    q["action"].as_str().unwrap().to_string(),
                );
                if held.lock().unwrap().contains(&key) {
                    (
                        axum::http::StatusCode::OK,
                        Json(json!({ "authorized": true })),
                    )
                } else {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(json!({ "type": "about:blank", "title": "not_found", "status": 404 })),
                    )
                }
            }
        }),
    );
    RegistryTarget {
        query_url: tls::serve(app).await,
    }
}

async fn entry(net: &Net, did: &str) -> Value {
    let doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/vtn/entries/show/0.1",
        "recipient": net.did,
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "did": did },
    });
    let answer: Value = tls::client()
        .post(format!("{}/v1/trust-tasks", net.url))
        .json(&doc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    answer["payload"]["entry"].clone()
}

#[tokio::test]
async fn a_member_verifies_end_to_end_and_the_registry_agrees() {
    let net = network(Visibility::Public).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    let reg = registry(&[(msf.did().to_string(), net.did.clone(), "member")]).await;

    let report = verifier()
        .verify(&net.url, msf.did(), Some(&net.did), Some(reg))
        .await;
    assert_eq!(report.verdict, Verdict::Member, "{}", report.to_text());
    assert_eq!(report.registry, RegistryAnswer::Member);
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.outcome != nnm_cli::verify::Outcome::Fail),
        "{}",
        report.to_text()
    );
    for name in ["listing credential", "membership grant", "acknowledgement"] {
        assert!(report.checks.iter().any(|c| c.name == name), "{name}");
    }
}

#[tokio::test]
async fn the_network_and_a_disagreeing_registry_are_indeterminate() {
    let net = network(Visibility::Public).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    let empty = registry(&[]).await;
    let report = verifier()
        .verify(&net.url, msf.did(), None, Some(empty))
        .await;
    assert_eq!(
        report.verdict,
        Verdict::Indeterminate,
        "{}",
        report.to_text()
    );
    assert!(report.to_text().contains("DISAGREE"));
}

#[tokio::test]
async fn listed_only_and_not_listed_are_not_members() {
    let net = network(Visibility::Public).await;
    let listed = Identity::generate();
    net.list(&listed).await;
    let report = verifier().verify(&net.url, listed.did(), None, None).await;
    assert_eq!(report.verdict, Verdict::Listed, "{}", report.to_text());
    assert_eq!(report.verdict.exit_code(), 1);

    let stranger = Identity::generate();
    let report = verifier()
        .verify(&net.url, stranger.did(), None, None)
        .await;
    assert_eq!(report.verdict, Verdict::NotMember, "{}", report.to_text());
}

#[tokio::test]
async fn a_wrong_network_did_is_refused() {
    let net = network(Visibility::Public).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    let report = verifier()
        .verify(
            &net.url,
            msf.did(),
            Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            None,
        )
        .await;
    assert_eq!(
        report.verdict,
        Verdict::Indeterminate,
        "{}",
        report.to_text()
    );
}

#[tokio::test]
async fn a_tampered_credential_is_not_evidence() {
    let net = network(Visibility::Public).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    let mut held = entry(&net, msf.did()).await;
    held["grant"]["validUntil"] = json!("2099-01-01T00:00:00Z");
    let (verdict, checks) = verifier().assess_entry(&held, &net.did, msf.did()).await;
    assert_eq!(verdict, Verdict::Indeterminate, "{checks:#?}");
    assert!(
        checks
            .iter()
            .any(|c| c.name == "membership grant" && c.outcome == nnm_cli::verify::Outcome::Fail)
    );
}

#[tokio::test]
async fn revoked_credentials_are_not_a_membership() {
    let net = network(Visibility::Public).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    // A copy of the entry a verifier held from before the network removed the member.
    let held = entry(&net, msf.did()).await;
    let removed = net
        .task::<specs::listings::remove::v0_1::Payload>(&net.operator, json!({ "did": msf.did() }))
        .await;
    assert!(
        removed["type"].as_str().unwrap().ends_with("#response"),
        "{removed:#}"
    );
    let (verdict, checks) = verifier().assess_entry(&held, &net.did, msf.did()).await;
    assert_eq!(verdict, Verdict::NotMember, "{checks:#?}");

    // And asked now, the network holds no entry.
    let report = verifier().verify(&net.url, msf.did(), None, None).await;
    assert_eq!(report.verdict, Verdict::NotMember, "{}", report.to_text());
}

#[tokio::test]
async fn a_restricted_directory_is_answered_by_the_registry_alone() {
    let net = network(Visibility::Members).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    let report = verifier().verify(&net.url, msf.did(), None, None).await;
    assert_eq!(
        report.verdict,
        Verdict::Indeterminate,
        "{}",
        report.to_text()
    );

    let reg = registry(&[(msf.did().to_string(), net.did.clone(), "member")]).await;
    let report = verifier()
        .verify(&net.url, msf.did(), None, Some(reg))
        .await;
    assert_eq!(report.verdict, Verdict::Member, "{}", report.to_text());
}

/// A registry reached only over the network's session: it answers `registry/record/*` from
/// an admin DID with documents signed by its own key, as the Affinidi registry does.
struct SessionRegistry {
    me: Identity,
    /// Sign answers with this key instead: a registry answer the network forged.
    forger: Option<Identity>,
    admins: Mutex<Vec<String>>,
    records: Mutex<Vec<Value>>,
}

impl SessionRegistry {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            me: Identity::generate(),
            forger: None,
            admins: Mutex::default(),
            records: Mutex::default(),
        })
    }
    fn forged() -> Arc<Self> {
        Arc::new(Self {
            me: Identity::generate(),
            forger: Some(Identity::generate()),
            admins: Mutex::default(),
            records: Mutex::default(),
        })
    }
}

#[async_trait::async_trait]
impl vtn_service::messaging::Exchange for SessionRegistry {
    async fn request(
        &self,
        _peer: &str,
        document: Value,
        _timeout: std::time::Duration,
    ) -> Result<Value, vtn_service::messaging::RequestError> {
        let type_uri = document["type"].as_str().unwrap().to_string();
        let issuer = document["issuer"].as_str().unwrap().to_string();
        assert!(self.admins.lock().unwrap().contains(&issuer));
        let payload = if type_uri.contains("/record/put/") {
            self.records
                .lock()
                .unwrap()
                .push(document["payload"]["record"].clone());
            json!({ "ok": true, "wasCreated": true })
        } else if type_uri.contains("/record/query/") {
            let want = &document["payload"];
            let records: Vec<Value> = self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["authorityId"] == want["authorityId"])
                .filter(|r| want.get("entityId").is_none_or(|e| r["entityId"] == *e))
                .cloned()
                .collect();
            json!({ "records": records })
        } else {
            json!({ "ok": true })
        };
        let signer = self.forger.as_ref().unwrap_or(&self.me);
        let answer = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": format!("{type_uri}#response"),
            "threadId": document["id"],
            "issuer": self.me.did(),
            "recipient": issuer,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": payload,
        });
        let mut signed = signer
            .sign_document_for(answer, vti_vtn::verify::AUTHENTICATION)
            .await
            .unwrap();
        signed["issuer"] = json!(self.me.did());
        Ok(signed)
    }
    fn is_connected(&self) -> bool {
        true
    }
}

/// A registry with no HTTPS: `nnm verify` asks through the network, and believes only the
/// registry's own signed answer it carries.
#[tokio::test]
async fn a_relayed_registry_answer_counts_only_when_the_registry_signed_it() {
    let net = network_with(Visibility::Public, Some(SessionRegistry::new())).await;
    let msf = Identity::generate();
    net.join(&msf).await;
    net.syncer.as_ref().unwrap().reconcile().await.unwrap();
    let report = verifier()
        .verify(&net.url, msf.did(), Some(&net.did), None)
        .await;
    assert_eq!(
        report.registry,
        RegistryAnswer::Member,
        "{}",
        report.to_text()
    );
    assert_eq!(report.registry_via, Some("relayed"));
    assert_eq!(report.verdict, Verdict::Member, "{}", report.to_text());
    assert!(
        report.to_text().contains("relayed by the network"),
        "{}",
        report.to_text()
    );

    // An answer the registry did not sign is not the registry's answer: indeterminate.
    let forged = network_with(Visibility::Public, Some(SessionRegistry::forged())).await;
    let au = Identity::generate();
    forged.join(&au).await;
    forged.syncer.as_ref().unwrap().reconcile().await.unwrap();
    let report = verifier()
        .verify(&forged.url, au.did(), Some(&forged.did), None)
        .await;
    assert_eq!(
        report.registry,
        RegistryAnswer::Unreachable,
        "{}",
        report.to_text()
    );
    assert!(
        report.to_text().contains("signature does not verify"),
        "{}",
        report.to_text()
    );
}
