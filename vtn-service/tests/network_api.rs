//! The service end to end over its Trust Task API, on the World Health Network example: WHN
//! lists a national network (Health-AU, itself a running VTN) and a community (MSF);
//! Health-AU acknowledges, MSF repudiates, then membership is suspended, reinstated and left.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::ServiceExt;
use trust_tasks_rs::Payload;
use vti_specs_vtn::vtn as specs;
use vti_vtn::credentials::member;
use vti_vtn::identity::Identity;
use vti_vtn::model::Visibility;
use vti_vtn::request::{request_document, sign_request};
use vti_vtn::status::Bitstring;
use vtn_service::config::{Config, DirectoryConfig, MembershipConfig, NetworkConfig};
use vtn_service::identity::VtaKeyResolver;
use vtn_service::routes::{AppState, router};

use specs::directory::{search::v0_1 as search, summary::v0_1 as summary};
use specs::entries::show::v0_1 as entries_show;
use specs::graph::show::v0_1 as graph_show;
use specs::listings::{
    create::v0_1 as create, list::v0_1 as list, reinstate::v0_1 as reinstate,
    remove::v0_1 as remove, show::v0_1 as show, suspend::v0_1 as suspend, update::v0_1 as update,
};
use specs::membership::{
    acknowledge::v0_1 as acknowledge, offer::v0_1 as offer, repudiate::v0_1 as repudiate,
};

struct TestNetwork {
    _dir: tempfile::TempDir,
    config: Config,
    state: AppState,
    app: Router,
    /// The operator's NNM identity, an administrator of this network.
    operator: Identity,
}

/// A network's answer: the response payload, or the refusal.
#[derive(Debug)]
enum Answer {
    Ok(Value),
    Refused {
        status: StatusCode,
        code: String,
        details: Value,
    },
}

impl Answer {
    fn ok(self) -> Value {
        match self {
            Answer::Ok(v) => v,
            refused => panic!("expected a response, got {refused:?}"),
        }
    }

    fn code(self) -> String {
        self.refusal().1
    }

    /// The HTTP status, code and details of a refusal.
    fn refusal(self) -> (StatusCode, String, Value) {
        match self {
            Answer::Refused {
                status,
                code,
                details,
            } => (status, code, details),
            Answer::Ok(v) => panic!("expected a refusal, got {v}"),
        }
    }
}

fn test_config(dir: &std::path::Path, name: &str, admins: Vec<String>) -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        base_url: format!("https://{}.example", name.to_lowercase()),
        data_dir: dir.to_path_buf(),
        admins,
        resolver_url: None,
        extra_root_certificates: vec![],
        status_cache_seconds: 0,
        network: NetworkConfig {
            name: name.into(),
            description: None,
            owner: format!("{name} owner"),
            framework: vti_vtn::model::Framework {
                iri: format!("https://{}.example/gf", name.to_lowercase()),
                version: "1.0".into(),
            },
        },
        membership: MembershipConfig::default(),
        directory: DirectoryConfig::default(),
        roles: vec![],
        relay: Default::default(),
        auth: Default::default(),
        rooms: vec![],
        identity: None,
        secrets: None,
        messaging: None,
        registry: None,
    }
}

async fn network(name: &str) -> TestNetwork {
    network_with(name, Visibility::Public, true).await
}

async fn network_with(name: &str, visibility: Visibility, show_counts: bool) -> TestNetwork {
    let dir = tempfile::tempdir().unwrap();
    let operator = Identity::generate();
    let mut config = test_config(dir.path(), name, vec![operator.did().to_string()]);
    config.directory.visibility = visibility;
    config.directory.show_counts = show_counts;
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    let app = router(state.clone());
    TestNetwork {
        _dir: dir,
        config,
        state,
        app,
        operator,
    }
}

impl TestNetwork {
    fn did(&self) -> String {
        self.state.network.did().to_string()
    }

    /// A `GET`.
    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Post `doc` to the Trust Task endpoint, as it is.
    async fn send(&self, doc: &Value) -> Answer {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/trust-tasks")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(doc.to_string()))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            answer["proof"].is_object(),
            "every answer is signed: {answer}"
        );
        if answer["type"] == format!("{}#response", doc["type"].as_str().unwrap()) {
            assert_eq!(status, StatusCode::OK);
            Answer::Ok(answer["payload"].clone())
        } else {
            Answer::Refused {
                status,
                code: answer["payload"]["code"].as_str().unwrap().to_string(),
                details: answer["payload"]["details"].clone(),
            }
        }
    }

    /// Task `P` with `payload`, signed by `who` (unsigned with `None`).
    async fn task<P: Payload + DeserializeOwned>(
        &self,
        who: Option<&Identity>,
        payload: Value,
    ) -> Answer {
        let payload: P = serde_json::from_value(payload).expect("a valid payload");
        let doc = match who {
            Some(who) => sign_request(who, &self.did(), &payload).await.unwrap(),
            None => request_document(None, &self.did(), &payload).unwrap(),
        };
        self.send(&doc).await
    }

    /// Task `P` as the operator, which must succeed.
    async fn admin<P: Payload + DeserializeOwned>(&self, payload: Value) -> Value {
        let operator = self.operator.clone();
        self.task::<P>(Some(&operator), payload).await.ok()
    }

    async fn bit(&self, purpose: &str, index: u64) -> bool {
        let (_, list) = self.get(&format!("/v1/status/{purpose}")).await;
        let encoded = list["credentialSubject"]["encodedList"].as_str().unwrap();
        Bitstring::decode(encoded).unwrap().get(index as u32)
    }
}

fn status_index(credential: &Value) -> u64 {
    credential["credentialStatus"][0]["statusListIndex"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn world_health_network() {
    let whn = network("WHN").await;
    let health_au = network("Health-AU").await;
    let au_identity = vtn_service::identity::load(&health_au.config)
        .await
        .unwrap();
    let msf = Identity::generate();
    let au = health_au.did();

    // --- Listing is one-sided (VTI-VTN-010) and published as unacknowledged (011).
    for (did, kind, label) in [
        (&au, "network", "Health-AU"),
        (&msf.did().to_string(), "community", "MSF"),
    ] {
        let created = whn
            .admin::<create::Payload>(json!({ "did": did, "kind": kind, "label": label }))
            .await;
        assert_eq!(created["entry"]["state"], "listed");
        assert!(
            created["entry"]["createdAt"].is_string(),
            "camelCase on the wire"
        );
    }
    let (_, index) = whn.get("/v1/index").await;
    assert_eq!(index["network"], whn.did());
    assert!(index["proof"].is_object(), "index is signed");
    assert!(
        index["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["acknowledged"] == false)
    );

    // Listing twice is refused.
    let refused = whn
        .task::<create::Payload>(Some(&whn.operator), json!({ "did": au, "kind": "network" }))
        .await;
    assert!(matches!(refused, Answer::Refused { .. }), "{refused:?}");

    // --- Health-AU (a VTN) acknowledges: ask for the unsigned offer, sign the ack.
    let offered = whn
        .task::<offer::Payload>(Some(&au_identity), json!({}))
        .await
        .ok();
    let offer = offered["offer"].clone();
    assert!(
        offer.get("proof").is_none(),
        "no signed membership credential before consent"
    );

    // An acknowledgement that is not of this party's offer is refused.
    let imposter_offer = {
        let mut o = offer.clone();
        o["credentialSubject"]["id"] = json!(msf.did());
        o
    };
    let forged = member::acknowledge(
        &imposter_offer,
        &msf,
        Utc::now() - Duration::seconds(5),
        None,
    )
    .await
    .unwrap();
    let code = whn
        .task::<acknowledge::Payload>(Some(&au_identity), json!({ "acknowledgement": forged }))
        .await
        .code();
    assert_eq!(code, "vtn/membership/acknowledge:acknowledgementInvalid");

    let ack = member::acknowledge(
        &offer,
        &au_identity,
        Utc::now() - Duration::seconds(5),
        None,
    )
    .await
    .unwrap();
    let acknowledged = whn
        .task::<acknowledge::Payload>(Some(&au_identity), json!({ "acknowledgement": ack }))
        .await
        .ok();
    let entry = &acknowledged["entry"];
    assert_eq!(entry["state"], "acknowledged");
    assert_eq!(entry["acknowledged"], true);
    assert_eq!(entry["kind"], "network");
    let grant = entry["grant"].clone();
    assert!(
        grant["proof"].is_object(),
        "grant signed after acknowledgement"
    );
    assert!(grant["credentialSubject"].get("digestMultibase").is_none());

    // The same acknowledgement again is the same answer, not an error.
    let again = whn
        .task::<acknowledge::Payload>(Some(&au_identity), json!({ "acknowledgement": ack }))
        .await
        .ok();
    assert_eq!(again["entry"]["grant"], grant);
    // ...and the offer is gone.
    let code = whn
        .task::<offer::Payload>(Some(&au_identity), json!({}))
        .await
        .code();
    assert_eq!(code, "vtn/membership/offer:alreadyMember");

    // The grant is fetchable by id and its status is clear.
    let grant_id = grant["id"].as_str().unwrap();
    let (status, fetched) = whn.get(&format!("/v1/credentials/{grant_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, grant);
    assert!(!whn.bit("revocation", status_index(&grant)).await);

    // --- MSF repudiates its listing: still published, with the repudiation (VTI-VTN-012).
    let msf_entry = whn
        .task::<entries_show::Payload>(None, json!({ "did": msf.did() }))
        .await
        .ok();
    let repudiation = member::repudiate(
        &msf_entry["entry"]["listing"],
        &msf,
        Utc::now() - Duration::seconds(5),
    )
    .await
    .unwrap();
    let repudiated = whn
        .task::<repudiate::Payload>(Some(&msf), json!({ "repudiation": repudiation }))
        .await
        .ok();
    assert_eq!(repudiated["entry"]["state"], "repudiated");
    let (_, index) = whn.get("/v1/index").await;
    let published = index["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["did"] == msf.did())
        .unwrap();
    assert!(published["repudiation"].is_object());
    // Nothing left to acknowledge.
    let code = whn
        .task::<offer::Payload>(Some(&msf), json!({}))
        .await
        .code();
    assert_eq!(code, "vtn/membership/offer:notListed");

    // --- Suspend and reinstate Health-AU: the suspension bit follows.
    whn.admin::<suspend::Payload>(json!({ "did": au, "reason": "audit" }))
        .await;
    assert!(whn.bit("suspension", status_index(&grant)).await);
    // Suspending again changes nothing and is not an error.
    let again = whn.admin::<suspend::Payload>(json!({ "did": au })).await;
    assert_eq!(again["entry"]["state"], "suspended");
    let shown = whn
        .task::<entries_show::Payload>(None, json!({ "did": au }))
        .await
        .ok();
    assert_eq!(
        shown["entry"]["acknowledged"], false,
        "suspended is not membership"
    );
    whn.admin::<reinstate::Payload>(json!({ "did": au })).await;
    assert!(!whn.bit("suspension", status_index(&grant)).await);

    // --- The graph: one edge per credential, both halves of the membership edge.
    let graph = whn.task::<graph_show::Payload>(None, json!({})).await.ok();
    let roles: Vec<&str> = graph["graph"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["target"] == au || e["source"] == au)
        .map(|e| e["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles.len(), 3, "{roles:?}");
    for role in ["listing", "grant", "acknowledgement"] {
        assert!(roles.contains(&role), "{role} in {roles:?}");
    }
    // The acknowledgement is the member's credential, checked against the member's own
    // status (it carries none here, so its validity window is its control): not left
    // `unchecked` because this network did not issue it.
    let ack = graph["graph"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["role"] == "acknowledgement" && (e["target"] == au || e["source"] == au))
        .unwrap();
    assert_eq!(ack["status"], "valid", "{ack:#}");
    // Including exited entries is for administrators.
    let code = whn
        .task::<graph_show::Payload>(None, json!({ "includeExited": true }))
        .await
        .code();
    assert_eq!(code, "permissionDenied");

    // --- Health-AU departs by repudiating its grant: all WHN-issued credentials revoked.
    let departure = member::repudiate(&grant, &au_identity, Utc::now() - Duration::seconds(5))
        .await
        .unwrap();
    let departed = whn
        .task::<repudiate::Payload>(Some(&au_identity), json!({ "repudiation": departure }))
        .await
        .ok();
    assert_eq!(departed["entry"]["state"], "departed");
    assert!(whn.bit("revocation", status_index(&grant)).await);
    assert!(
        whn.bit("revocation", status_index(&departed["entry"]["listing"]))
            .await
    );
    let (_, index) = whn.get("/v1/index").await;
    assert!(
        index["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["did"] != au)
    );

    // --- Re-listing starts over.
    let relisted = whn
        .admin::<create::Payload>(json!({ "did": au, "kind": "network" }))
        .await;
    assert_eq!(relisted["entry"]["state"], "listed");
    assert_eq!(relisted["entry"]["history"].as_array().unwrap().len(), 6);
    assert!(relisted["entry"]["history"][0]["changedAt"].is_string());

    // --- Audit trail records who did what.
    let audit = whn
        .admin::<specs::audit::list::v0_1::Payload>(json!({}))
        .await;
    let actors: Vec<&str> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["actor"].as_str().unwrap())
        .collect();
    assert!(actors.contains(&au.as_str()) && actors.contains(&whn.operator.did()));
    let latest = whn
        .admin::<specs::audit::list::v0_1::Payload>(json!({ "did": au, "limit": 1 }))
        .await;
    assert_eq!(latest["events"].as_array().unwrap().len(), 1);
    assert_eq!(latest["events"][0]["event"], "list");
}

#[tokio::test]
async fn administration_needs_an_administrators_signature() {
    let whn = network("WHN").await;
    let payload = json!({ "did": "did:key:z6Mkx", "kind": "community" });

    // Unsigned: the specification requires a proof.
    let code = whn
        .task::<create::Payload>(None, payload.clone())
        .await
        .code();
    assert_eq!(code, "proofRequired");

    // Signed by someone who is not an administrator.
    let stranger = Identity::generate();
    let (status, code, _) = whn
        .task::<create::Payload>(Some(&stranger), payload.clone())
        .await
        .refusal();
    assert_eq!(code, "permissionDenied");
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The operator.
    whn.admin::<list::Payload>(json!({})).await;
}

#[tokio::test]
async fn a_request_is_bound_to_its_signer_purpose_network_and_id() {
    let whn = network("WHN").await;
    let payload: list::Payload = serde_json::from_value(json!({})).unwrap();

    // Claiming the operator as issuer, signed by someone else.
    let stranger = Identity::generate();
    let mut forged = request_document(Some(whn.operator.did()), &whn.did(), &payload).unwrap();
    forged = stranger
        .sign_document_for(forged, vti_vtn::verify::AUTHENTICATION)
        .await
        .unwrap();
    let code = whn.send(&forged).await.code();
    assert!(
        code == "proofInvalid" || code == "permissionDenied",
        "{code}"
    );

    // The operator's own key, but made for assertion, not authentication.
    let wrong_purpose = whn
        .operator
        .sign_document(request_document(Some(whn.operator.did()), &whn.did(), &payload).unwrap())
        .await
        .unwrap();
    let code = whn.send(&wrong_purpose).await.code();
    assert!(
        code == "proofInvalid" || code == "permissionDenied",
        "{code}"
    );

    // Addressed to another network.
    let elsewhere = sign_request(&whn.operator, "did:key:z6MkOther", &payload)
        .await
        .unwrap();
    assert_eq!(whn.send(&elsewhere).await.code(), "wrongRecipient");

    // Too old: outside the acceptance window.
    let mut stale = request_document(Some(whn.operator.did()), &whn.did(), &payload).unwrap();
    stale["issuedAt"] = json!((Utc::now() - Duration::minutes(30)).to_rfc3339());
    let stale = whn
        .operator
        .sign_document_for(stale, vti_vtn::verify::AUTHENTICATION)
        .await
        .unwrap();
    assert!(matches!(whn.send(&stale).await, Answer::Refused { .. }));

    // A document is executed once: the same one again is answered, not re-run.
    let listed = sign_request(
        &whn.operator,
        &whn.did(),
        &serde_json::from_value::<create::Payload>(
            json!({ "did": "did:key:z6MkOnce", "kind": "community" }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let first = whn.send(&listed).await.ok();
    let second = whn.send(&listed).await.ok();
    assert_eq!(first, second);
    // A different document under the same id is a conflict.
    let mut other = listed.clone();
    other.as_object_mut().unwrap().remove("proof");
    other["payload"]["did"] = json!("did:key:z6MkTwice");
    let other = whn
        .operator
        .sign_document_for(other, vti_vtn::verify::AUTHENTICATION)
        .await
        .unwrap();
    assert_eq!(whn.send(&other).await.code(), "idConflict");
}

/// The provisioned path without a live VTA: keys in the `[secrets]` store as `vtn setup`
/// leaves them, loaded by `[identity]`. The VTA mints a `did:webvh`; a `did:key` stands in
/// so the test needs no resolver.
#[tokio::test]
async fn provisioned_identity_loads_from_the_secret_store() {
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vtn_service::config::ProvisionedIdentity;

    let dir = tempfile::tempdir().unwrap();
    let seed = [42u8; 32];
    let expected = Identity::from_ed25519_seed(&seed);
    let secret = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(
        Some(expected.verification_method()),
        Some(&seed),
    );
    let bundle = DidSecretsBundle {
        did: expected.did().to_string(),
        secrets: vec![SecretEntry {
            key_id: expected.verification_method().to_string(),
            key_type: vta_sdk::keys::KeyType::Ed25519,
            private_key_multibase: secret.get_private_keymultibase().unwrap(),
        }],
    };

    let secrets: vti_secrets::SecretsConfig =
        toml::from_str("backend = \"plaintext\"\nallow_plaintext = true").unwrap();
    let store = vti_secrets::create_seed_store(&secrets, dir.path()).unwrap();
    vtn_service::identity::save_keys(&*store, &bundle)
        .await
        .unwrap();

    let mut config = test_config(dir.path(), "WHN", vec![]);
    config.identity = Some(ProvisionedIdentity {
        did: expected.did().to_string(),
        vta_did: "did:webvh:QmVTA:vta.example.com".into(),
        context: "vtn".into(),
    });
    config.secrets = Some(secrets);

    // `vtn init` refuses a provisioned network.
    assert!(vtn_service::init_dev(&config).is_err());

    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    assert_eq!(state.network.did(), expected.did());

    // It signs as that identity: the index verifies against the provisioned key.
    let index = state.network.index().await.unwrap();
    let vm = index["proof"]["verificationMethod"].as_str().unwrap();
    assert_eq!(vm, expected.verification_method());

    // A bundle for another DID is refused.
    let mut other = config.clone();
    other.identity.as_mut().unwrap().did = Identity::generate().did().to_string();
    assert!(vtn_service::identity::load(&other).await.is_err());
}

#[tokio::test]
async fn network_removal_revokes_what_it_issued() {
    let whn = network("WHN").await;
    let vtc = Identity::generate();
    let created = whn
        .admin::<create::Payload>(json!({ "did": vtc.did(), "kind": "community" }))
        .await;
    let listing_index = status_index(&created["entry"]["listing"]["credential"]);
    let removed = whn
        .admin::<remove::Payload>(json!({ "did": vtc.did(), "reason": "criteria" }))
        .await;
    assert_eq!(removed["entry"]["state"], "removed");
    assert!(whn.bit("revocation", listing_index).await);
    // Removed is unpublished: answered as if absent.
    let shown = whn
        .task::<entries_show::Payload>(None, json!({ "did": vtc.did() }))
        .await;
    assert!(matches!(shown, Answer::Refused { .. }), "{shown:?}");
    // Removing again is not an error; reinstating a removed entry is.
    whn.admin::<remove::Payload>(json!({ "did": vtc.did() }))
        .await;
    let code = whn
        .task::<reinstate::Payload>(Some(&whn.operator), json!({ "did": vtc.did() }))
        .await
        .code();
    assert_eq!(code, "vtn/listings/reinstate:invalidTransition");
}

/// List `party` and have it acknowledge. It asks for its offer as itself, whatever the
/// directory's visibility.
async fn join(net: &TestNetwork, party: &Identity, kind: &str, label: &str, extra: Value) {
    let mut body = json!({ "did": party.did(), "kind": kind, "label": label });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    net.admin::<create::Payload>(body).await;
    let offered = net
        .task::<offer::Payload>(Some(party), json!({}))
        .await
        .ok();
    let ack = member::acknowledge(
        &offered["offer"],
        party,
        Utc::now() - Duration::seconds(5),
        None,
    )
    .await
    .unwrap();
    net.task::<acknowledge::Payload>(Some(party), json!({ "acknowledgement": ack }))
        .await
        .ok();
}

/// A community's membership credential (the grant) for `person`, signed by the community.
async fn community_vmc(community: &Identity, person: &Identity) -> Value {
    let mut vmc = dtg_credentials::DTGCredential::new_vmc(
        community.did().to_string(),
        person.did().to_string(),
        Utc::now() - Duration::seconds(5),
        Some(Utc::now() + Duration::days(1)),
        false,
    )
    .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    community.sign_credential(&mut vmc).await.unwrap();
    serde_json::to_value(vmc).unwrap()
}

fn entries(answer: Value) -> Vec<Value> {
    answer["entries"].as_array().unwrap().clone()
}

#[tokio::test]
async fn public_directory_is_searchable() {
    let whn = network("WHN").await;
    let msf = Identity::generate();
    join(
        &whn,
        &msf,
        "community",
        "Médecins Sans Frontières",
        json!({ "description": "Emergency medical humanitarian organisation", "tags": ["ngo", "emergency"] }),
    )
    .await;
    let nz = Identity::generate();
    whn.admin::<create::Payload>(json!({
        "did": nz.did(), "kind": "network", "label": "Health-NZ",
        "url": "https://health-nz.example", "tags": ["new zealand"],
    }))
    .await;

    let rows = entries(whn.task::<search::Payload>(None, json!({})).await.ok());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["acknowledged"], true, "members first");
    assert_eq!(rows[1]["state"], "listed");

    let hits = entries(
        whn.task::<search::Payload>(None, json!({ "q": "emergency NGO" }))
            .await
            .ok(),
    );
    assert_eq!(hits.len(), 1);
    let hits = entries(
        whn.task::<search::Payload>(None, json!({ "kind": "network", "membersOnly": true }))
            .await
            .ok(),
    );
    assert!(hits.is_empty(), "Health-NZ has not acknowledged");

    let counts = whn.task::<summary::Payload>(None, json!({})).await.ok();
    assert_eq!(counts["summary"]["acknowledged"], 1);
    assert_eq!(counts["summary"]["unacknowledged"], 1);

    // The admin edits part of a profile: what is named changes, the rest stays, nothing is
    // re-issued.
    let updated = whn
        .admin::<update::Payload>(json!({ "did": nz.did(), "description": "Te Whatu Ora" }))
        .await;
    let entry = &updated["entry"];
    assert_eq!(entry["state"], "listed");
    assert_eq!(entry["label"], "Health-NZ");
    assert_eq!(entry["profile"]["url"], "https://health-nz.example");
    assert_eq!(entry["profile"]["tags"], json!(["new zealand"]));
    let hits = entries(
        whn.task::<search::Payload>(None, json!({ "q": "whatu" }))
            .await
            .ok(),
    );
    assert_eq!(hits.len(), 1);
    // An empty value clears.
    let cleared = whn
        .admin::<update::Payload>(json!({ "did": nz.did(), "url": "" }))
        .await;
    assert!(cleared["entry"]["profile"].get("url").is_none());
}

#[tokio::test]
async fn members_only_directory() {
    let whn = network_with("WHN", Visibility::Members, true).await;
    let msf = Identity::generate();
    join(&whn, &msf, "community", "MSF", json!({})).await;
    let pending = Identity::generate();
    whn.admin::<create::Payload>(
        json!({ "did": pending.did(), "kind": "community", "label": "Pending" }),
    )
    .await;

    // Anonymous: no set, but the profile, the page, status lists and counts are public.
    assert_eq!(
        whn.task::<search::Payload>(None, json!({})).await.code(),
        "permissionDenied"
    );
    assert_eq!(
        whn.task::<graph_show::Payload>(None, json!({}))
            .await
            .code(),
        "permissionDenied"
    );
    assert_eq!(
        whn.task::<entries_show::Payload>(None, json!({ "did": msf.did() }))
            .await
            .code(),
        "permissionDenied"
    );
    // The index and credentials are unsigned fetches, so a restricted network does not serve
    // them (A21).
    assert_eq!(whn.get("/v1/index").await.0, StatusCode::FORBIDDEN);
    let (_, info) = whn.get("/.well-known/vtn").await;
    assert_eq!(info["directory"]["visibility"], "members");
    whn.task::<summary::Payload>(None, json!({})).await.ok();
    assert_eq!(whn.get("/v1/status/revocation").await.0, StatusCode::OK);

    // A member community, as itself.
    let rows = entries(
        whn.task::<search::Payload>(Some(&msf), json!({}))
            .await
            .ok(),
    );
    assert_eq!(rows.len(), 2);

    // A person presenting MSF's membership credential.
    let person = Identity::generate();
    let vmc = community_vmc(&msf, &person).await;
    whn.task::<search::Payload>(Some(&person), json!({ "membership": vmc }))
        .await
        .ok();
    // ...but not without it.
    assert_eq!(
        whn.task::<search::Payload>(Some(&person), json!({}))
            .await
            .code(),
        "permissionDenied"
    );

    // Someone else presenting that person's credential.
    let thief = Identity::generate();
    assert_eq!(
        whn.task::<search::Payload>(Some(&thief), json!({ "membership": vmc }))
            .await
            .code(),
        "permissionDenied"
    );
    // A credential from a community that is listed but has not acknowledged.
    let pending_member = Identity::generate();
    let vmc = community_vmc(&pending, &pending_member).await;
    assert_eq!(
        whn.task::<search::Payload>(Some(&pending_member), json!({ "membership": vmc }))
            .await
            .code(),
        "permissionDenied"
    );

    // A listed, unacknowledged party gets its own offer and entry, not the directory.
    assert_eq!(
        whn.task::<search::Payload>(Some(&pending), json!({}))
            .await
            .code(),
        "permissionDenied"
    );
    whn.task::<offer::Payload>(Some(&pending), json!({}))
        .await
        .ok();
    whn.task::<entries_show::Payload>(Some(&pending), json!({ "did": pending.did() }))
        .await
        .ok();
    // ...and no administration.
    assert_eq!(
        whn.task::<list::Payload>(Some(&pending), json!({}))
            .await
            .code(),
        "permissionDenied"
    );

    // A stranger asking for an offer learns only that it is not listed.
    assert_eq!(
        whn.task::<offer::Payload>(Some(&Identity::generate()), json!({}))
            .await
            .code(),
        "vtn/membership/offer:notListed"
    );
}

#[tokio::test]
async fn admins_only_directory_and_hidden_counts() {
    let whn = network_with("WHN", Visibility::Admins, false).await;
    let msf = Identity::generate();
    join(&whn, &msf, "community", "MSF", json!({})).await;

    assert_eq!(
        whn.task::<search::Payload>(Some(&msf), json!({}))
            .await
            .code(),
        "permissionDenied",
        "members do not see an admins-only directory"
    );
    assert_eq!(
        whn.task::<summary::Payload>(None, json!({})).await.code(),
        "permissionDenied",
        "counts hidden"
    );
    // A member still reads its own entry.
    whn.task::<entries_show::Payload>(Some(&msf), json!({ "did": msf.did() }))
        .await
        .ok();
    let rows = entries(whn.admin::<search::Payload>(json!({})).await);
    assert_eq!(rows.len(), 1);
    let shown = whn
        .admin::<show::Payload>(json!({ "did": msf.did() }))
        .await;
    assert_eq!(shown["entry"]["state"], "acknowledged");
}

#[tokio::test]
async fn an_unknown_task_is_refused_by_type() {
    let whn = network("WHN").await;
    let mut doc = request_document(
        None,
        &whn.did(),
        &serde_json::from_value::<search::Payload>(json!({})).unwrap(),
    )
    .unwrap();
    doc["type"] = json!("https://trusttasks.org/spec/vtn/directory/search/9.9");
    assert_eq!(whn.send(&doc).await.code(), "unsupportedVersion");
    doc["type"] = json!("https://trusttasks.org/spec/vtn/nothing/here/0.1");
    assert_eq!(whn.send(&doc).await.code(), "unsupportedType");
}

#[tokio::test]
async fn health_and_readiness_answer_without_a_signature() {
    // An admins-only directory: neither probe is gated by it.
    let whn = network_with("WHN", Visibility::Admins, false).await;
    let (status, live) = whn.get("/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(live["status"], "ok");
    assert_eq!(live["did"], whn.did());
    assert_eq!(live["version"], env!("CARGO_PKG_VERSION"));

    let (status, ready) = whn.get("/health/ready").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ready,
        json!({ "status": "ready", "checks": { "store": "ok" } })
    );
}

#[tokio::test]
async fn landing_page_is_served_with_a_strict_policy() {
    let whn = network("WHN").await;
    let res = whn
        .app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let csp = res.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("connect-src 'self'") && csp.contains("frame-ancestors 'none'"));
    let html = String::from_utf8(
        to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("/v1/trust-tasks") && html.contains("vtn/directory/search"));
}

#[tokio::test]
async fn every_task_is_served() {
    // Every `vtn/*` request type the pinned specifications define has a handler: an unrouted
    // one would answer `unsupportedType`.
    let whn = network("WHN").await;
    let requests: Vec<&str> = vti_specs_vtn::schema_index::INDEX
        .iter()
        .map(|e| e.type_uri)
        .filter(|uri| !uri.contains('#'))
        .collect();
    assert_eq!(requests.len(), 35, "{requests:?}");
    let template = request_document(
        None,
        &whn.did(),
        &serde_json::from_value::<search::Payload>(json!({})).unwrap(),
    )
    .unwrap();
    for uri in requests {
        let mut doc = template.clone();
        doc["id"] = json!(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        doc["type"] = json!(uri);
        if let Answer::Refused { code, .. } = whn.send(&doc).await {
            assert!(!code.starts_with("unsupported"), "{uri}: {code}");
        }
    }
}
