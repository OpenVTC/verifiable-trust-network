//! The service end to end over HTTP, on the World Health Network example: WHN lists a
//! national network (Health-AU, itself a running VTN) and a community (MSF); Health-AU
//! acknowledges, MSF repudiates, then membership is suspended, reinstated and left.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use tower::ServiceExt;
use vtn_core::credentials::member;
use vtn_core::identity::Identity;
use vtn_core::model::Visibility;
use vtn_core::status::Bitstring;
use vtn_core::verify::AUTHENTICATION;
use vtn_service::auth::{Challenge, authentication_document};
use vtn_service::config::{Config, DirectoryConfig, MembershipConfig, NetworkConfig};
use vtn_service::identity::VtaKeyResolver;
use vtn_service::routes::{AppState, router};

struct TestNetwork {
    _dir: tempfile::TempDir,
    config: Config,
    state: AppState,
    app: Router,
    /// The operator's NNM identity, an administrator of this network.
    operator: Identity,
    token: String,
}

fn test_config(dir: &std::path::Path, name: &str, admins: Vec<String>) -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        base_url: format!("https://{}.example", name.to_lowercase()),
        data_dir: dir.to_path_buf(),
        admins,
        resolver_url: None,
        status_cache_seconds: 0,
        network: NetworkConfig {
            name: name.into(),
            description: None,
            owner: format!("{name} owner"),
            framework: vtn_core::model::Framework {
                iri: format!("https://{}.example/gf", name.to_lowercase()),
                version: "1.0".into(),
            },
        },
        membership: MembershipConfig::default(),
        directory: DirectoryConfig::default(),
        roles: vec![],
        relay: Default::default(),
        rooms: vec![],
        identity: None,
        secrets: None,
    }
}

async fn network(name: &str) -> TestNetwork {
    network_with(name, Visibility::Public).await
}

async fn network_with(name: &str, visibility: Visibility) -> TestNetwork {
    let dir = tempfile::tempdir().unwrap();
    let operator = Identity::generate();
    let mut config = test_config(dir.path(), name, vec![operator.did().to_string()]);
    config.directory.visibility = visibility;
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    let app = router(state.clone());
    let mut net = TestNetwork {
        _dir: dir,
        config,
        state,
        app,
        operator,
        token: String::new(),
    };
    let operator = net.operator.clone();
    net.token = net.sign_in(&operator).await.expect("operator signs in");
    net
}

impl TestNetwork {
    /// Sign in as `who` the way the NNM does; the session token, or the refusal status.
    async fn sign_in(&self, who: &Identity) -> Result<String, StatusCode> {
        self.sign_in_with(who, None).await
    }

    /// Sign in as `who`, presenting `membership` (a VMC naming `who`) if given.
    async fn sign_in_with(
        &self,
        who: &Identity,
        membership: Option<Value>,
    ) -> Result<String, StatusCode> {
        let (status, challenge) = self
            .public(
                "POST",
                "/v1/auth/challenge",
                Some(json!({ "did": who.did() })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        let challenge: Challenge = serde_json::from_value(challenge).unwrap();
        let document = who
            .sign_document_for(
                authentication_document(who.did(), &challenge),
                AUTHENTICATION,
            )
            .await
            .unwrap();
        let (status, grant) = self
            .public(
                "POST",
                "/v1/auth/session",
                Some(json!({ "authentication": document, "membership": membership })),
            )
            .await;
        if status != StatusCode::OK {
            return Err(status);
        }
        Ok(grant["token"].as_str().unwrap().to_string())
    }

    fn did(&self) -> String {
        self.state.network.did().to_string()
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        admin: bool,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if admin {
            req = req.header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn admin(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (status, value) = self.call(method, path, body, true).await;
        assert!(status.is_success(), "{method} {path}: {status} {value}");
        value
    }

    /// A request with `token` as the bearer (a member's or listed party's session).
    async fn as_session(&self, token: &str, method: &str, path: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn public(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call(method, path, body, false).await
    }

    async fn bit(&self, purpose: &str, index: u64) -> bool {
        let (_, list) = self
            .public("GET", &format!("/v1/status/{purpose}"), None)
            .await;
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

fn entry_path(did: &str, suffix: &str) -> String {
    format!("/v1/entries/{did}{suffix}")
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
        let entry = whn
            .admin(
                "POST",
                "/v1/admin/entries",
                Some(json!({ "did": did, "kind": kind, "label": label })),
            )
            .await;
        assert_eq!(entry["state"], "listed");
    }
    let (_, index) = whn.public("GET", "/v1/index", None).await;
    assert_eq!(index["network"], whn.did());
    assert!(index["proof"].is_object(), "index is signed");
    assert!(
        index["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["acknowledged"] == false)
    );

    // Listing twice is a conflict.
    let (status, _) = whn
        .call(
            "POST",
            "/v1/admin/entries",
            Some(json!({ "did": au, "kind": "network" })),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // --- Health-AU (a VTN) acknowledges: fetch the unsigned offer, sign the ack.
    let (status, offer) = whn.public("GET", &entry_path(&au, "/offer"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        offer.get("proof").is_none(),
        "no signed membership credential before consent"
    );

    // Someone else's acknowledgement is refused.
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
    let (status, _) = whn
        .public(
            "POST",
            &entry_path(&au, "/acknowledge"),
            Some(json!({ "acknowledgement": forged })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let ack = member::acknowledge(
        &offer,
        &au_identity,
        Utc::now() - Duration::seconds(5),
        None,
    )
    .await
    .unwrap();
    let (status, entry) = whn
        .public(
            "POST",
            &entry_path(&au, "/acknowledge"),
            Some(json!({ "acknowledgement": ack })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{entry}");
    assert_eq!(entry["state"], "acknowledged");
    assert_eq!(entry["acknowledged"], true);
    assert_eq!(entry["kind"], "network");
    let grant = entry["grant"].clone();
    assert!(
        grant["proof"].is_object(),
        "grant signed after acknowledgement"
    );
    assert!(grant["credentialSubject"].get("digestMultibase").is_none());

    // The grant is fetchable by id and its status is clear.
    let grant_id = grant["id"].as_str().unwrap();
    let (status, fetched) = whn
        .public("GET", &format!("/v1/credentials/{grant_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, grant);
    assert!(!whn.bit("revocation", status_index(&grant)).await);

    // --- MSF repudiates its listing: still published, with the repudiation (VTI-VTN-012).
    let (_, msf_entry) = whn.public("GET", &entry_path(msf.did(), ""), None).await;
    let repudiation = member::repudiate(
        &msf_entry["listing"],
        &msf,
        Utc::now() - Duration::seconds(5),
    )
    .await
    .unwrap();
    let (status, msf_entry) = whn
        .public(
            "POST",
            &entry_path(msf.did(), "/repudiate"),
            Some(json!({ "repudiation": repudiation })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{msf_entry}");
    assert_eq!(msf_entry["state"], "repudiated");
    let (_, index) = whn.public("GET", "/v1/index", None).await;
    let published = index["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["did"] == msf.did())
        .unwrap();
    assert!(published["repudiation"].is_object());
    // Nothing left to acknowledge.
    let (status, _) = whn
        .public("GET", &entry_path(msf.did(), "/offer"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // --- Suspend and reinstate Health-AU: the suspension bit follows.
    whn.admin(
        "POST",
        &format!("/v1/admin/entries/{au}/suspend"),
        Some(json!({ "reason": "audit" })),
    )
    .await;
    assert!(whn.bit("suspension", status_index(&grant)).await);
    let (_, entry) = whn.public("GET", &entry_path(&au, ""), None).await;
    assert_eq!(entry["acknowledged"], false, "suspended is not membership");
    whn.admin("POST", &format!("/v1/admin/entries/{au}/reinstate"), None)
        .await;
    assert!(!whn.bit("suspension", status_index(&grant)).await);

    // --- The graph: one edge per credential, both halves of the membership edge.
    let (_, graph) = whn.public("GET", "/v1/graph", None).await;
    let roles: Vec<&str> = graph["edges"]
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

    // --- Health-AU departs by repudiating its grant: all WHN-issued credentials revoked.
    let departure = member::repudiate(&grant, &au_identity, Utc::now() - Duration::seconds(5))
        .await
        .unwrap();
    let (status, entry) = whn
        .public(
            "POST",
            &entry_path(&au, "/repudiate"),
            Some(json!({ "repudiation": departure })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{entry}");
    assert_eq!(entry["state"], "departed");
    assert!(whn.bit("revocation", status_index(&grant)).await);
    assert!(whn.bit("revocation", status_index(&entry["listing"])).await);
    let (_, index) = whn.public("GET", "/v1/index", None).await;
    assert!(
        index["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["did"] != au)
    );

    // --- Re-listing starts over.
    let entry = whn
        .admin(
            "POST",
            "/v1/admin/entries",
            Some(json!({ "did": au, "kind": "network" })),
        )
        .await;
    assert_eq!(entry["state"], "listed");
    assert_eq!(entry["history"].as_array().unwrap().len(), 6);

    // --- Audit trail records who did what.
    let audit = whn.admin("GET", "/v1/admin/audit", None).await;
    let actors: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["actor"].as_str().unwrap())
        .collect();
    assert!(actors.contains(&au.as_str()) && actors.contains(&whn.operator.did()));
}

#[tokio::test]
async fn admin_routes_need_the_token() {
    let whn = network("WHN").await;
    let (status, _) = whn
        .call(
            "POST",
            "/v1/admin/entries",
            Some(json!({ "did": "did:key:z6Mkx", "kind": "community" })),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = whn.call("GET", "/v1/admin/audit", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The operator's session works, and says who it is.
    let me = whn.admin("GET", "/v1/admin/whoami", None).await;
    assert_eq!(me["did"], whn.operator.did());
}

#[tokio::test]
async fn only_administrators_sign_in() {
    let whn = network("WHN").await;
    // A DID that proves control of itself but is not an administrator.
    let stranger = Identity::generate();
    assert_eq!(whn.sign_in(&stranger).await, Err(StatusCode::UNAUTHORIZED));

    // A document for the operator's DID signed by someone else's key.
    let (_, challenge) = whn
        .public(
            "POST",
            "/v1/auth/challenge",
            Some(json!({ "did": whn.operator.did() })),
        )
        .await;
    let challenge: Challenge = serde_json::from_value(challenge).unwrap();
    let forged = stranger
        .sign_document_for(
            authentication_document(whn.operator.did(), &challenge),
            AUTHENTICATION,
        )
        .await
        .unwrap();
    let (status, _) = whn
        .public(
            "POST",
            "/v1/auth/session",
            Some(json!({ "authentication": forged })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A genuine document signed for the wrong purpose (an assertion, not authentication).
    let (_, challenge) = whn
        .public(
            "POST",
            "/v1/auth/challenge",
            Some(json!({ "did": whn.operator.did() })),
        )
        .await;
    let challenge: Challenge = serde_json::from_value(challenge).unwrap();
    let wrong_purpose = whn
        .operator
        .sign_document(authentication_document(whn.operator.did(), &challenge))
        .await
        .unwrap();
    let (status, _) = whn
        .public(
            "POST",
            "/v1/auth/session",
            Some(json!({ "authentication": wrong_purpose })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A challenge is single use.
    let (_, challenge) = whn
        .public(
            "POST",
            "/v1/auth/challenge",
            Some(json!({ "did": whn.operator.did() })),
        )
        .await;
    let challenge: Challenge = serde_json::from_value(challenge).unwrap();
    let document = whn
        .operator
        .sign_document_for(
            authentication_document(whn.operator.did(), &challenge),
            AUTHENTICATION,
        )
        .await
        .unwrap();
    for expected in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
        let (status, _) = whn
            .public(
                "POST",
                "/v1/auth/session",
                Some(json!({ "authentication": document })),
            )
            .await;
        assert_eq!(status, expected);
    }
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
    let entry = whn
        .admin(
            "POST",
            "/v1/admin/entries",
            Some(json!({ "did": vtc.did(), "kind": "community" })),
        )
        .await;
    let listing_index = status_index(&entry["listing"]["credential"]);
    let entry = whn
        .admin(
            "POST",
            &format!("/v1/admin/entries/{}/remove", vtc.did()),
            Some(json!({ "reason": "criteria" })),
        )
        .await;
    assert_eq!(entry["state"], "removed");
    assert!(whn.bit("revocation", listing_index).await);
    let (status, _) = whn.public("GET", &entry_path(vtc.did(), ""), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// List `party` and have it acknowledge, signing in as itself first when the network is
/// restricted (a listed party fetches its own offer only when signed in).
async fn join(net: &TestNetwork, party: &Identity, kind: &str, label: &str, extra: Value) {
    let mut body = json!({ "did": party.did(), "kind": kind, "label": label });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    net.admin("POST", "/v1/admin/entries", Some(body)).await;
    let offer = if net.config.directory.visibility == Visibility::Public {
        net.public("GET", &entry_path(party.did(), "/offer"), None)
            .await
            .1
    } else {
        let token = net.sign_in(party).await.expect("a listed party signs in");
        let (status, offer) = net
            .as_session(&token, "GET", &entry_path(party.did(), "/offer"))
            .await;
        assert_eq!(status, StatusCode::OK, "{offer}");
        offer
    };
    let ack = member::acknowledge(&offer, party, Utc::now() - Duration::seconds(5), None)
        .await
        .unwrap();
    let (status, entry) = net
        .public(
            "POST",
            &entry_path(party.did(), "/acknowledge"),
            Some(json!({ "acknowledgement": ack })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{entry}");
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
    whn.admin(
        "POST",
        "/v1/admin/entries",
        Some(json!({ "did": nz.did(), "kind": "network", "label": "Health-NZ", "tags": ["new zealand"] })),
    )
    .await;

    let (status, rows) = whn.public("GET", "/v1/directory", None).await;
    assert_eq!(status, StatusCode::OK);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["acknowledged"], true, "members first");
    assert_eq!(rows[1]["state"], "listed");

    let (_, hits) = whn
        .public("GET", "/v1/directory?q=emergency%20NGO", None)
        .await;
    assert_eq!(hits.as_array().unwrap().len(), 1);
    let (_, hits) = whn
        .public("GET", "/v1/directory?kind=network&members_only=true", None)
        .await;
    assert!(
        hits.as_array().unwrap().is_empty(),
        "Health-NZ has not acknowledged"
    );

    let (_, summary) = whn.public("GET", "/v1/directory/summary", None).await;
    assert_eq!(summary["acknowledged"], 1);
    assert_eq!(summary["unacknowledged"], 1);

    // The admin edits a profile; search sees it, nothing is re-issued.
    let entry = whn
        .admin(
            "POST",
            &format!("/v1/admin/entries/{}/profile", nz.did()),
            Some(json!({ "description": "Te Whatu Ora", "tags": ["aotearoa"] })),
        )
        .await;
    assert_eq!(entry["state"], "listed");
    let (_, hits) = whn.public("GET", "/v1/directory?q=aotearoa", None).await;
    assert_eq!(hits.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn members_only_directory() {
    let whn = network_with("WHN", Visibility::Members).await;
    let msf = Identity::generate();
    join(&whn, &msf, "community", "MSF", json!({})).await;
    let pending = Identity::generate();
    whn.admin(
        "POST",
        "/v1/admin/entries",
        Some(json!({ "did": pending.did(), "kind": "community", "label": "Pending" })),
    )
    .await;

    // Anonymous: no set, but the profile, the page, status lists and counts are public.
    for path in ["/v1/directory", "/v1/index", "/v1/graph"] {
        assert_eq!(
            whn.public("GET", path, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        whn.public("GET", &entry_path(msf.did(), ""), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Probing for a listing reveals nothing.
    assert_eq!(
        whn.public("GET", &entry_path(pending.did(), "/offer"), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, info) = whn.public("GET", "/.well-known/vtn", None).await;
    assert_eq!(info["directory"]["visibility"], "members");
    assert_eq!(
        whn.public("GET", "/v1/directory/summary", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        whn.public("GET", "/v1/status/revocation", None).await.0,
        StatusCode::OK
    );

    // A member community, signed in as itself.
    let token = whn.sign_in(&msf).await.unwrap();
    let (status, rows) = whn.as_session(&token, "GET", "/v1/directory").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows.as_array().unwrap().len(), 2);
    let (_, me) = whn.as_session(&token, "GET", "/v1/auth/session").await;
    assert_eq!(me["role"]["role"], "memberEntity");

    // A person holding MSF's membership credential.
    let person = Identity::generate();
    let vmc = community_vmc(&msf, &person).await;
    let token = whn.sign_in_with(&person, Some(vmc.clone())).await.unwrap();
    let (status, _) = whn.as_session(&token, "GET", "/v1/directory").await;
    assert_eq!(status, StatusCode::OK);
    let (_, me) = whn.as_session(&token, "GET", "/v1/auth/session").await;
    assert_eq!(me["role"]["community"], msf.did());

    // Someone else presenting that person's credential.
    let thief = Identity::generate();
    assert_eq!(
        whn.sign_in_with(&thief, Some(vmc)).await,
        Err(StatusCode::UNAUTHORIZED)
    );
    // A credential from a community that is listed but has not acknowledged.
    let pending_member = Identity::generate();
    let vmc = community_vmc(&pending, &pending_member).await;
    assert_eq!(
        whn.sign_in_with(&pending_member, Some(vmc)).await,
        Err(StatusCode::UNAUTHORIZED)
    );

    // A listed, unacknowledged party gets its own offer and entry, not the directory.
    let token = whn.sign_in(&pending).await.unwrap();
    assert_eq!(
        whn.as_session(&token, "GET", "/v1/directory").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        whn.as_session(&token, "GET", &entry_path(pending.did(), "/offer"))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        whn.as_session(&token, "GET", &entry_path(msf.did(), "/offer"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // ...and no admin route.
    assert_eq!(
        whn.as_session(&token, "GET", "/v1/admin/entries").await.0,
        StatusCode::FORBIDDEN
    );

    // A stranger cannot sign in at all.
    assert_eq!(
        whn.sign_in(&Identity::generate()).await,
        Err(StatusCode::UNAUTHORIZED)
    );
}

#[tokio::test]
async fn admins_only_directory_and_hidden_counts() {
    let dir = tempfile::tempdir().unwrap();
    let operator = Identity::generate();
    let mut config = test_config(dir.path(), "WHN", vec![operator.did().to_string()]);
    config.directory.visibility = Visibility::Admins;
    config.directory.show_counts = false;
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    let app = router(state.clone());
    let mut whn = TestNetwork {
        _dir: dir,
        config,
        state,
        app,
        operator: operator.clone(),
        token: String::new(),
    };
    whn.token = whn.sign_in(&operator).await.unwrap();
    let msf = Identity::generate();
    join(&whn, &msf, "community", "MSF", json!({})).await;

    let token = whn.sign_in(&msf).await.unwrap();
    assert_eq!(
        whn.as_session(&token, "GET", "/v1/directory").await.0,
        StatusCode::FORBIDDEN,
        "members do not see an admins-only directory"
    );
    assert_eq!(
        whn.public("GET", "/v1/directory/summary", None).await.0,
        StatusCode::UNAUTHORIZED,
        "counts hidden"
    );
    // A member still reads its own entry.
    assert_eq!(
        whn.as_session(&token, "GET", &entry_path(msf.did(), ""))
            .await
            .0,
        StatusCode::OK
    );
    let (status, rows) = whn.call("GET", "/v1/directory", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows.as_array().unwrap().len(), 1);
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
    assert!(html.contains("/v1/directory"));
}
