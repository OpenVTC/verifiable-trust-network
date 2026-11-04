//! Live networks over real HTTP: nesting, cascading broadcast, and credential status.
//!
//! ```text
//!   WHN (roles: admins, required)
//!   ├── MSF          community, inbox "msf"
//!   └── Health-AU    network: joined WHN itself, its network group serves WHN's admins
//!       ├── St Vincent's   community, inbox "stv"
//!       └── WHN            (a cycle: WHN also joined Health-AU)
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use vti_vtn::credentials::member;
use vti_vtn::groups;
use vti_vtn::identity::Identity;
use vti_vtn::model::{Framework, Visibility};
use vti_vtn::relay::{self, Envelope};
use vti_vtn::status::{Bitstring, Purpose, credential_status, status_list_credential};
use vti_vtn::verify::LocalDidKeyResolver;
use vti_vtn::{VtnClient, encode_did};
use vtn_service::config::{Config, DirectoryConfig, MembershipConfig, NetworkConfig};
use vtn_service::identity::VtaKeyResolver;

mod support;
use support::tls;

/// A client for a test server, trusting the test authority.
fn https(url: &str) -> VtnClient {
    VtnClient::with_http(tls::client(), url)
}

struct Live {
    _dir: tempfile::TempDir,
    url: String,
    did: String,
    admin: VtnClient,
}

async fn serve(app: Router) -> String {
    tls::serve(app).await
}

async fn live(name: &str, required_admins: bool, visibility: Visibility) -> Live {
    live_with(name, required_admins, visibility, vec![]).await
}

async fn live_with(
    name: &str,
    required_admins: bool,
    visibility: Visibility,
    rooms: Vec<vtn_service::rooms::RoomDef>,
) -> Live {
    let (listener, url) = tls::bind().await;
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("test-ca.pem");
    std::fs::write(&ca, &tls::ca().ca_pem).unwrap();
    let operator = Identity::generate();
    let config = Config {
        listen: url.clone(),
        base_url: url.clone(),
        data_dir: dir.path().to_path_buf(),
        admins: vec![operator.did().to_string()],
        resolver_url: None,
        extra_root_certificates: vec![ca],
        status_cache_seconds: 0,
        network: NetworkConfig {
            name: name.into(),
            description: None,
            owner: format!("{name} owner"),
            framework: Framework {
                iri: format!("{url}/gf"),
                version: "1.0".into(),
            },
        },
        membership: MembershipConfig::default(),
        directory: DirectoryConfig {
            visibility,
            ..Default::default()
        },
        roles: vec![vti_vtn::groups::RoleDef {
            name: "admins".into(),
            description: Some("Each member's administrators".into()),
            required: required_admins,
        }],
        relay: Default::default(),
        rooms,
        identity: None,
        secrets: None,
    };
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    let did = state.network.did().to_string();
    let app = vtn_service::routes::router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut admin = https(&url);
    admin.sign_in(&operator, &did, None).await.unwrap();
    Live {
        _dir: dir,
        url,
        did,
        admin,
    }
}

/// Community group inboxes, keyed by name; each delivery is recorded.
#[derive(Clone, Default)]
struct Inboxes(Arc<Mutex<HashMap<String, Vec<Value>>>>);

impl Inboxes {
    async fn start(&self) -> String {
        async fn deliver(
            State(inboxes): State<Inboxes>,
            Path(name): Path<String>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            inboxes
                .0
                .lock()
                .await
                .entry(name)
                .or_default()
                .push(body["envelope"].clone());
            Json(json!({ "accepted": true }))
        }
        serve(
            Router::new()
                .route("/inbox/{name}", post(deliver))
                .with_state(self.clone()),
        )
        .await
    }

    async fn of(&self, name: &str) -> Vec<Value> {
        self.0.lock().await.get(name).cloned().unwrap_or_default()
    }
}

/// A community joins `net`: listed by its admin, registers its admins group, acknowledges.
async fn community_joins(net: &Live, community: &Identity, label: &str, inbox: &str) {
    net.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": community.did(), "kind": "community", "label": label }),
        )
        .await
        .unwrap();
    let client = https(&net.url);
    let at = Utc::now() - Duration::seconds(5);

    // Acknowledging before registering the required role is refused.
    let offer = client
        .get(&format!(
            "/v1/entries/{}/offer",
            encode_did(community.did())
        ))
        .await
        .unwrap();
    let ack = member::acknowledge(&offer, community, at, None)
        .await
        .unwrap();
    let early = client
        .post(
            &format!("/v1/entries/{}/acknowledge", encode_did(community.did())),
            &json!({ "acknowledgement": ack }),
        )
        .await;
    assert_eq!(
        early.unwrap_err().status(),
        Some(422),
        "required role first"
    );

    let group = format!("{}:groups:admins", community.did());
    let registration = groups::register(community, &net.did, "admins", &group, inbox)
        .await
        .unwrap();
    client
        .post(
            &format!("/v1/entries/{}/groups", encode_did(community.did())),
            &json!({ "registration": registration }),
        )
        .await
        .unwrap();
    let entry = client
        .post(
            &format!("/v1/entries/{}/acknowledge", encode_did(community.did())),
            &json!({ "acknowledgement": ack }),
        )
        .await
        .unwrap();
    assert_eq!(entry["state"], "acknowledged");
}

/// `child` is listed by `parent` and joins it, serving `admins` with its own network group.
async fn network_joins(parent: &Live, child: &Live, label: &str) -> Value {
    parent
        .admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": child.did, "kind": "network", "label": label }),
        )
        .await
        .unwrap();
    child
        .admin
        .post("/v1/admin/memberships", &json!({ "url": parent.url }))
        .await
        .unwrap()
}

fn total_reached(record: &Value) -> u64 {
    record["reached"].as_u64().unwrap()
}

#[tokio::test]
async fn broadcast_cascades_through_nested_networks() {
    let inboxes = Inboxes::default();
    let inbox_url = inboxes.start().await;
    let whn = live("WHN", true, Visibility::Public).await;
    let au = live("Health-AU", true, Visibility::Members).await;

    let msf = Identity::generate();
    community_joins(&whn, &msf, "MSF", &format!("{inbox_url}/inbox/msf")).await;

    // Health-AU joins WHN by itself: its network group is registered for WHN's admins.
    let membership = network_joins(&whn, &au, "Health-AU").await;
    assert_eq!(membership["state"], "acknowledged");
    assert_eq!(
        membership["groups"][0]["group"],
        format!("{}#role-admins", au.did)
    );
    let entry = whn
        .admin
        .get(&format!("/v1/admin/entries/{}", encode_did(&au.did)))
        .await
        .unwrap();
    assert_eq!(entry["state"], "acknowledged");

    // Health-AU is members-only; St Vincent's is listed there and joins.
    // (A restricted network makes a listed party sign in for its offer.)
    let stv = Identity::generate();
    au.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": stv.did(), "kind": "community", "label": "St Vincent's" }),
        )
        .await
        .unwrap();
    let mut stv_client = https(&au.url);
    stv_client.sign_in(&stv, &au.did, None).await.unwrap();
    let at = Utc::now() - Duration::seconds(5);
    let registration = groups::register(
        &stv,
        &au.did,
        "admins",
        &format!("{}:groups:admins", stv.did()),
        &format!("{inbox_url}/inbox/stv"),
    )
    .await
    .unwrap();
    stv_client
        .post(
            &format!("/v1/entries/{}/groups", encode_did(stv.did())),
            &json!({ "registration": registration }),
        )
        .await
        .unwrap();
    let offer = stv_client
        .get(&format!("/v1/entries/{}/offer", encode_did(stv.did())))
        .await
        .unwrap();
    let ack = member::acknowledge(&offer, &stv, at, None).await.unwrap();
    stv_client
        .post(
            &format!("/v1/entries/{}/acknowledge", encode_did(stv.did())),
            &json!({ "acknowledgement": ack }),
        )
        .await
        .unwrap();

    // A cycle: WHN also joins Health-AU.
    network_joins(&au, &whn, "WHN").await;

    // --- WHN broadcasts to all admins.
    let record = whn
        .admin
        .post(
            "/v1/admin/broadcasts",
            &json!({ "role": "admins", "subject": "Drill", "body": "Exercise at 09:00 UTC" }),
        )
        .await
        .unwrap();
    // MSF directly, St Vincent's through Health-AU; WHN's copy back through the cycle is a
    // duplicate and reaches nobody.
    assert_eq!(total_reached(&record), 2, "{record:#}");
    let au_receipt = record["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["member"] == au.did)
        .unwrap()
        .clone();
    let relayed = au_receipt["relayed"].as_array().unwrap();
    assert!(
        relayed
            .iter()
            .any(|r| r["member"] == stv.did() && r["status"] == "delivered")
    );
    assert!(
        relayed
            .iter()
            .any(|r| r["member"] == whn.did && r["status"] == "duplicate")
    );

    // St Vincent's got one copy, with the full provenance chain WHN → Health-AU → StV.
    let delivered = inboxes.of("stv").await;
    assert_eq!(delivered.len(), 1);
    let envelope: Envelope = serde_json::from_value(delivered[0].clone()).unwrap();
    let v = relay::verify(&envelope, &LocalDidKeyResolver, Utc::now(), 8)
        .await
        .unwrap();
    assert_eq!(v.origin, whn.did);
    assert_eq!(v.from, au.did);
    assert_eq!(v.hops, 2);
    assert_eq!(envelope.message["body"], "Exercise at 09:00 UTC");
    assert_eq!(inboxes.of("msf").await.len(), 1);

    // Health-AU recorded the relay, but holds nothing of WHN's roster.
    let au_log = au.admin.get("/v1/admin/broadcasts").await.unwrap();
    assert_eq!(au_log[0]["direction"], "received");
    assert_eq!(au_log[0]["from"], whn.did);

    // --- A delivery from a network Health-AU is not a member of is refused.
    let rogue = Identity::generate();
    let message = relay::new_message(
        &rogue,
        &relay::Outgoing {
            role: "admins".into(),
            class: "notice".into(),
            subject: "Phish".into(),
            body: "Click here".into(),
            reply_to: None,
        },
        Duration::hours(1),
        Utc::now(),
    )
    .await
    .unwrap();
    let id = message["id"].as_str().unwrap().to_string();
    let hop = relay::new_hop(&rogue, &id, &format!("{}#role-admins", au.did), "admins", 0)
        .await
        .unwrap();
    let refused = https(&au.url)
        .post(
            "/v1/relay/admins",
            &json!({ "envelope": { "message": message, "hops": [hop] } }),
        )
        .await;
    assert_eq!(refused.unwrap_err().status(), Some(422));

    // --- A suspended member's groups are skipped.
    whn.admin
        .post(
            &format!("/v1/admin/entries/{}/suspend", encode_did(msf.did())),
            &json!({}),
        )
        .await
        .unwrap();
    let record = whn
        .admin
        .post(
            "/v1/admin/broadcasts",
            &json!({ "role": "admins", "subject": "Second", "body": "…" }),
        )
        .await
        .unwrap();
    assert!(
        record["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["member"] != msf.did())
    );
    assert_eq!(inboxes.of("msf").await.len(), 1);
    assert_eq!(inboxes.of("stv").await.len(), 2);

    // --- Health-AU leaves WHN: departed there, its group dropped, StV no longer reached.
    let left = au
        .admin
        .post(
            &format!("/v1/admin/memberships/{}/leave", encode_did(&whn.did)),
            &json!({}),
        )
        .await
        .unwrap();
    assert_eq!(left["state"], "departed");
    let entry = whn
        .admin
        .get(&format!("/v1/admin/entries/{}", encode_did(&au.did)))
        .await
        .unwrap();
    assert_eq!(entry["state"], "departed");
    let groups = whn.admin.get("/v1/admin/groups?role=admins").await.unwrap();
    assert!(
        groups
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["member"] != au.did)
    );
    whn.admin
        .post(
            "/v1/admin/broadcasts",
            &json!({ "role": "admins", "subject": "Third", "body": "…" }),
        )
        .await
        .unwrap();
    assert_eq!(inboxes.of("stv").await.len(), 2);
}

#[tokio::test]
async fn a_network_can_repudiate_a_parent_listing() {
    let whn = live("WHN", false, Visibility::Public).await;
    let nz = live("Health-NZ", false, Visibility::Public).await;
    whn.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": nz.did, "kind": "network", "label": "Health-NZ" }),
        )
        .await
        .unwrap();
    let m = nz
        .admin
        .post(
            "/v1/admin/memberships/repudiate",
            &json!({ "url": whn.url }),
        )
        .await
        .unwrap();
    assert_eq!(m["state"], "repudiated");
    let (_, entry) = (
        (),
        https(&whn.url)
            .get(&format!("/v1/entries/{}", encode_did(&nz.did)))
            .await
            .unwrap(),
    );
    assert_eq!(entry["state"], "repudiated");
    assert!(
        entry["repudiation"].is_object(),
        "published with the repudiation"
    );

    // A network that was never listed cannot join.
    let stranger = live("Stranger", false, Visibility::Public).await;
    let err = stranger
        .admin
        .post("/v1/admin/memberships", &json!({ "url": whn.url }))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(422), "{err}");
}

/// A community serving its own status list, to check a person's credential against.
async fn status_server(community: &Identity, revoked: &[u32]) -> String {
    let (listener, url) = tls::bind().await;
    let mut bits = Bitstring::default();
    for i in revoked {
        bits.set(*i, true).unwrap();
    }
    let mut lists = HashMap::new();
    for purpose in [Purpose::Revocation, Purpose::Suspension] {
        let b = if purpose == Purpose::Revocation {
            bits.clone()
        } else {
            Bitstring::default()
        };
        let list = status_list_credential(community.did(), &url, purpose, &b, Utc::now()).unwrap();
        lists.insert(
            purpose.as_str().to_string(),
            community.sign_document(list).await.unwrap(),
        );
    }
    let lists = Arc::new(lists);
    let app = Router::new().route(
        "/v1/status/{purpose}",
        get(move |Path(p): Path<String>| {
            let lists = lists.clone();
            async move { Json(lists.get(&p).cloned().unwrap_or(Value::Null)) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

#[tokio::test]
async fn member_credentials_are_checked_against_the_communitys_status_list() {
    let whn = live("WHN", false, Visibility::Members).await;
    let msf = Identity::generate();
    whn.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": msf.did(), "kind": "community", "label": "MSF" }),
        )
        .await
        .unwrap();
    let mut client = https(&whn.url);
    client.sign_in(&msf, &whn.did, None).await.unwrap();
    let offer = client
        .get(&format!("/v1/entries/{}/offer", encode_did(msf.did())))
        .await
        .unwrap();
    let ack = member::acknowledge(&offer, &msf, Utc::now() - Duration::seconds(5), None)
        .await
        .unwrap();
    client
        .post(
            &format!("/v1/entries/{}/acknowledge", encode_did(msf.did())),
            &json!({ "acknowledgement": ack }),
        )
        .await
        .unwrap();

    let status_url = status_server(&msf, &[1]).await;
    let vmc = |index: Option<u32>, base: String| {
        let msf = msf.clone();
        async move {
            let person = Identity::generate();
            let mut vmc = dtg_credentials::DTGCredential::new_vmc(
                msf.did().to_string(),
                person.did().to_string(),
                Utc::now() - Duration::seconds(5),
                Some(Utc::now() + Duration::days(1)),
                false,
            )
            .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
            if let Some(i) = index {
                vmc = vmc.with_credential_status(credential_status(&base, i));
            }
            msf.sign_credential(&mut vmc).await.unwrap();
            (person, serde_json::to_value(vmc).unwrap())
        }
    };
    let sign_in = |person: Identity, vmc: Value| {
        let url = whn.url.clone();
        let did = whn.did.clone();
        async move {
            https(&url)
                .sign_in(&person, &did, Some(vmc))
                .await
                .map_err(|e| e.status())
        }
    };

    let (person, good) = vmc(Some(0), status_url.clone()).await;
    assert!(sign_in(person, good).await.is_ok(), "status clear");
    let (person, revoked) = vmc(Some(1), status_url.clone()).await;
    assert_eq!(
        sign_in(person, revoked).await.unwrap_err(),
        Some(401),
        "revoked"
    );
    let (person, unreachable) = vmc(Some(0), "http://127.0.0.1:9".into()).await;
    assert_eq!(
        sign_in(person, unreachable).await.unwrap_err(),
        Some(401),
        "an unreachable status list is indeterminate, not valid"
    );
    let (person, no_status) = vmc(None, String::new()).await;
    assert!(
        sign_in(person, no_status).await.is_ok(),
        "validity window only"
    );
}

/// `parent` lists `child` with its URL, and `child` joins.
async fn network_joins_at(parent: &Live, child: &Live, label: &str) {
    parent
        .admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": child.did, "kind": "network", "label": label, "url": child.url }),
        )
        .await
        .unwrap();
    child
        .admin
        .post("/v1/admin/memberships", &json!({ "url": parent.url }))
        .await
        .unwrap();
}

#[tokio::test]
async fn federated_search_follows_member_networks_with_paths() {
    let whn = live("WHN", false, Visibility::Public).await;
    let au = live("Health-AU", false, Visibility::Public).await;
    let nsw = live("Health-NSW", false, Visibility::Public).await;
    let private = live("Private-Net", false, Visibility::Members).await;
    network_joins_at(&whn, &au, "Health-AU").await;
    network_joins_at(&au, &nsw, "Health-NSW").await;
    network_joins_at(&whn, &private, "Private-Net").await;
    nsw.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": Identity::generate().did(), "kind": "community",
                     "label": "St Vincent's Hospital", "tags": ["sydney"] }),
        )
        .await
        .unwrap();
    // Listed by WHN but never acknowledged: not followed.
    let pending = live("Pending-Net", false, Visibility::Public).await;
    whn.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": pending.did, "kind": "network", "url": pending.url }),
        )
        .await
        .unwrap();
    pending
        .admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": Identity::generate().did(), "kind": "community", "label": "Vincent Hidden" }),
        )
        .await
        .unwrap();

    let found = https(&whn.url)
        .get("/v1/directory/federated?q=vincent")
        .await
        .unwrap();
    let results = found["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "{found:#}");
    let stv = &results[0];
    assert_eq!(stv["label"], "St Vincent's Hospital");
    assert_eq!(stv["listedBy"], nsw.did);
    assert_eq!(stv["acknowledged"], false, "NSW only lists it");
    let path: Vec<&str> = stv["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["network"].as_str().unwrap())
        .collect();
    assert_eq!(path, [au.did.as_str(), nsw.did.as_str()]);

    // The members-only network's index cannot be read: indeterminate, reported.
    let unreachable = found["unreachable"].as_array().unwrap();
    assert!(
        unreachable.iter().any(|u| u["network"] == private.did),
        "{found:#}"
    );

    // The graph view expands a member network from its verified index.
    let au_graph = https(&whn.url)
        .get(&format!("/v1/graph/member/{}", encode_did(&au.did)))
        .await
        .unwrap();
    assert_eq!(au_graph["nodes"][0]["id"], au.did);
    assert!(
        au_graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == nsw.did)
    );
    // Not for a network that never acknowledged.
    let err = https(&whn.url)
        .get(&format!("/v1/graph/member/{}", encode_did(&pending.did)))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(404));

    // Plain (non-federated) search sees only WHN's own entries.
    let own = https(&whn.url)
        .get("/v1/directory?q=vincent")
        .await
        .unwrap();
    assert!(own.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn browser_sign_in_is_handed_to_a_wallet_and_back() {
    let whn = live("WHN", false, Visibility::Members).await;
    let other = live("Other", false, Visibility::Public).await;
    let msf = Identity::generate();
    community_joins_open(&whn, &msf).await;

    // The page starts a login; nobody has signed yet.
    let page = https(&whn.url);
    let start = page.post("/v1/auth/login", &json!({})).await.unwrap();
    let (login, secret) = (
        start["login"].as_str().unwrap(),
        start["pollSecret"].as_str().unwrap(),
    );
    let poll = |secret: &str| format!("/v1/auth/login/{login}?secret={secret}");
    assert_eq!(page.get(&poll(secret)).await.unwrap()["status"], "pending");
    assert_eq!(
        page.get(&poll("wrong")).await.unwrap_err().status(),
        Some(401)
    );

    // A link whose endpoint answers as another network is refused before anything is signed.
    let mismatched = vti_vtn::SignInLink {
        network: whn.did.clone(),
        endpoint: other.url.clone(),
        challenge: start["challenge"].as_str().unwrap().into(),
    };
    assert!(mismatched.complete(&msf, None).await.is_err());

    // The wallet (here, the member community itself) signs the link.
    let link = vti_vtn::SignInLink::parse(
        &vti_vtn::SignInLink {
            network: start["audience"].as_str().unwrap().into(),
            endpoint: whn.url.clone(),
            challenge: start["challenge"].as_str().unwrap().into(),
        }
        .to_uri(),
    )
    .unwrap();
    // What `SignInLink::complete` does, over a client that trusts the test authority.
    let wallet = https(&link.endpoint);
    assert_eq!(wallet.network_did().await.unwrap(), link.network);
    let authentication = msf
        .sign_document_for(
            json!({
                "type": "VtnAdminAuthentication",
                "did": msf.did(),
                "challenge": link.challenge,
                "audience": link.network,
            }),
            vti_vtn::verify::AUTHENTICATION,
        )
        .await
        .unwrap();
    let grant = wallet
        .post(
            "/v1/auth/session",
            &json!({ "authentication": authentication }),
        )
        .await
        .unwrap();
    assert_eq!(grant["role"], "memberEntity");

    // The page collects the session once, and it opens the members-only directory.
    let done = page.get(&poll(secret)).await.unwrap();
    assert_eq!(done["status"], "complete");
    assert_eq!(
        page.get(&poll(secret)).await.unwrap_err().status(),
        Some(401),
        "handed over once"
    );
    let token = done["session"]["token"].as_str().unwrap();
    let res = tls::client()
        .get(format!("{}/v1/directory", whn.url))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // The challenge was single use.
    assert!(link.complete(&msf, None).await.is_err());
}

/// A community joins a network with no required roles.
async fn community_joins_open(net: &Live, community: &Identity) {
    net.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": community.did(), "kind": "community", "label": "MSF" }),
        )
        .await
        .unwrap();
    let mut client = https(&net.url);
    client.sign_in(community, &net.did, None).await.unwrap();
    let offer = client
        .get(&format!(
            "/v1/entries/{}/offer",
            encode_did(community.did())
        ))
        .await
        .unwrap();
    let ack = member::acknowledge(&offer, community, Utc::now() - Duration::seconds(5), None)
        .await
        .unwrap();
    client
        .post(
            &format!("/v1/entries/{}/acknowledge", encode_did(community.did())),
            &json!({ "acknowledgement": ack }),
        )
        .await
        .unwrap();
}

/// An inbox that answers 500 `fails` times, then accepts; or always refuses with 403.
async fn flaky_inbox(fails: u32, refuse: bool) -> (String, Arc<Mutex<Vec<Value>>>) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let left = Arc::new(Mutex::new(fails));
    let (g, l) = (got.clone(), left.clone());
    let app = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let (g, l) = (g.clone(), l.clone());
            async move {
                if refuse {
                    return (
                        axum::http::StatusCode::FORBIDDEN,
                        Json(json!({ "message": "no" })),
                    );
                }
                let mut left = l.lock().await;
                if *left > 0 {
                    *left -= 1;
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({})),
                    );
                }
                g.lock().await.push(body);
                (
                    axum::http::StatusCode::OK,
                    Json(json!({ "accepted": true })),
                )
            }
        }),
    );
    (format!("{}/", serve(app).await), got)
}

/// A community joins `net` and registers a group (role not required) at `endpoint`.
async fn join_with_group(net: &Live, community: &Identity, endpoint: &str) {
    community_joins_open(net, community).await;
    let registration = groups::register(
        community,
        &net.did,
        "admins",
        &format!("{}:groups:admins", community.did()),
        endpoint,
    )
    .await
    .unwrap();
    https(&net.url)
        .post(
            &format!("/v1/entries/{}/groups", encode_did(community.did())),
            &json!({ "registration": registration }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_deliveries_are_queued_and_retried() {
    let whn = live("WHN", false, Visibility::Public).await;
    let (flaky_url, flaky_got) = flaky_inbox(1, false).await;
    let (refusing_url, _) = flaky_inbox(0, true).await;
    let flaky = Identity::generate();
    let refusing = Identity::generate();
    let dead = Identity::generate();
    join_with_group(&whn, &flaky, &flaky_url).await;
    join_with_group(&whn, &refusing, &refusing_url).await;
    join_with_group(&whn, &dead, "https://127.0.0.1:9/").await;

    let record = whn
        .admin
        .post(
            "/v1/admin/broadcasts",
            &json!({ "role": "admins", "subject": "Retry", "body": "…" }),
        )
        .await
        .unwrap();
    let status_of = |record: &Value, who: &Identity| {
        record["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["member"] == who.did())
            .unwrap()["status"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(status_of(&record, &flaky), "queued");
    assert_eq!(status_of(&record, &dead), "queued");
    assert_eq!(
        status_of(&record, &refusing),
        "refused",
        "a refusal is final"
    );
    assert_eq!(record["reached"], 0);
    let outbox = whn.admin.get("/v1/admin/outbox").await.unwrap();
    assert_eq!(outbox.as_array().unwrap().len(), 2);

    let retried = whn
        .admin
        .post("/v1/admin/outbox/retry", &json!({}))
        .await
        .unwrap();
    assert_eq!(retried["attempted"], 2);
    let id = record["id"].as_str().unwrap();
    let record = whn
        .admin
        .get(&format!(
            "/v1/admin/broadcasts/{}",
            vti_vtn::encode_query(id)
        ))
        .await
        .unwrap();
    assert_eq!(status_of(&record, &flaky), "delivered");
    assert_eq!(record["reached"], 1);
    assert_eq!(flaky_got.lock().await.len(), 1);
    // The dead endpoint stays queued, its attempts counted.
    let outbox = whn.admin.get("/v1/admin/outbox").await.unwrap();
    let left = outbox.as_array().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["member"], dead.did());
    assert_eq!(left[0]["attempts"], 2);
    assert_eq!(status_of(&record, &dead), "queued");
}

/// A community joins `net` registering `group` (a group DID it controls) for `admins`.
/// Returns the chain link for that group: the registration and the network's acceptance.
async fn join_registering(net: &Live, community: &Identity, group: &Identity) -> ChainLinkJson {
    community_joins_open(net, community).await;
    let registration = groups::register(
        community,
        &net.did,
        "admins",
        group.did(),
        "https://127.0.0.1:9/",
    )
    .await
    .unwrap();
    let registered = https(&net.url)
        .post(
            &format!("/v1/entries/{}/groups", encode_did(community.did())),
            &json!({ "registration": registration }),
        )
        .await
        .unwrap();
    json!({ "registration": registration, "acceptance": registered["acceptance"]["credential"] })
}

type ChainLinkJson = Value;

/// A group's membership credential for `person`.
async fn group_vmc(group: &Identity, person: &Identity) -> Value {
    community_vmc(group, person).await
}

async fn community_vmc(issuer: &Identity, person: &Identity) -> Value {
    let mut vmc = dtg_credentials::DTGCredential::new_vmc(
        issuer.did().to_string(),
        person.did().to_string(),
        Utc::now() - Duration::seconds(5),
        Some(Utc::now() + Duration::days(1)),
        false,
    )
    .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    issuer.sign_credential(&mut vmc).await.unwrap();
    serde_json::to_value(vmc).unwrap()
}

/// `person` asks `net` for a pass to `room`.
async fn ask_pass(
    net: &Live,
    person: &Identity,
    membership: Value,
    chain: Vec<Value>,
) -> Result<Value, Option<u16>> {
    let client = https(&net.url);
    let challenge = client
        .post("/v1/auth/challenge", &json!({ "did": person.did() }))
        .await
        .unwrap();
    let authentication = person
        .sign_document_for(
            json!({
                "type": "VtnAdminAuthentication",
                "did": person.did(),
                "challenge": challenge["challenge"],
                "audience": net.did,
            }),
            vti_vtn::verify::AUTHENTICATION,
        )
        .await
        .unwrap();
    client
        .post(
            "/v1/rooms/pandemic/pass",
            &json!({ "authentication": authentication, "membership": membership, "chain": chain }),
        )
        .await
        .map_err(|e| e.status())
}

#[tokio::test]
async fn room_passes_follow_group_evidence_through_member_networks() {
    let room = vtn_service::rooms::RoomDef {
        id: "pandemic".into(),
        name: "Pandemic Response".into(),
        role: "admins".into(),
        description: None,
        url: None,
        pass_minutes: 30,
    };
    let whn = live_with("WHN", false, Visibility::Public, vec![room]).await;
    let au = live("Health-AU", false, Visibility::Public).await;
    // Health-AU serves WHN's admins with its network group.
    whn.admin
        .post(
            "/v1/admin/entries",
            &json!({ "did": au.did, "kind": "network" }),
        )
        .await
        .unwrap();
    au.admin
        .post(
            "/v1/admin/memberships",
            &json!({ "url": whn.url, "roles": [{ "parentRole": "admins", "localRole": "admins" }] }),
        )
        .await
        .unwrap();

    // St Vincent's (in Health-AU) registers its admins group; a person is in that group.
    let stv = Identity::generate();
    let stv_admins = Identity::generate();
    let link = join_registering(&au, &stv, &stv_admins).await;
    let person = Identity::generate();
    let vmc = group_vmc(&stv_admins, &person).await;

    let rooms = https(&whn.url).get("/v1/rooms").await.unwrap();
    assert_eq!(rooms[0]["id"], "pandemic");

    // Through Health-AU: one link.
    let pass = ask_pass(&whn, &person, vmc.clone(), vec![link.clone()])
        .await
        .unwrap();
    assert_eq!(pass["via"], json!([au.did]));
    let vac = &pass["pass"];
    assert_eq!(vac["issuer"], whn.did);
    assert_eq!(vac["credentialSubject"]["id"], person.did());
    assert_eq!(
        vac["credentialSubject"]["authority"]["actions"],
        json!(["room:enter"])
    );
    assert_eq!(
        vac["credentialSubject"]["authority"]["scope"],
        format!("{}#room-pandemic", whn.did)
    );
    vti_vtn::verify::verify_signed_by(vac, &whn.did, &LocalDidKeyResolver, Utc::now())
        .await
        .unwrap();

    // A direct member's group needs no chain.
    let msf = Identity::generate();
    let msf_admins = Identity::generate();
    join_registering(&whn, &msf, &msf_admins).await;
    let doctor = Identity::generate();
    assert!(
        ask_pass(&whn, &doctor, group_vmc(&msf_admins, &doctor).await, vec![])
            .await
            .is_ok()
    );

    // Missing the link: refused.
    assert_eq!(
        ask_pass(&whn, &person, vmc.clone(), vec![])
            .await
            .unwrap_err(),
        Some(422)
    );
    // A group nobody registered: refused.
    let stranger_group = Identity::generate();
    let stranger = Identity::generate();
    assert_eq!(
        ask_pass(
            &whn,
            &stranger,
            group_vmc(&stranger_group, &stranger).await,
            vec![link.clone()]
        )
        .await
        .unwrap_err(),
        Some(422)
    );
    // Someone else presenting the person's credential: refused.
    let thief = Identity::generate();
    assert_eq!(
        ask_pass(&whn, &thief, vmc.clone(), vec![link.clone()])
            .await
            .unwrap_err(),
        Some(422)
    );

    // St Vincent's leaves Health-AU: its acceptance is revoked, and the chain no longer holds.
    let departure = member::repudiate(
        &https(&au.url)
            .get(&format!("/v1/entries/{}", encode_did(stv.did())))
            .await
            .unwrap()["grant"],
        &stv,
        Utc::now() - Duration::seconds(5),
    )
    .await
    .unwrap();
    https(&au.url)
        .post(
            &format!("/v1/entries/{}/repudiate", encode_did(stv.did())),
            &json!({ "repudiation": departure }),
        )
        .await
        .unwrap();
    assert_eq!(
        ask_pass(&whn, &person, vmc, vec![link]).await.unwrap_err(),
        Some(422)
    );
}
