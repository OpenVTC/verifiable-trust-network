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
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use trust_tasks_rs::RequestPayload;
use vti_specs_vtn::vtn as specs;
use vti_vtn::credentials::member;
use vti_vtn::groups;
use vti_vtn::identity::Identity;
use vti_vtn::model::{Framework, Visibility};
use vti_vtn::relay::{self, Envelope};
use vti_vtn::status::{Bitstring, Purpose, credential_status, status_list_credential};
use vti_vtn::verify::{AUTHENTICATION, LocalDidKeyResolver};
use vti_vtn::{ClientError, VtnClient};
use vtn_service::config::{Config, DirectoryConfig, MembershipConfig, NetworkConfig};
use vtn_service::identity::VtaKeyResolver;

use specs::listings::{create::v0_1 as create, show::v0_1 as show, suspend::v0_1 as suspend};
use specs::membership::{
    acknowledge::v0_1 as acknowledge, offer::v0_1 as offer, repudiate::v0_1 as repudiate,
};

mod support;
use support::tls;

/// A client for a test server, trusting the test authority, verifying its answers (the
/// networks here are `did:key`s).
fn https(url: &str) -> VtnClient {
    VtnClient::with_http(tls::client(), url).verifying(Arc::new(VtaKeyResolver::offline()))
}

struct Live {
    _dir: tempfile::TempDir,
    url: String,
    did: String,
    /// The operator's NNM identity, an administrator of this network.
    operator: Identity,
}

impl Live {
    fn client(&self) -> VtnClient {
        https(&self.url)
    }

    /// Task `P` with `payload`, signed by `who`; the response as JSON, or the refusal.
    async fn task<P>(&self, who: &Identity, payload: Value) -> Result<Value, ClientError>
    where
        P: RequestPayload + DeserializeOwned,
        P::Response: Serialize,
    {
        let payload: P = serde_json::from_value(payload).expect("a valid payload");
        let answer = self.client().task(who, &self.did, &payload).await?;
        Ok(serde_json::to_value(answer).unwrap())
    }

    /// Task `P`, unsigned.
    async fn read<P>(&self, payload: Value) -> Result<Value, ClientError>
    where
        P: RequestPayload + DeserializeOwned,
        P::Response: Serialize,
    {
        let payload: P = serde_json::from_value(payload).expect("a valid payload");
        let answer = self.client().read_task(&self.did, &payload).await?;
        Ok(serde_json::to_value(answer).unwrap())
    }

    /// Task `P` as the operator, which must succeed.
    async fn admin<P>(&self, payload: Value) -> Value
    where
        P: RequestPayload + DeserializeOwned,
        P::Response: Serialize,
    {
        let operator = self.operator.clone();
        self.task::<P>(&operator, payload)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", P::TYPE_URI))
    }

    /// `who` registers `group` for `role`, deliveries to `endpoint`: the network's answer.
    async fn register(
        &self,
        who: &Identity,
        role: &str,
        group: &str,
        endpoint: &str,
    ) -> Result<Value, ClientError> {
        let registration = groups::register(who, &self.did, role, group, endpoint)
            .await
            .unwrap();
        self.client().send_request(&registration, &self.did).await
    }
}

/// The code of a refusal.
fn code(result: Result<Value, ClientError>) -> String {
    match result {
        Err(e) => e
            .code()
            .unwrap_or_else(|| panic!("not a refusal: {e}"))
            .to_string(),
        Ok(v) => panic!("expected a refusal, got {v}"),
    }
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
        auth: Default::default(),
        rooms,
        identity: None,
        secrets: None,
        registry: None,
    };
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    let did = state.network.did().to_string();
    let app = vtn_service::routes::router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Live {
        _dir: dir,
        url,
        did,
        operator,
    }
}

/// What a community answers a `vtc/networks/deliver`: the `#response`, signed by it.
async fn community_answer(me: &Identity, request: &Value, status: &str) -> Value {
    assert_eq!(
        request["type"], "https://trusttasks.org/spec/vtc/networks/deliver/0.1",
        "a community gets vtc/networks/deliver"
    );
    assert_eq!(request["payload"]["role"], "admins", "{request}");
    let answer = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": format!("{}#response", request["type"].as_str().unwrap()),
        "issuer": me.did(),
        "recipient": request["issuer"],
        "threadId": request["id"],
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": { "status": status },
    });
    me.sign_document_for(answer, AUTHENTICATION).await.unwrap()
}

/// Community group inboxes (Trust Task endpoints), keyed by name; each delivered envelope is
/// recorded, and answered as the community whose key [`Inboxes::add`] gave.
#[derive(Clone, Default)]
struct Inboxes {
    got: Arc<Mutex<HashMap<String, Vec<Value>>>>,
    keys: Arc<Mutex<HashMap<String, Identity>>>,
}

impl Inboxes {
    async fn start(&self) -> String {
        async fn deliver(
            State(inboxes): State<Inboxes>,
            Path(name): Path<String>,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            let me = inboxes.keys.lock().await[&name].clone();
            inboxes
                .got
                .lock()
                .await
                .entry(name)
                .or_default()
                .push(request["payload"]["envelope"].clone());
            Json(community_answer(&me, &request, "delivered").await)
        }
        serve(
            Router::new()
                .route("/inbox/{name}", post(deliver))
                .with_state(self.clone()),
        )
        .await
    }

    /// The inbox `name` answers as `community`.
    async fn add(&self, name: &str, community: &Identity) {
        self.keys
            .lock()
            .await
            .insert(name.into(), community.clone());
    }

    async fn of(&self, name: &str) -> Vec<Value> {
        self.got.lock().await.get(name).cloned().unwrap_or_default()
    }
}

/// A community joins `net`: listed by its admin, registers its admins group, acknowledges.
async fn community_joins(net: &Live, community: &Identity, label: &str, inbox: &str) {
    net.admin::<create::Payload>(
        json!({ "did": community.did(), "kind": "community", "label": label }),
    )
    .await;
    let at = Utc::now() - Duration::seconds(5);

    // Acknowledging before registering the required role is refused, naming the role.
    let offered = net
        .task::<offer::Payload>(community, json!({}))
        .await
        .unwrap();
    let ack = member::acknowledge(&offered["offer"], community, at, None)
        .await
        .unwrap();
    let early = net
        .task::<acknowledge::Payload>(community, json!({ "acknowledgement": ack }))
        .await
        .unwrap_err();
    assert_eq!(
        early.code(),
        Some("vtn/membership/acknowledge:rolesUnregistered"),
        "required role first"
    );
    match early {
        ClientError::Refused { details, .. } => {
            assert_eq!(details.unwrap()["roles"], json!(["admins"]));
        }
        other => panic!("{other}"),
    }

    let group = format!("{}:groups:admins", community.did());
    let registered = net
        .register(community, "admins", &group, inbox)
        .await
        .unwrap();
    assert_eq!(registered["group"]["group"], group);
    let acknowledged = net
        .task::<acknowledge::Payload>(community, json!({ "acknowledgement": ack }))
        .await
        .unwrap();
    assert_eq!(acknowledged["entry"]["state"], "acknowledged");
}

/// `child` is listed by `parent` and joins it, serving `admins` with its own network group.
async fn network_joins(parent: &Live, child: &Live, label: &str) -> Value {
    parent
        .admin::<create::Payload>(json!({ "did": child.did, "kind": "network", "label": label }))
        .await;
    child
        .admin::<specs::memberships::join::v0_1::Payload>(
            json!({ "url": parent.url, "network": parent.did, "roles": [] }),
        )
        .await["membership"]
        .clone()
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
    inboxes.add("msf", &msf).await;
    community_joins(&whn, &msf, "MSF", &format!("{inbox_url}/inbox/msf")).await;

    // Health-AU joins WHN by itself: its network group is registered for WHN's admins.
    let membership = network_joins(&whn, &au, "Health-AU").await;
    assert_eq!(membership["state"], "acknowledged");
    assert_eq!(
        membership["groups"][0]["group"],
        format!("{}#role-admins", au.did)
    );
    let entry = whn.admin::<show::Payload>(json!({ "did": au.did })).await;
    assert_eq!(entry["entry"]["state"], "acknowledged");

    // Health-AU is members-only; St Vincent's is listed there and joins, asking as itself.
    let stv = Identity::generate();
    inboxes.add("stv", &stv).await;
    au.admin::<create::Payload>(
        json!({ "did": stv.did(), "kind": "community", "label": "St Vincent's" }),
    )
    .await;
    let at = Utc::now() - Duration::seconds(5);
    au.register(
        &stv,
        "admins",
        &format!("{}:groups:admins", stv.did()),
        &format!("{inbox_url}/inbox/stv"),
    )
    .await
    .unwrap();
    let offered = au.task::<offer::Payload>(&stv, json!({})).await.unwrap();
    let ack = member::acknowledge(&offered["offer"], &stv, at, None)
        .await
        .unwrap();
    au.task::<acknowledge::Payload>(&stv, json!({ "acknowledgement": ack }))
        .await
        .unwrap();

    // A cycle: WHN also joins Health-AU.
    network_joins(&au, &whn, "WHN").await;

    // --- WHN broadcasts to all admins.
    let record = whn
        .admin::<specs::broadcasts::send::v0_1::Payload>(
            json!({ "role": "admins", "subject": "Drill", "body": "Exercise at 09:00 UTC" }),
        )
        .await["broadcast"]
        .clone();
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
    let au_log = au
        .admin::<specs::broadcasts::list::v0_1::Payload>(json!({}))
        .await;
    assert_eq!(au_log["broadcasts"][0]["direction"], "received");
    assert_eq!(au_log["broadcasts"][0]["from"], whn.did);

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
    let refused = au
        .task::<specs::relay::deliver::v0_1::Payload>(
            &rogue,
            json!({ "role": "admins", "envelope": { "message": message, "hops": [hop] } }),
        )
        .await;
    assert_eq!(code(refused), "vtn/relay/deliver:notMember");

    // --- A suspended member's groups are skipped.
    whn.admin::<suspend::Payload>(json!({ "did": msf.did() }))
        .await;
    let record = whn
        .admin::<specs::broadcasts::send::v0_1::Payload>(
            json!({ "role": "admins", "subject": "Second", "body": "…" }),
        )
        .await["broadcast"]
        .clone();
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
        .admin::<specs::memberships::leave::v0_1::Payload>(json!({ "network": whn.did }))
        .await;
    assert_eq!(left["membership"]["state"], "departed");
    let entry = whn.admin::<show::Payload>(json!({ "did": au.did })).await;
    assert_eq!(entry["entry"]["state"], "departed");
    let groups = whn
        .admin::<specs::groups::list::v0_1::Payload>(json!({ "role": "admins" }))
        .await;
    assert!(
        groups["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["member"] != au.did)
    );
    // Broadcasting again no longer reaches St Vincent's through Health-AU.
    whn.admin::<specs::broadcasts::send::v0_1::Payload>(
        json!({ "role": "admins", "subject": "Third", "body": "…" }),
    )
    .await;
    assert_eq!(inboxes.of("stv").await.len(), 2);
}

#[tokio::test]
async fn a_network_can_repudiate_a_parent_listing() {
    let whn = live("WHN", false, Visibility::Public).await;
    let nz = live("Health-NZ", false, Visibility::Public).await;
    whn.admin::<create::Payload>(json!({ "did": nz.did, "kind": "network", "label": "Health-NZ" }))
        .await;
    let m = nz
        .admin::<specs::memberships::repudiate::v0_1::Payload>(
            json!({ "url": whn.url, "network": whn.did }),
        )
        .await;
    assert_eq!(m["membership"]["state"], "repudiated");
    let entry = whn
        .read::<specs::entries::show::v0_1::Payload>(json!({ "did": nz.did }))
        .await
        .unwrap();
    assert_eq!(entry["entry"]["state"], "repudiated");
    assert!(
        entry["entry"]["repudiation"].is_object(),
        "published with the repudiation"
    );

    // A network that was never listed cannot join.
    let stranger = live("Stranger", false, Visibility::Public).await;
    let refused = stranger
        .task::<specs::memberships::join::v0_1::Payload>(
            &stranger.operator,
            json!({ "url": whn.url, "network": whn.did, "roles": [] }),
        )
        .await;
    assert_eq!(code(refused), "vtn/memberships/join:notListed");
    // Nor join the network at a URL that answers as another.
    let refused = stranger
        .task::<specs::memberships::join::v0_1::Payload>(
            &stranger.operator,
            json!({ "url": whn.url, "network": nz.did, "roles": [] }),
        )
        .await;
    assert_eq!(code(refused), "vtn/memberships/join:networkMismatch");
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
    community_joins_open(&whn, &msf).await;

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
    // The person reads the members-only directory, presenting the credential.
    let search = |person: Identity, vmc: Value| {
        let whn = &whn;
        async move {
            whn.task::<specs::directory::search::v0_1::Payload>(
                &person,
                json!({ "membership": vmc }),
            )
            .await
        }
    };

    let (person, good) = vmc(Some(0), status_url.clone()).await;
    assert!(search(person, good).await.is_ok(), "status clear");
    let (person, revoked) = vmc(Some(1), status_url.clone()).await;
    assert_eq!(
        code(search(person, revoked).await),
        "permissionDenied",
        "revoked"
    );
    let (person, unreachable) = vmc(Some(0), "https://127.0.0.1:9".into()).await;
    assert_eq!(
        code(search(person, unreachable).await),
        "permissionDenied",
        "an unreachable status list is indeterminate, not valid"
    );
    let (person, no_status) = vmc(None, String::new()).await;
    assert!(
        search(person, no_status).await.is_ok(),
        "validity window only"
    );
}

/// `parent` lists `child` with its URL, and `child` joins.
async fn network_joins_at(parent: &Live, child: &Live, label: &str) {
    parent
        .admin::<create::Payload>(
            json!({ "did": child.did, "kind": "network", "label": label, "url": child.url }),
        )
        .await;
    child
        .admin::<specs::memberships::join::v0_1::Payload>(
            json!({ "url": parent.url, "network": parent.did, "roles": [] }),
        )
        .await;
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
    nsw.admin::<create::Payload>(
        json!({ "did": Identity::generate().did(), "kind": "community",
                     "label": "St Vincent's Hospital", "tags": ["sydney"] }),
    )
    .await;
    // Listed by WHN but never acknowledged: not followed.
    let pending = live("Pending-Net", false, Visibility::Public).await;
    whn.admin::<create::Payload>(
        json!({ "did": pending.did, "kind": "network", "url": pending.url }),
    )
    .await;
    pending
        .admin::<create::Payload>(
            json!({ "did": Identity::generate().did(), "kind": "community", "label": "Vincent Hidden" }),
        )
        .await;

    let found = whn
        .read::<specs::directory::federated::v0_1::Payload>(json!({ "q": "vincent" }))
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
    let au_graph = whn
        .read::<specs::graph::member::v0_1::Payload>(json!({ "did": au.did }))
        .await
        .unwrap()["graph"]
        .clone();
    assert_eq!(au_graph["nodes"][0]["id"], au.did);
    assert!(
        au_graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == nsw.did)
    );
    // Not for a network that never acknowledged.
    let refused = whn
        .read::<specs::graph::member::v0_1::Payload>(json!({ "did": pending.did }))
        .await;
    assert_eq!(code(refused), "vtn/graph/member:notMember");

    // Plain (non-federated) search sees only WHN's own entries.
    let own = whn
        .read::<specs::directory::search::v0_1::Payload>(json!({ "q": "vincent" }))
        .await
        .unwrap();
    assert!(own["entries"].as_array().unwrap().is_empty());
}

/// A community joins a network with no required roles.
async fn community_joins_open(net: &Live, community: &Identity) {
    net.admin::<create::Payload>(
        json!({ "did": community.did(), "kind": "community", "label": "MSF" }),
    )
    .await;
    let offered = net
        .task::<offer::Payload>(community, json!({}))
        .await
        .unwrap();
    let ack = member::acknowledge(
        &offered["offer"],
        community,
        Utc::now() - Duration::seconds(5),
        None,
    )
    .await
    .unwrap();
    net.task::<acknowledge::Payload>(community, json!({ "acknowledgement": ack }))
        .await
        .unwrap();
}

/// `community`'s inbox: answers 500 `fails` times, then accepts; or always refuses.
async fn flaky_inbox(
    community: &Identity,
    fails: u32,
    refuse: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let left = Arc::new(Mutex::new(fails));
    let me = community.clone();
    let (g, l) = (got.clone(), left.clone());
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let (g, l, me) = (g.clone(), l.clone(), me.clone());
            async move {
                if refuse {
                    return (
                        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({
                            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                            "threadId": request["id"],
                            "payload": {
                                "code": "vtc/networks/deliver:roleUnregistered",
                                "message": "no",
                            },
                        })),
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
                g.lock().await.push(request["payload"]["envelope"].clone());
                (
                    axum::http::StatusCode::OK,
                    Json(community_answer(&me, &request, "delivered").await),
                )
            }
        }),
    );
    (format!("{}/", serve(app).await), got)
}

/// A community joins `net` and registers a group (role not required) at `endpoint`.
async fn join_with_group(net: &Live, community: &Identity, endpoint: &str) {
    community_joins_open(net, community).await;
    net.register(
        community,
        "admins",
        &format!("{}:groups:admins", community.did()),
        endpoint,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_deliveries_are_queued_and_retried() {
    let whn = live("WHN", false, Visibility::Public).await;
    let flaky = Identity::generate();
    let refusing = Identity::generate();
    let dead = Identity::generate();
    let (flaky_url, flaky_got) = flaky_inbox(&flaky, 1, false).await;
    let (refusing_url, _) = flaky_inbox(&refusing, 0, true).await;
    join_with_group(&whn, &flaky, &flaky_url).await;
    join_with_group(&whn, &refusing, &refusing_url).await;
    join_with_group(&whn, &dead, "https://127.0.0.1:9/").await;

    let record = whn
        .admin::<specs::broadcasts::send::v0_1::Payload>(
            json!({ "role": "admins", "subject": "Retry", "body": "…" }),
        )
        .await["broadcast"]
        .clone();
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
    let outbox = whn
        .admin::<specs::outbox::list::v0_1::Payload>(json!({}))
        .await;
    assert_eq!(outbox["items"].as_array().unwrap().len(), 2);

    let retried = whn
        .admin::<specs::outbox::retry::v0_1::Payload>(json!({}))
        .await;
    assert_eq!(retried["attempted"], 2);
    let id = record["id"].as_str().unwrap();
    let record = whn
        .admin::<specs::broadcasts::show::v0_1::Payload>(json!({ "id": id }))
        .await["broadcast"]
        .clone();
    assert_eq!(status_of(&record, &flaky), "delivered");
    assert_eq!(record["reached"], 1);
    assert_eq!(flaky_got.lock().await.len(), 1);
    // The dead endpoint stays queued, its attempts counted.
    let outbox = whn
        .admin::<specs::outbox::list::v0_1::Payload>(json!({}))
        .await;
    let left = outbox["items"].as_array().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["member"], dead.did());
    assert_eq!(left[0]["attempts"], 2);
    assert_eq!(status_of(&record, &dead), "queued");
}

/// A community joins `net` registering `group` (a group DID it controls) for `admins`.
/// Returns the chain link for that group: the registration and the network's acceptance.
async fn join_registering(net: &Live, community: &Identity, group: &Identity) -> ChainLinkJson {
    community_joins_open(net, community).await;
    let registered = net
        .register(community, "admins", group.did(), "https://127.0.0.1:9/")
        .await
        .unwrap();
    json!({
        "registration": registered["group"]["registration"],
        "acceptance": registered["group"]["acceptance"],
    })
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

/// `person` asks `net` for a pass to the room `pandemic`, signing the request themselves.
async fn ask_pass(
    net: &Live,
    person: &Identity,
    membership: Value,
    chain: Vec<Value>,
) -> Result<Value, ClientError> {
    net.task::<specs::rooms::pass::v0_1::Payload>(
        person,
        json!({ "room": "pandemic", "membership": membership, "chain": chain }),
    )
    .await
    .map(|answer| answer["pass"].clone())
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
    whn.admin::<create::Payload>(json!({ "did": au.did, "kind": "network" }))
        .await;
    au.admin::<specs::memberships::join::v0_1::Payload>(json!({
        "url": whn.url,
        "network": whn.did,
        "roles": [{ "parentRole": "admins", "localRole": "admins" }],
    }))
    .await;

    // St Vincent's (in Health-AU) registers its admins group; a person is in that group.
    let stv = Identity::generate();
    let stv_admins = Identity::generate();
    let link = join_registering(&au, &stv, &stv_admins).await;
    let person = Identity::generate();
    let vmc = group_vmc(&stv_admins, &person).await;

    let rooms = whn
        .read::<specs::rooms::list::v0_1::Payload>(json!({}))
        .await
        .unwrap();
    assert_eq!(rooms["rooms"][0]["id"], "pandemic");
    assert_eq!(rooms["rooms"][0]["passMinutes"], 30);

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
        code(ask_pass(&whn, &person, vmc.clone(), vec![]).await),
        "vtn/rooms/pass:notEligible"
    );
    // A group nobody registered: the link does not lift it.
    let stranger_group = Identity::generate();
    let stranger = Identity::generate();
    assert_eq!(
        code(
            ask_pass(
                &whn,
                &stranger,
                group_vmc(&stranger_group, &stranger).await,
                vec![link.clone()]
            )
            .await
        ),
        "vtn/rooms/pass:chainInvalid"
    );
    // Someone else presenting the person's credential: refused.
    let thief = Identity::generate();
    assert_eq!(
        code(ask_pass(&whn, &thief, vmc.clone(), vec![link.clone()]).await),
        "vtn/rooms/pass:notEligible"
    );
    // A room that does not exist.
    assert_eq!(
        code(
            whn.task::<specs::rooms::pass::v0_1::Payload>(
                &person,
                json!({ "room": "nowhere", "membership": vmc, "chain": [] }),
            )
            .await
        ),
        "vtn/rooms/pass:unknownRoom"
    );

    // St Vincent's leaves Health-AU: its acceptance is revoked, and the chain no longer holds.
    let own = au
        .task::<specs::entries::show::v0_1::Payload>(&stv, json!({ "did": stv.did() }))
        .await
        .unwrap();
    let departure = member::repudiate(
        &own["entry"]["grant"],
        &stv,
        Utc::now() - Duration::seconds(5),
    )
    .await
    .unwrap();
    au.task::<repudiate::Payload>(&stv, json!({ "repudiation": departure }))
        .await
        .unwrap();
    assert_eq!(
        code(ask_pass(&whn, &person, vmc, vec![link]).await),
        "vtn/rooms/pass:chainInvalid"
    );
}
