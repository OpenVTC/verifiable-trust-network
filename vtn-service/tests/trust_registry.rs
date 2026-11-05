//! The trust-registry projection (A23): what the network publishes, how it follows the
//! lifecycle, the backfill of existing members, stale records, retries, and what the
//! profile and landing page advertise.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use serde_json::Value;
use tower::ServiceExt;
use vti_vtn::credentials::member;
use vti_vtn::identity::Identity;
use vti_vtn::model::{EntryKind, EntryProfile, Visibility};
use vtn_service::config::{
    Config, DirectoryConfig, MembershipConfig, NetworkConfig, RegistryConfig,
};
use vtn_service::identity::VtaKeyResolver;
use vtn_service::registry::{
    LISTED_ACTION, MEMBER_ACTION, MockRegistry, Publish, RESOURCE, Syncer, record_for,
};
use vtn_service::routes::{AppState, router};

const BASE_URL: &str = "https://whn.example";
const REGISTRY_DID: &str = "did:web:registry.example";

fn registry(publish: Publish) -> RegistryConfig {
    RegistryConfig {
        did: REGISTRY_DID.into(),
        query_url: Some("https://registry.example/".into()),
        publish,
        sync_interval_secs: 3600,
    }
}

async fn network(registry: Option<RegistryConfig>) -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        base_url: BASE_URL.into(),
        data_dir: dir.path().to_path_buf(),
        admins: vec![],
        resolver_url: None,
        extra_root_certificates: vec![],
        status_cache_seconds: 0,
        network: NetworkConfig {
            name: "WHN".into(),
            description: None,
            owner: "WHN owner".into(),
            framework: vti_vtn::model::Framework {
                iri: format!("{BASE_URL}/gf"),
                version: "1.0".into(),
            },
        },
        membership: MembershipConfig::default(),
        directory: DirectoryConfig {
            visibility: Visibility::Public,
            ..Default::default()
        },
        roles: vec![],
        relay: Default::default(),
        auth: Default::default(),
        rooms: vec![],
        identity: None,
        secrets: None,
        messaging: None,
        registry,
    };
    config.validate().unwrap();
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    (dir, state)
}

/// List `party`, and have it acknowledge: a member.
async fn member_of(state: &AppState, party: &Identity, label: &str) {
    list(state, party, label).await;
    let offer = state.network.offer(party.did()).await.unwrap();
    let ack = member::acknowledge(&offer, party, Utc::now() - Duration::seconds(5), None)
        .await
        .unwrap();
    state
        .network
        .acknowledge(party.did(), serde_json::to_value(ack).unwrap())
        .await
        .unwrap();
}

async fn list(state: &AppState, party: &Identity, label: &str) {
    state
        .network
        .list(
            party.did(),
            EntryKind::Community,
            Some(label.into()),
            EntryProfile::default(),
            "admin",
        )
        .await
        .unwrap();
}

fn syncer(state: &AppState, mock: &Arc<MockRegistry>, publish: Publish) -> Syncer {
    Syncer::new(state.network.clone(), mock.clone(), registry(publish))
}

#[tokio::test]
async fn existing_members_are_backfilled_and_the_projection_follows_the_lifecycle() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    let net = state.network.did().to_string();
    let (msf, westmead) = (Identity::generate(), Identity::generate());
    member_of(&state, &msf, "MSF").await;
    list(&state, &westmead, "Westmead").await;

    // First run, with members already there: every member is put; a listing is not
    // membership, so it is not published under `members` (VTI-VTN-013).
    let mock = Arc::new(MockRegistry::listing());
    let sync = syncer(&state, &mock, Publish::Members);
    let report = sync.reconcile().await.unwrap();
    assert_eq!(report.expected, 1, "{report:?}");
    assert_eq!(report.put, vec![msf.did().to_string()]);
    assert_eq!(
        mock.held(&net).await,
        vec![(msf.did().to_string(), MEMBER_ACTION.to_string())]
    );
    // Nothing changed: nothing is written again.
    let again = sync.reconcile().await.unwrap();
    assert!(
        again.put.is_empty() && again.deleted.is_empty(),
        "{again:?}"
    );

    // Westmead acknowledges: it is published too.
    let offer = state.network.offer(westmead.did()).await.unwrap();
    let ack = member::acknowledge(&offer, &westmead, Utc::now() - Duration::seconds(5), None)
        .await
        .unwrap();
    state
        .network
        .acknowledge(westmead.did(), serde_json::to_value(ack).unwrap())
        .await
        .unwrap();
    sync.reconcile().await.unwrap();
    assert_eq!(mock.held(&net).await.len(), 2);

    // Suspended: not a member while it lasts, so its record goes; reinstated, it returns.
    state
        .network
        .suspend(msf.did(), Some("audit".into()), "admin")
        .await
        .unwrap();
    let report = sync.reconcile().await.unwrap();
    assert_eq!(
        report.deleted,
        vec![format!("{} {MEMBER_ACTION}", msf.did())]
    );
    assert!(!mock.held(&net).await.iter().any(|(e, _)| e == msf.did()));
    state
        .network
        .reinstate(msf.did(), None, "admin")
        .await
        .unwrap();
    sync.reconcile().await.unwrap();
    assert!(mock.held(&net).await.iter().any(|(e, _)| e == msf.did()));

    // Removed: gone for good.
    state
        .network
        .remove(westmead.did(), None, "admin")
        .await
        .unwrap();
    sync.reconcile().await.unwrap();
    assert_eq!(
        mock.held(&net).await,
        vec![(msf.did().to_string(), MEMBER_ACTION.to_string())]
    );
}

#[tokio::test]
async fn a_record_this_network_did_not_derive_is_deleted() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    let net = state.network.did().to_string();
    let mock = Arc::new(MockRegistry::listing());
    // Left by an earlier run, or written by hand, under this network's authority.
    mock.plant(&net, "did:web:gone.example", MEMBER_ACTION)
        .await;
    // Another authority's record is not this network's to touch.
    mock.plant(
        "did:web:other-authority.example",
        "did:web:x.example",
        MEMBER_ACTION,
    )
    .await;
    let report = syncer(&state, &mock, Publish::Members)
        .reconcile()
        .await
        .unwrap();
    assert_eq!(
        report.deleted,
        vec![format!("did:web:gone.example {MEMBER_ACTION}")]
    );
    assert!(mock.held(&net).await.is_empty());
    assert_eq!(mock.held("did:web:other-authority.example").await.len(), 1);
}

#[tokio::test]
async fn listed_parties_are_published_under_their_own_action_only_when_asked() {
    let (_dir, state) = network(Some(registry(Publish::MembersAndListed))).await;
    let net = state.network.did().to_string();
    let (msf, westmead) = (Identity::generate(), Identity::generate());
    member_of(&state, &msf, "MSF").await;
    list(&state, &westmead, "Westmead").await;
    let mock = Arc::new(MockRegistry::listing());
    let sync = syncer(&state, &mock, Publish::MembersAndListed);
    sync.reconcile().await.unwrap();
    let mut held = mock.held(&net).await;
    held.sort();
    let mut want = vec![
        (msf.did().to_string(), MEMBER_ACTION.to_string()),
        (westmead.did().to_string(), LISTED_ACTION.to_string()),
    ];
    want.sort();
    assert_eq!(held, want);

    // Westmead acknowledges: its `lists` record is replaced by `member`, never both.
    let offer = state.network.offer(westmead.did()).await.unwrap();
    let ack = member::acknowledge(&offer, &westmead, Utc::now() - Duration::seconds(5), None)
        .await
        .unwrap();
    state
        .network
        .acknowledge(westmead.did(), serde_json::to_value(ack).unwrap())
        .await
        .unwrap();
    let report = sync.reconcile().await.unwrap();
    assert_eq!(
        report.deleted,
        vec![format!("{} {LISTED_ACTION}", westmead.did())]
    );
    assert!(
        mock.held(&net)
            .await
            .iter()
            .all(|(_, action)| action == MEMBER_ACTION)
    );
}

#[tokio::test]
async fn a_failed_write_is_retried_by_the_next_reconcile() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    let net = state.network.did().to_string();
    let msf = Identity::generate();
    member_of(&state, &msf, "MSF").await;
    // A registry that cannot list: the mirror of what was written stands in for it.
    let mock = Arc::new(MockRegistry::default());
    let sync = syncer(&state, &mock, Publish::Members);
    mock.fail(true);
    let report = sync.reconcile().await.unwrap();
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert!(report.put.is_empty());
    assert_eq!(sync.last_report().await.unwrap(), Some(report));

    mock.fail(false);
    let report = sync.reconcile().await.unwrap();
    assert_eq!(report.put, vec![msf.did().to_string()]);
    assert!(report.failed.is_empty());

    // Removed: deleted by what the mirror says was written, though the registry cannot list.
    state
        .network
        .remove(msf.did(), None, "admin")
        .await
        .unwrap();
    let report = sync.reconcile().await.unwrap();
    assert_eq!(
        report.deleted,
        vec![format!("{} {MEMBER_ACTION}", msf.did())]
    );
    assert!(mock.held(&net).await.is_empty());
}

#[tokio::test]
async fn without_a_write_transport_the_projection_is_reported_not_written() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    member_of(&state, &Identity::generate(), "MSF").await;
    let sync = Syncer::new(
        state.network.clone(),
        Arc::new(vtn_service::registry::NoWriteTransport),
        registry(Publish::Members),
    );
    let report = sync.reconcile().await.unwrap();
    assert_eq!(report.expected, 1);
    assert!(report.put.is_empty());
    assert!(
        report
            .blocked
            .as_deref()
            .unwrap_or("")
            .contains("DIDComm or TSP"),
        "{report:?}"
    );
}

#[tokio::test]
async fn a_member_record_carries_what_evidences_it() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    let msf = Identity::generate();
    member_of(&state, &msf, "MSF").await;
    let entry = state.network.entry(msf.did()).await.unwrap();
    let record = record_for(&entry, Publish::Members, &state.network.profile.framework).unwrap();
    let wire = record.trust_record(state.network.did());
    assert_eq!(wire["entityId"], msf.did());
    assert_eq!(wire["authorityId"], state.network.did());
    assert_eq!(wire["action"], MEMBER_ACTION);
    assert_eq!(wire["resource"], RESOURCE);
    assert_eq!(wire["context"]["kind"], "community");
    assert_eq!(wire["context"]["name"], "MSF");
    assert_eq!(wire["context"]["governanceFramework"]["version"], "1.0");
    assert_eq!(wire["context"]["listing"], entry.listing.credential["id"]);
    assert_eq!(
        wire["context"]["grant"],
        entry.grant.as_ref().unwrap().credential["id"]
    );
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Option<String>, Value) {
    let res = router(state.clone())
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let csp = res
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .map(|v| v.to_str().unwrap().to_string());
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (
        status,
        csp,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn the_profile_and_landing_page_advertise_the_registry() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    let (_, _, profile) = get(&state, "/.well-known/vtn").await;
    let tr = &profile["trustRegistry"];
    assert_eq!(tr["did"], REGISTRY_DID);
    assert_eq!(tr["queryUrl"], "https://registry.example/");
    assert_eq!(tr["authority"], state.network.did());
    assert_eq!(tr["resource"], RESOURCE);
    assert_eq!(tr["actions"]["member"], MEMBER_ACTION);
    assert_eq!(tr["actions"]["listed"], LISTED_ACTION);
    assert_eq!(tr["publishes"], "members");
    let (status, csp, _) = get(&state, "/").await;
    assert_eq!(status, StatusCode::OK);
    let csp = csp.unwrap();
    assert!(
        csp.contains("connect-src 'self' https://registry.example;"),
        "{csp}"
    );

    // No registry: no profile member, and the page reaches only this network.
    let (_dir, plain) = network(None).await;
    let (_, _, profile) = get(&plain, "/.well-known/vtn").await;
    assert!(profile.get("trustRegistry").is_none(), "{profile:#}");
    let (_, csp, _) = get(&plain, "/").await;
    assert!(csp.unwrap().contains("connect-src 'self';"));
}

#[test]
fn a_registry_must_be_named_by_did_and_queried_over_https() {
    let mut bad = registry(Publish::Members);
    bad.did = "https://registry.example".into();
    bad.query_url = Some("http://registry.example".into());
    bad.sync_interval_secs = 5;
    let config: Config = toml::from_str(&format!(
        r#"
        base_url = "{BASE_URL}"
        data_dir = "/tmp/x"
        [network]
        name = "WHN"
        owner = "o"
        framework = {{ iri = "{BASE_URL}/gf", version = "1.0" }}
        [registry]
        did = "{}"
        query_url = "{}"
        sync_interval_secs = {}
        "#,
        bad.did,
        bad.query_url.unwrap(),
        bad.sync_interval_secs
    ))
    .unwrap();
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("is not a DID"), "{err}");
    assert!(err.contains("must be an https:// URL"), "{err}");
    assert!(err.contains("at least 60"), "{err}");
}

/// A registry reached over the session: it checks each request as the Affinidi registry does
/// (named as recipient, issued by the sender, signed for `authentication` by it, the sender
/// in `ADMIN_DIDS`, writing under its own authority) and answers with signed documents.
struct SessionRegistry {
    me: Identity,
    admins: std::sync::Mutex<Vec<String>>,
    records: std::sync::Mutex<std::collections::BTreeMap<(String, String, String), Value>>,
    seen: std::sync::Mutex<Vec<Value>>,
}

impl SessionRegistry {
    fn new(admin: &str) -> Self {
        Self {
            me: Identity::generate(),
            admins: std::sync::Mutex::new(vec![admin.to_string()]),
            records: Default::default(),
            seen: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl vtn_service::messaging::Exchange for SessionRegistry {
    async fn request(
        &self,
        peer: &str,
        document: Value,
        _timeout: std::time::Duration,
    ) -> Result<Value, vtn_service::messaging::RequestError> {
        assert_eq!(peer, REGISTRY_DID);
        self.seen.lock().unwrap().push(document.clone());
        let issuer = document["issuer"].as_str().unwrap().to_string();
        assert_eq!(document["recipient"], REGISTRY_DID);
        assert!(document["issuedAt"].is_string());
        vti_vtn::verify::verify_document(
            &document,
            &issuer,
            vti_vtn::verify::AUTHENTICATION,
            &VtaKeyResolver::offline(),
        )
        .await
        .expect("a request signed for authentication by its issuer");
        let type_uri = document["type"].as_str().unwrap().to_string();
        let p = &document["payload"];
        let (kind, payload) = if !self.admins.lock().unwrap().contains(&issuer) {
            (
                "error",
                serde_json::json!({ "code": "permissionDenied", "message": "not an admin" }),
            )
        } else if type_uri.contains("/record/put/") {
            let r = &p["record"];
            assert_eq!(
                r["authorityId"],
                issuer.as_str(),
                "writes under its own authority"
            );
            assert_eq!(r["recordType"], "authorization");
            let key = (
                r["entityId"].as_str().unwrap().to_string(),
                r["action"].as_str().unwrap().to_string(),
                r["resource"].as_str().unwrap().to_string(),
            );
            let created = self
                .records
                .lock()
                .unwrap()
                .insert(key, r.clone())
                .is_none();
            (
                "ok",
                serde_json::json!({ "ok": true, "wasCreated": created }),
            )
        } else if type_uri.contains("/record/delete/") {
            let key = (
                p["entityId"].as_str().unwrap().to_string(),
                p["action"].as_str().unwrap().to_string(),
                p["resource"].as_str().unwrap().to_string(),
            );
            match self.records.lock().unwrap().remove(&key) {
                Some(_) => ("ok", serde_json::json!({ "ok": true })),
                None => (
                    "error",
                    serde_json::json!({ "code": "registry/record/delete:notFound" }),
                ),
            }
        } else if type_uri.contains("/record/query/") {
            let records: Vec<Value> = self
                .records
                .lock()
                .unwrap()
                .values()
                .filter(|r| r["authorityId"] == p["authorityId"])
                .cloned()
                .collect();
            ("ok", serde_json::json!({ "records": records }))
        } else {
            panic!("unexpected {type_uri}");
        };
        let answer = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": if kind == "ok" { format!("{type_uri}#response") } else {
                "https://trusttasks.org/spec/trust-task-error/0.1".to_string() },
            "threadId": document["id"],
            "issuer": self.me.did(),
            "recipient": issuer,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": payload,
        });
        Ok(self
            .me
            .sign_document_for(answer, vti_vtn::verify::AUTHENTICATION)
            .await
            .unwrap())
    }
    fn is_connected(&self) -> bool {
        true
    }
}

fn session_syncer(state: &AppState, registry_: &Arc<SessionRegistry>) -> Syncer {
    let writer = vtn_service::registry::MessagingWriter::new(
        state.network.clone(),
        registry_.clone(),
        REGISTRY_DID.into(),
        "did:web:mediator.example".into(),
        std::time::Duration::from_secs(5),
    );
    Syncer::new(
        state.network.clone(),
        Arc::new(writer),
        registry(Publish::Members),
    )
}

/// Over the session: the backfill writes signed `registry/record/put/0.3` requests the
/// registry accepts, a departure deletes the record, and the registry's own list is what
/// the reconcile compares against. Without the network in `ADMIN_DIDS`, every write is
/// refused and reported, and retried once it is added.
#[tokio::test]
async fn records_are_written_as_signed_trust_tasks_over_the_session() {
    let (_dir, state) = network(Some(registry(Publish::Members))).await;
    let net = state.network.did().to_string();
    let (msf, au) = (Identity::generate(), Identity::generate());
    member_of(&state, &msf, "MSF").await;
    member_of(&state, &au, "Health-AU").await;

    let reg = Arc::new(SessionRegistry::new("did:web:someone-else"));
    let sync = session_syncer(&state, &reg);
    let refused = sync.reconcile().await.unwrap();
    // Not an admin: the registry refuses even the listing, and nothing is written.
    assert!(
        refused
            .blocked
            .as_deref()
            .is_some_and(|b| b.contains("permissionDenied")),
        "{refused:?}"
    );
    assert!(reg.records.lock().unwrap().is_empty());

    reg.admins.lock().unwrap().push(net.clone());
    let report = sync.reconcile().await.unwrap();
    assert_eq!(report.put.len(), 2, "{report:?}");
    assert!(
        report.failed.is_empty() && report.blocked.is_none(),
        "{report:?}"
    );
    let types: Vec<String> = reg
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|d| d["type"].as_str().unwrap().to_string())
        .collect();
    assert!(
        types
            .iter()
            .any(|t| t.ends_with("/registry/record/put/0.3")),
        "{types:?}"
    );
    assert!(
        types
            .iter()
            .any(|t| t.ends_with("/registry/record/query/0.3")),
        "{types:?}"
    );
    let r = reg.records.lock().unwrap()[&(
        msf.did().to_string(),
        MEMBER_ACTION.to_string(),
        RESOURCE.to_string(),
    )]
        .clone();
    assert_eq!(r["authorityId"], net.as_str());
    assert_eq!(r["context"]["name"], "MSF");

    // Health-AU departs: its record goes.
    let grant = state
        .network
        .entry(au.did())
        .await
        .unwrap()
        .grant
        .unwrap()
        .credential;
    let departure = member::repudiate(&grant, &au, Utc::now() - Duration::seconds(5))
        .await
        .unwrap();
    state
        .network
        .repudiate(au.did(), serde_json::to_value(departure).unwrap())
        .await
        .unwrap();
    let report = sync.reconcile().await.unwrap();
    assert_eq!(
        report.deleted,
        vec![format!("{} {MEMBER_ACTION}", au.did())],
        "{report:?}"
    );
    assert_eq!(reg.records.lock().unwrap().len(), 1);
}
