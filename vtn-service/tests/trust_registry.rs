//! The trust-registry projection (A22): what the network publishes, how it follows the
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
