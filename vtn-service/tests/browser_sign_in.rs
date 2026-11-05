//! Browser sign-in (`auth/oob/*`, A13) end to end through the router, every document signed
//! for real: the landing page's key `K_b` is approved by a member community's wallet, then
//! reads a members-only directory as that community, and nothing else.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, header};
use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::ServiceExt;
use trust_tasks_rs::Payload;
use vti_specs_vtn::vtn as specs;
use vti_vtn::credentials::member;
use vti_vtn::identity::Identity;
use vti_vtn::model::Visibility;
use vti_vtn::request::sign_request;
use vti_vtn::verify::{ASSERTION_METHOD, AUTHENTICATION};
use vtn_service::config::{Config, DirectoryConfig, MembershipConfig, NetworkConfig};
use vtn_service::identity::VtaKeyResolver;
use vtn_service::routes::router;

const BASE_URL: &str = "https://whn.example";
const OOB: &str = "https://trusttasks.org/spec/auth/oob";

struct Net {
    _dir: tempfile::TempDir,
    did: String,
    app: Router,
    operator: Identity,
}

async fn network() -> Net {
    let dir = tempfile::tempdir().unwrap();
    let operator = Identity::generate();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        base_url: BASE_URL.into(),
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
                iri: format!("{BASE_URL}/gf"),
                version: "1.0".into(),
            },
        },
        membership: MembershipConfig::default(),
        directory: DirectoryConfig {
            visibility: Visibility::Members,
            ..Default::default()
        },
        roles: vec![],
        relay: Default::default(),
        auth: Default::default(),
        rooms: vec![],
        identity: None,
        secrets: None,
        registry: None,
    };
    vtn_service::init_dev(&config).unwrap();
    let state = vtn_service::build_state_with(&config, Arc::new(VtaKeyResolver::offline()))
        .await
        .unwrap();
    Net {
        _dir: dir,
        did: state.network.did().to_string(),
        app: router(state),
        operator,
    }
}

impl Net {
    /// Post `doc` as the browser at this network's origin would.
    async fn post(&self, doc: &Value) -> Value {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/trust-tasks")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, BASE_URL)
            .header(header::HOST, "whn.example")
            .header(header::USER_AGENT, "Mozilla/5.0 (Macintosh) Firefox/140.0")
            .body(Body::from(doc.to_string()))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    /// An `auth/oob` document from `who`, signed for `purpose`.
    async fn oob(
        &self,
        who: &Identity,
        task: &str,
        payload: Value,
        parent: Option<&str>,
        purpose: &str,
    ) -> Value {
        let version = match task {
            "request" | "claim" | "redeem" => "0.2",
            "prove" | "respond" | "grant" => "0.3",
            _ => "0.1",
        };
        let mut doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": format!("{OOB}/{task}/{version}"),
            "issuer": who.did(),
            "recipient": self.did,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": payload,
        });
        if let Some(p) = parent {
            doc["parentThreadId"] = json!(p);
        }
        who.sign_document_for(doc, purpose).await.unwrap()
    }

    /// Task `P`, signed by `who`: the response document.
    async fn task<P: Payload + DeserializeOwned>(&self, who: &Identity, payload: Value) -> Value {
        let payload: P = serde_json::from_value(payload).unwrap();
        self.post(&sign_request(who, &self.did, &payload).await.unwrap())
            .await
    }
}

fn ok(answer: &Value) -> &Value {
    assert!(
        answer["type"]
            .as_str()
            .unwrap_or_default()
            .ends_with("#response"),
        "{answer:#}"
    );
    &answer["payload"]
}

fn code(answer: &Value) -> &str {
    answer["payload"]["code"].as_str().unwrap_or_default()
}

/// `party` is listed and acknowledges.
async fn joins(net: &Net, party: &Identity) {
    let operator = net.operator.clone();
    ok(&net
        .task::<specs::listings::create::v0_1::Payload>(
            &operator,
            json!({ "did": party.did(), "kind": "community", "label": "MSF" }),
        )
        .await);
    let offered = net
        .task::<specs::membership::offer::v0_1::Payload>(party, json!({}))
        .await;
    let ack = member::acknowledge(
        &ok(&offered)["offer"],
        party,
        Utc::now() - Duration::seconds(5),
        None,
    )
    .await
    .unwrap();
    ok(&net
        .task::<specs::membership::acknowledge::v0_1::Payload>(
            party,
            json!({ "acknowledgement": ack }),
        )
        .await);
}

/// Run the flow up to `prove` for `approver`: the request id, and step 2 (or the refusal).
async fn up_to_prove(
    net: &Net,
    k_b: &Identity,
    k_a: &Identity,
    approver: &Identity,
) -> (String, Value) {
    let started = net
        .post(
            &net.oob(
                k_b,
                "request",
                json!({ "purpose": "login", "mode": "scan" }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    let id = ok(&started)["requestId"].as_str().unwrap().to_string();
    let step1 = net
        .post(
            &net.oob(
                k_a,
                "claim",
                json!({ "requestId": id }),
                Some(&id),
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    assert_eq!(ok(&step1)["service"]["did"], net.did);
    assert_eq!(ok(&step1)["service"]["name"], "WHN");
    // The page learns the number the person types into the wallet.
    let pending = net
        .post(
            &net.oob(
                k_b,
                "redeem",
                json!({ "requestId": id }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    assert_eq!(code(&pending), "auth/oob/redeem:pending", "{pending:#}");
    let number = pending["payload"]["details"]["matchNumber"]
        .as_str()
        .unwrap()
        .to_string();
    let identify = net
        .oob(
            approver,
            "identify",
            json!({ "requestId": id, "approverKey": k_a.did(), "enteredNumber": number }),
            None,
            AUTHENTICATION,
        )
        .await;
    let step2 = net
        .post(
            &net.oob(
                k_a,
                "prove",
                json!({ "identify": identify }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    (id, step2)
}

#[tokio::test]
async fn a_wallet_approves_the_page_key_for_reads_only() {
    vti_oob_server::set_redeem_hold_for_tests(std::time::Duration::from_millis(100));
    let net = network().await;
    let msf = Identity::generate();
    joins(&net, &msf).await;
    let (k_b, k_a) = (Identity::generate(), Identity::generate());

    // Before sign-in the page's key is no one: the members-only directory is closed.
    let search = json!({});
    let closed = net
        .task::<specs::directory::search::v0_1::Payload>(&k_b, search.clone())
        .await;
    assert_eq!(code(&closed), "permissionDenied");

    let (id, step2) = up_to_prove(&net, &k_b, &k_a, &msf).await;
    let offered = ok(&step2);
    assert_eq!(offered["identifiedAs"], msf.did(), "{step2:#}");
    let scope = offered["signingScope"].clone();
    assert!(
        scope
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "vtn/directory")
    );
    assert!(
        step2["proof"]["proofPurpose"] == ASSERTION_METHOD,
        "step 2 is attested"
    );

    // The approver grants, over the step 2 it saw, for longer than the network allows.
    let grant = net
        .oob(
            &msf,
            "grant",
            json!({
                "requestId": id,
                "decision": "approve",
                "sessionKey": k_b.did(),
                "approverKey": k_a.did(),
                "origin": BASE_URL,
                "contextDigest": vti_oob_server::context_digest(&step2).unwrap(),
                "sessionEndsAt": (Utc::now() + Duration::days(2)).to_rfc3339(),
                "signingScope": scope,
            }),
            None,
            ASSERTION_METHOD,
        )
        .await;
    let responded = net
        .post(
            &net.oob(
                &k_a,
                "respond",
                json!({ "grant": grant }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    assert_eq!(ok(&responded)["status"], "approved", "{responded:#}");

    let redeemed = net
        .post(
            &net.oob(
                &k_b,
                "redeem",
                json!({ "requestId": id }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    let done = ok(&redeemed);
    assert_eq!(done["subject"], msf.did());
    assert_eq!(done["displayName"], "MSF");
    // Capped at `[auth] browser_key_hours` (8 by default), not the grant's two days.
    let ends: chrono::DateTime<Utc> = done["sessionEndsAt"].as_str().unwrap().parse().unwrap();
    assert!(
        ends <= Utc::now() + Duration::hours(8) + Duration::minutes(1),
        "{ends}"
    );

    // Now the page's key reads the directory as MSF...
    let open = net
        .task::<specs::directory::search::v0_1::Payload>(&k_b, search)
        .await;
    assert_eq!(ok(&open)["entries"].as_array().unwrap().len(), 1);
    // ...and its own entry as MSF.
    let own = net
        .task::<specs::entries::show::v0_1::Payload>(&k_b, json!({ "did": msf.did() }))
        .await;
    assert_eq!(ok(&own)["entry"]["state"], "acknowledged");
    // It signs nothing outside the scope: not MSF's membership tasks.
    let offer = net
        .task::<specs::membership::offer::v0_1::Payload>(&k_b, json!({}))
        .await;
    assert_eq!(code(&offer), "vtn/membership/offer:notListed");

    // Sign-out: the key revokes its own delegation, and is no one again.
    let revoke: vti_specs_core::auth::revoke_session::v0_2::Payload =
        serde_json::from_value(json!({ "all": true, "reason": "logout" })).unwrap();
    let out = net
        .post(&sign_request(&k_b, &net.did, &revoke).await.unwrap())
        .await;
    assert_eq!(ok(&out)["revokedCount"], 1, "{out:#}");
    let closed = net
        .task::<specs::directory::search::v0_1::Payload>(&k_b, json!({}))
        .await;
    assert_eq!(code(&closed), "permissionDenied");
    // Again: nothing left to revoke.
    let again = net
        .post(&sign_request(&k_b, &net.did, &revoke).await.unwrap())
        .await;
    assert_eq!(ok(&again)["revokedCount"], 0, "{again:#}");
}

#[tokio::test]
async fn only_a_party_or_administrator_may_approve() {
    vti_oob_server::set_redeem_hold_for_tests(std::time::Duration::from_millis(100));
    let net = network().await;
    let stranger = Identity::generate();
    let (k_b, k_a) = (Identity::generate(), Identity::generate());
    let (_, step2) = up_to_prove(&net, &k_b, &k_a, &stranger).await;
    assert_eq!(code(&step2), "auth/oob:notAuthorized", "{step2:#}");

    // The administrator may: and with the key, still no administration.
    let (k_b, k_a) = (Identity::generate(), Identity::generate());
    let operator = net.operator.clone();
    let (_, step2) = up_to_prove(&net, &k_b, &k_a, &operator).await;
    assert_eq!(ok(&step2)["identifiedAs"], operator.did());
}

#[tokio::test]
async fn sign_in_keys_must_be_made_for_the_exchange() {
    let net = network().await;
    // A network DID's key, not an Ed25519 did:key made for this sign-in, is refused before
    // anything is verified (T21). An `Identity` here is a did:key too, so forge the issuer.
    let k_b = Identity::generate();
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": format!("{OOB}/request/0.2"),
        "issuer": "did:web:example.org",
        "recipient": net.did,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": { "purpose": "login", "mode": "scan" },
    });
    doc = k_b.sign_document_for(doc, AUTHENTICATION).await.unwrap();
    assert_eq!(code(&net.post(&doc).await), "auth/oob:keyUnsupported");
}

/// The landing page shows the sign-in link as a QR code a phone wallet can scan, drawn from
/// this network's own link (its DID and link host), and only for a well-formed request id.
#[tokio::test]
async fn the_sign_in_link_is_served_as_a_qr_code() {
    let net = network().await;
    let get = |uri: String| {
        let app = net.app.clone();
        async move {
            let res = app
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = res.status();
            let kind = res
                .headers()
                .get(header::CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, kind, String::from_utf8(body.to_vec()).unwrap())
        }
    };

    let id = vti_oob_server::new_request_id();
    let exp = Utc::now().timestamp() as u64 + 120;
    let (status, kind, svg) = get(format!("/v1/sign-in/qr.svg?id={id}&exp={exp}")).await;
    assert_eq!(status, 200);
    assert_eq!(kind.as_deref(), Some("image/svg+xml"));
    assert!(svg.contains("<svg"), "{svg}");

    let (status, _, _) = get(format!("/v1/sign-in/qr.svg?id=not-an-id&exp={exp}")).await;
    assert_eq!(status, 400);
    let (status, _, _) = get("/v1/sign-in/qr.svg".to_string()).await;
    assert_eq!(status, 400);
}

/// Sign `k_b` in as `approver` through the whole exchange; returns once `redeem` succeeds.
async fn sign_in(net: &Net, k_b: &Identity, approver: &Identity) {
    let k_a = Identity::generate();
    let (id, step2) = up_to_prove(net, k_b, &k_a, approver).await;
    let scope = ok(&step2)["signingScope"].clone();
    let grant = net
        .oob(
            approver,
            "grant",
            json!({
                "requestId": id,
                "decision": "approve",
                "sessionKey": k_b.did(),
                "approverKey": k_a.did(),
                "origin": BASE_URL,
                "contextDigest": vti_oob_server::context_digest(&step2).unwrap(),
                "sessionEndsAt": (Utc::now() + Duration::hours(1)).to_rfc3339(),
                "signingScope": scope,
            }),
            None,
            ASSERTION_METHOD,
        )
        .await;
    let responded = net
        .post(
            &net.oob(
                &k_a,
                "respond",
                json!({ "grant": grant }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    assert_eq!(ok(&responded)["status"], "approved", "{responded:#}");
    let redeemed = net
        .post(
            &net.oob(
                k_b,
                "redeem",
                json!({ "requestId": id }),
                None,
                AUTHENTICATION,
            )
            .await,
        )
        .await;
    ok(&redeemed);
}

/// The landing page's Invite tab: an administrator's browser key lists a community and reads
/// it back; a member's browser key, under the same scope, lists no one.
#[tokio::test]
async fn an_administrators_page_key_invites_and_a_members_does_not() {
    vti_oob_server::set_redeem_hold_for_tests(std::time::Duration::from_millis(100));
    let net = network().await;
    let msf = Identity::generate();
    joins(&net, &msf).await;

    let admin_key = Identity::generate();
    sign_in(&net, &admin_key, &net.operator).await;
    let invited = Identity::generate();
    let created = net
        .task::<specs::listings::create::v0_1::Payload>(
            &admin_key,
            json!({ "did": invited.did(), "kind": "community", "label": "Westmead" }),
        )
        .await;
    assert_eq!(ok(&created)["entry"]["state"], "listed", "{created:#}");
    let shown = net
        .task::<specs::listings::show::v0_1::Payload>(&admin_key, json!({ "did": invited.did() }))
        .await;
    assert_eq!(ok(&shown)["entry"]["label"], "Westmead");
    // Still nothing administrative beyond inviting.
    let removed = net
        .task::<specs::listings::remove::v0_1::Payload>(&admin_key, json!({ "did": invited.did() }))
        .await;
    assert_eq!(code(&removed), "permissionDenied", "{removed:#}");

    let member_key = Identity::generate();
    sign_in(&net, &member_key, &msf).await;
    let refused = net
        .task::<specs::listings::create::v0_1::Payload>(
            &member_key,
            json!({ "did": Identity::generate().did(), "kind": "community" }),
        )
        .await;
    assert_eq!(code(&refused), "permissionDenied", "{refused:#}");
}
