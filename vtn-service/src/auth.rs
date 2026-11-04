//! Sign-in. Every principal is a DID that proves control of itself (VTI-VTN-004):
//!
//! 1. `POST /v1/auth/challenge { did }` returns a single-use challenge, bound to that DID and
//!    to this network. It answers for any DID, so it does not reveal who is enrolled.
//! 2. The caller signs `{ type: "VtnAdminAuthentication", did, challenge, audience }` with a
//!    key of `did` authorised for `authentication`, and posts it to `POST /v1/auth/session`.
//!    That returns a bearer session token.
//!
//! What the session may do is its [`Role`], which is decided at sign-in:
//! - **Admin:** `did` is in `admins` (the NNM signs in this way).
//! - **Member, as an entity:** `did` is a member VTC or VTN of this network, signing in as
//!   itself.
//! - **Member, by credential:** `did` is a person (or agent) who presents, with the
//!   sign-in, a membership credential (VMC) naming them. The VMC must be issued by a
//!   community that is a member of this network. This is a community-anchored check. The
//!   holder's proof of control plus the community's grant is sufficient (DTG Core,
//!   Membership Edge Completion).
//! - **Listed:** `did` is listed but not a member. It may only fetch its own membership
//!   offer.
//!
//! Sessions and challenges are held in memory, so a restart signs everyone out.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use vti_vtn::verify::{AUTHENTICATION, KeyResolver, verify_document};

use crate::error::{ApiError, ApiResult};

pub const AUTH_DOCUMENT_TYPE: &str = "VtnAdminAuthentication";
const CHALLENGE_TTL: Duration = Duration::minutes(5);
const SESSION_TTL: Duration = Duration::hours(1);
const MAX_PENDING_CHALLENGES: usize = 10_000;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub challenge: String,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
}

/// What a session may do.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "role")]
pub enum Role {
    Admin,
    /// A member VTC or VTN, signed in as itself.
    MemberEntity,
    /// A person holding a VMC from `community`, a member of this network.
    MemberByCredential {
        community: String,
    },
    /// A listed party that is not (yet) a member.
    Listed,
}

impl Role {
    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }

    pub fn is_member(&self) -> bool {
        matches!(self, Role::MemberEntity | Role::MemberByCredential { .. })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionGrant {
    pub token: String,
    pub did: String,
    #[serde(flatten)]
    pub role: Role,
    pub expires_at: DateTime<Utc>,
}

/// A signed-in principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub did: String,
    pub role: Role,
}

/// The document a principal signs to sign in.
pub fn authentication_document(did: &str, challenge: &Challenge) -> Value {
    serde_json::json!({
        "type": AUTH_DOCUMENT_TYPE,
        "did": did,
        "challenge": challenge.challenge,
        "audience": challenge.audience,
    })
}

struct Pending {
    /// `None` for a browser login: the page does not know who will sign.
    did: Option<String>,
    /// The browser login this challenge belongs to, if any.
    login: Option<String>,
    expires_at: DateTime<Utc>,
}

/// A browser login waiting for a wallet to sign its challenge (A13).
struct Login {
    poll_secret: String,
    expires_at: DateTime<Utc>,
    grant: Option<SessionGrant>,
}

/// What the page needs to hand a sign-in to a wallet.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoginStart {
    pub login: String,
    /// Only the page that started the login can collect its session.
    pub poll_secret: String,
    pub challenge: String,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
}

/// A browser login's progress.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum LoginStatus {
    Pending,
    Complete { session: SessionGrant },
}

struct Session {
    principal: Principal,
    expires_at: DateTime<Utc>,
}

pub struct Auth {
    network_did: String,
    admins: Vec<String>,
    resolver: Arc<dyn KeyResolver>,
    challenges: Mutex<HashMap<String, Pending>>,
    sessions: Mutex<HashMap<String, Session>>,
    logins: Mutex<HashMap<String, Login>>,
}

impl Auth {
    pub fn new(network_did: String, admins: Vec<String>, resolver: Arc<dyn KeyResolver>) -> Self {
        Self {
            network_did,
            admins,
            resolver,
            challenges: Mutex::default(),
            sessions: Mutex::default(),
            logins: Mutex::default(),
        }
    }

    pub fn admins(&self) -> &[String] {
        &self.admins
    }

    pub fn is_admin(&self, did: &str) -> bool {
        self.admins.iter().any(|a| a == did)
    }

    pub async fn challenge(&self, did: &str) -> ApiResult<Challenge> {
        if !did.starts_with("did:") {
            return Err(ApiError::BadRequest(format!("{did:?} is not a DID")));
        }
        let now = Utc::now();
        let mut challenges = self.challenges.lock().await;
        challenges.retain(|_, p| p.expires_at > now);
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            return Err(ApiError::BadRequest("too many pending challenges".into()));
        }
        let challenge = random_token();
        let expires_at = now + CHALLENGE_TTL;
        challenges.insert(
            challenge.clone(),
            Pending {
                did: Some(did.to_string()),
                login: None,
                expires_at,
            },
        );
        Ok(Challenge {
            challenge,
            audience: self.network_did.clone(),
            expires_at,
        })
    }

    /// Start a browser login: a challenge any DID may sign, and a poll secret for the page.
    pub async fn start_login(&self) -> ApiResult<LoginStart> {
        let now = Utc::now();
        let mut challenges = self.challenges.lock().await;
        challenges.retain(|_, p| p.expires_at > now);
        let mut logins = self.logins.lock().await;
        logins.retain(|_, l| l.expires_at > now);
        if challenges.len() >= MAX_PENDING_CHALLENGES || logins.len() >= MAX_PENDING_CHALLENGES {
            return Err(ApiError::BadRequest("too many pending sign-ins".into()));
        }
        let (login, poll_secret, challenge) = (random_token(), random_token(), random_token());
        let expires_at = now + CHALLENGE_TTL;
        challenges.insert(
            challenge.clone(),
            Pending {
                did: None,
                login: Some(login.clone()),
                expires_at,
            },
        );
        logins.insert(
            login.clone(),
            Login {
                poll_secret: poll_secret.clone(),
                expires_at,
                grant: None,
            },
        );
        Ok(LoginStart {
            login,
            poll_secret,
            challenge,
            audience: self.network_did.clone(),
            expires_at,
        })
    }

    /// The page collects its login. A completed login is handed over once.
    pub async fn poll_login(&self, login: &str, poll_secret: &str) -> ApiResult<LoginStatus> {
        let mut logins = self.logins.lock().await;
        let entry = logins.get(login).ok_or(ApiError::Unauthorized)?;
        if !constant_time_eq(entry.poll_secret.as_bytes(), poll_secret.as_bytes())
            || entry.expires_at <= Utc::now()
        {
            return Err(ApiError::Unauthorized);
        }
        match &entry.grant {
            None => Ok(LoginStatus::Pending),
            Some(_) => {
                let grant = logins.remove(login).and_then(|l| l.grant).expect("checked");
                Ok(LoginStatus::Complete { session: grant })
            }
        }
    }

    /// Attach a session opened for a browser login to that login.
    pub async fn complete_login(&self, login: &str, grant: &SessionGrant) {
        if let Some(entry) = self.logins.lock().await.get_mut(login) {
            entry.grant = Some(grant.clone());
        }
    }

    /// Check a signed sign-in document: the challenge is live (and bound to its DID, unless
    /// it is a browser login's), and the DID signed it for `authentication`. Returns the DID
    /// and the browser login it completes, if any; the caller decides the role.
    pub async fn verify_sign_in(&self, document: &Value) -> ApiResult<(String, Option<String>)> {
        let field = |name: &str| {
            document
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::BadRequest(format!("authentication has no `{name}`")))
        };
        if field("type")? != AUTH_DOCUMENT_TYPE {
            return Err(ApiError::BadRequest(format!(
                "expected a {AUTH_DOCUMENT_TYPE}"
            )));
        }
        let did = field("did")?;
        let challenge = field("challenge")?;
        if field("audience")? != self.network_did {
            return Err(ApiError::Unauthorized);
        }
        // Single use: taken before verification, so a failed attempt burns it.
        let pending = self
            .challenges
            .lock()
            .await
            .remove(challenge)
            .ok_or(ApiError::Unauthorized)?;
        if pending.did.as_deref().is_some_and(|d| d != did) || pending.expires_at <= Utc::now() {
            return Err(ApiError::Unauthorized);
        }
        verify_document(document, did, AUTHENTICATION, self.resolver.as_ref())
            .await
            .map_err(|e| {
                tracing::info!(did, error = %e, "sign-in refused");
                ApiError::Unauthorized
            })?;
        Ok((did.to_string(), pending.login))
    }

    pub async fn open_session(&self, principal: Principal) -> SessionGrant {
        let token = random_token();
        let now = Utc::now();
        let expires_at = now + SESSION_TTL;
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, s| s.expires_at > now);
        sessions.insert(
            token.clone(),
            Session {
                principal: principal.clone(),
                expires_at,
            },
        );
        tracing::info!(did = %principal.did, role = ?principal.role, "signed in");
        SessionGrant {
            token,
            did: principal.did,
            role: principal.role,
            expires_at,
        }
    }

    /// The principal a bearer token belongs to. An admin session ends as soon as its DID
    /// leaves `admins`.
    pub async fn principal(&self, token: &str) -> ApiResult<Principal> {
        let sessions = self.sessions.lock().await;
        match sessions.get(token) {
            Some(s)
                if s.expires_at > Utc::now()
                    && (!s.principal.role.is_admin() || self.is_admin(&s.principal.did)) =>
            {
                Ok(s.principal.clone())
            }
            _ => Err(ApiError::Unauthorized),
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    crate::hex(&bytes)
}
