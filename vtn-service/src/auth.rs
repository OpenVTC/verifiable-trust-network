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
use vtn_core::verify::{AUTHENTICATION, KeyResolver, verify_document};

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
    did: String,
    expires_at: DateTime<Utc>,
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
}

impl Auth {
    pub fn new(network_did: String, admins: Vec<String>, resolver: Arc<dyn KeyResolver>) -> Self {
        Self {
            network_did,
            admins,
            resolver,
            challenges: Mutex::default(),
            sessions: Mutex::default(),
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
                did: did.to_string(),
                expires_at,
            },
        );
        Ok(Challenge {
            challenge,
            audience: self.network_did.clone(),
            expires_at,
        })
    }

    /// Check a signed sign-in document: the challenge is live and bound to its DID, and the
    /// DID signed it for `authentication`. Returns the DID; the caller decides the role.
    pub async fn verify_sign_in(&self, document: &Value) -> ApiResult<String> {
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
        if pending.did != did || pending.expires_at <= Utc::now() {
            return Err(ApiError::Unauthorized);
        }
        verify_document(document, did, AUTHENTICATION, self.resolver.as_ref())
            .await
            .map_err(|e| {
                tracing::info!(did, error = %e, "sign-in refused");
                ApiError::Unauthorized
            })?;
        Ok(did.to_string())
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

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    crate::hex(&bytes)
}
