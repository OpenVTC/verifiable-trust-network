//! An authenticated client for one VTN.

use anyhow::Context;
use serde_json::{Value, json};
use vtn_core::identity::Identity;
use vtn_core::verify::AUTHENTICATION;

pub struct VtnClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl VtnClient {
    pub fn new(base: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    /// The network's public profile (`/.well-known/vtn`).
    pub async fn profile(&self) -> anyhow::Result<Value> {
        self.get("/.well-known/vtn").await
    }

    /// Sign in as `admin` to the network `network_did`: challenge, sign for
    /// `authentication`, exchange for a session. The signed document names `network_did` as
    /// its audience, never what the server claims, so a sign-in cannot be relayed to another
    /// network.
    pub async fn sign_in(&mut self, admin: &Identity, network_did: &str) -> anyhow::Result<()> {
        let challenge = self
            .post("/v1/auth/challenge", &json!({ "did": admin.did() }))
            .await?;
        if challenge["audience"].as_str() != Some(network_did) {
            anyhow::bail!(
                "the challenge is for {}, not {network_did}",
                challenge["audience"]
            );
        }
        let document = json!({
            "type": "VtnAdminAuthentication",
            "did": admin.did(),
            "challenge": challenge["challenge"],
            "audience": network_did,
        });
        let document = admin
            .sign_document_for(document, AUTHENTICATION)
            .await
            .map_err(|e| anyhow::anyhow!("sign the authentication: {e}"))?;
        let grant = self
            .post("/v1/auth/session", &json!({ "authentication": document }))
            .await
            .with_context(|| {
                format!(
                    "{} refused the sign-in: is {} in the network's `admins`?",
                    self.base,
                    admin.did()
                )
            })?;
        self.token = Some(
            grant["token"]
                .as_str()
                .context("the network answered with no session token")?
                .to_string(),
        );
        Ok(())
    }

    /// The session token, once signed in.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.send(self.http.get(self.url(path))).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        self.send(self.http.post(self.url(path)).json(body)).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, mut req: reqwest::RequestBuilder) -> anyhow::Result<Value> {
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.context("request to the network failed")?;
        let status = res.status();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let message = body["message"].as_str().unwrap_or("no message");
            anyhow::bail!("{status}: {message}");
        }
        Ok(body)
    }
}

/// Percent-encode a DID for a path segment (DIDs carry `:` and may carry `%`).
pub fn encode_did(did: &str) -> String {
    did.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Percent-encode a query-string value.
pub fn encode_query(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_dids_and_queries() {
        assert_eq!(
            encode_did("did:webvh:Qm%41:x.org"),
            "did:webvh:Qm%2541:x.org"
        );
        assert_eq!(encode_query("new zealand&x"), "new%20zealand%26x");
    }
}
