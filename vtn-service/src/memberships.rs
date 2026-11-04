//! This network as a member of other networks (nesting, VTI-VTN-030).
//!
//! When a parent network lists this one, this network's admins decide, through the NNM,
//! to acknowledge, repudiate, or later leave. Each step is signed by this network's own
//! identity, its VTA-provisioned DID:
//!
//! 1. Sign in to the parent as this network (the parent sees a listed party).
//! 2. Read this network's entry there, and verify the listing is the parent's.
//! 3. Register this network's **network group** for each role the parent requires (and
//!    any others asked for). Deliveries for the parent's role then come to this network's
//!    relay endpoint, which passes them on to its own members' groups.
//! 4. Acknowledge the parent's membership offer. Then verify the grant the parent signs:
//!    issued by the parent, naming this network, and matching the acknowledgement.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_vtn::VtnError;
use vti_vtn::credentials::member;
use vti_vtn::groups::{self, network_group_id};
use vti_vtn::model::EntryKind;
use vti_vtn::verify::verify_signed_by;
use vti_vtn::vocab::LISTS_V1;
use vti_vtn::{VtnClient, encode_did};

use crate::error::{ApiError, ApiResult};
use crate::network::Network;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MembershipState {
    Acknowledged,
    Repudiated,
    Departed,
}

/// This network's group registered for one of the parent's roles.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamGroup {
    pub parent_role: String,
    pub local_role: String,
    pub group: String,
    pub registration: Value,
    pub acceptance: Value,
}

/// This network's membership of a parent network.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub parent: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    pub state: MembershipState,
    pub listing: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repudiation: Option<Value>,
    #[serde(default)]
    pub groups: Vec<UpstreamGroup>,
    pub updated_at: DateTime<Utc>,
}

/// A parent role this network serves with one of its own roles.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoleMapping {
    pub parent_role: String,
    pub local_role: String,
}

fn rejected(why: impl Into<String>) -> ApiError {
    ApiError::Vtn(VtnError::Rejected(why.into()))
}

fn peer(e: vti_vtn::ClientError) -> ApiError {
    ApiError::Upstream(e.to_string())
}

/// Allow for clock skew between networks on what we sign.
fn signing_time() -> DateTime<Utc> {
    Utc::now() - Duration::seconds(30)
}

impl Network {
    pub async fn memberships(&self) -> ApiResult<Vec<Membership>> {
        Ok(self.store.memberships().await?)
    }

    pub async fn membership(&self, parent: &str) -> ApiResult<Membership> {
        self.store
            .membership(parent)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("not a member of {parent}")))
    }

    /// Sign in to the network at `url` as this network.
    async fn parent_session(&self, url: &str) -> ApiResult<(VtnClient, String, Value)> {
        let mut client = self.client(url);
        let profile = client.profile().await.map_err(peer)?;
        let parent = profile["did"]
            .as_str()
            .ok_or_else(|| rejected(format!("{url} names no DID")))?
            .to_string();
        if parent == self.did() {
            return Err(rejected("a network cannot be a member of itself"));
        }
        client
            .sign_in(&self.identity, &parent, None)
            .await
            .map_err(|e| match e.status() {
                Some(401) => rejected(format!("{parent} does not list this network")),
                _ => peer(e),
            })?;
        Ok((client, parent, profile))
    }

    /// Our entry at the parent, with its listing verified as the parent's.
    async fn own_listing(&self, client: &VtnClient, parent: &str) -> ApiResult<Value> {
        let entry = client
            .get(&format!("/v1/entries/{}", encode_did(self.did())))
            .await
            .map_err(peer)?;
        let listing = entry["listing"].clone();
        let vsc = verify_signed_by(&listing, parent, self.resolver.as_ref(), Utc::now()).await?;
        if vsc.subject() != self.did() || vsc.predicate() != Some(LISTS_V1) {
            return Err(rejected("the parent's listing does not list this network"));
        }
        if listing["credentialSubject"]["object"]["value"]["nodeType"].as_str()
            != Some(EntryKind::Network.node_type())
        {
            return Err(rejected(
                "the parent's listing does not list this party as a network",
            ));
        }
        Ok(listing)
    }

    /// Register this network's group for `local_role` to serve the parent's `parent_role`.
    async fn register_upstream(
        &self,
        client: &VtnClient,
        parent: &str,
        mapping: &RoleMapping,
    ) -> ApiResult<UpstreamGroup> {
        if self.role(&mapping.local_role).is_none() {
            return Err(rejected(format!(
                "this network defines no role {:?} to serve {:?} with",
                mapping.local_role, mapping.parent_role
            )));
        }
        let group = network_group_id(self.did(), &mapping.local_role);
        let endpoint = format!("{}/v1/relay/{}", self.base_url, mapping.local_role);
        let registration = groups::register(
            &self.identity,
            parent,
            &mapping.parent_role,
            &group,
            &endpoint,
        )
        .await?;
        let accepted = client
            .post(
                &format!("/v1/entries/{}/groups", encode_did(self.did())),
                &json!({ "registration": registration }),
            )
            .await
            .map_err(peer)?;
        let acceptance = accepted["acceptance"]["credential"].clone();
        verify_signed_by(&acceptance, parent, self.resolver.as_ref(), Utc::now()).await?;
        Ok(UpstreamGroup {
            parent_role: mapping.parent_role.clone(),
            local_role: mapping.local_role.clone(),
            group,
            registration,
            acceptance,
        })
    }

    /// Accept a parent network's listing of this one.
    ///
    /// `roles` maps parent roles to this network's roles. Any role the parent requires that
    /// is not mapped is served by this network's role of the same name.
    pub async fn join(
        &self,
        url: &str,
        roles: Vec<RoleMapping>,
        actor: &str,
    ) -> ApiResult<Membership> {
        let url = url.trim_end_matches('/');
        let (client, parent, profile) = self.parent_session(url).await?;
        let listing = self.own_listing(&client, &parent).await?;

        let mut mappings = roles;
        for required in profile["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["required"] == true)
            .filter_map(|r| r["name"].as_str())
        {
            if !mappings.iter().any(|m| m.parent_role == required) {
                mappings.push(RoleMapping {
                    parent_role: required.to_string(),
                    local_role: required.to_string(),
                });
            }
        }
        let mut upstream = Vec::new();
        for mapping in &mappings {
            upstream.push(self.register_upstream(&client, &parent, mapping).await?);
        }

        let offer = client
            .get(&format!("/v1/entries/{}/offer", encode_did(self.did())))
            .await
            .map_err(peer)?;
        if offer["issuer"].as_str() != Some(parent.as_str())
            || offer["credentialSubject"]["id"].as_str() != Some(self.did())
        {
            return Err(rejected(
                "the parent's offer is not a membership of this network",
            ));
        }
        let ack = member::acknowledge(&offer, &self.identity, signing_time(), None).await?;
        let ack_json = serde_json::to_value(&ack).map_err(VtnError::from)?;
        let entry = client
            .post(
                &format!("/v1/entries/{}/acknowledge", encode_did(self.did())),
                &json!({ "acknowledgement": ack_json }),
            )
            .await
            .map_err(peer)?;
        let grant = entry["grant"].clone();
        let grant_vc =
            verify_signed_by(&grant, &parent, self.resolver.as_ref(), Utc::now()).await?;
        if grant_vc.subject() != self.did()
            || !ack.acknowledges(&grant_vc).map_err(VtnError::from)?
        {
            return Err(rejected(
                "the parent's grant does not match the acknowledgement",
            ));
        }

        let membership = Membership {
            parent: parent.clone(),
            url: url.to_string(),
            parent_name: profile["profile"]["name"].as_str().map(str::to_string),
            state: MembershipState::Acknowledged,
            listing,
            grant: Some(grant),
            acknowledgement: Some(ack_json),
            repudiation: None,
            groups: upstream,
            updated_at: Utc::now(),
        };
        self.store.put_membership(&parent, &membership).await?;
        tracing::info!(parent, actor, "joined parent network");
        Ok(membership)
    }

    /// Register (or re-register) a group with a parent this network has joined.
    pub async fn add_upstream_group(
        &self,
        parent: &str,
        mapping: RoleMapping,
    ) -> ApiResult<Membership> {
        let mut membership = self.membership(parent).await?;
        if membership.state != MembershipState::Acknowledged {
            return Err(rejected("not a current member of that network"));
        }
        let (client, _, _) = self.parent_session(&membership.url).await?;
        let group = self.register_upstream(&client, parent, &mapping).await?;
        membership
            .groups
            .retain(|g| g.parent_role != mapping.parent_role);
        membership.groups.push(group);
        membership.updated_at = Utc::now();
        self.store.put_membership(parent, &membership).await?;
        Ok(membership)
    }

    /// Leave a parent network: repudiate its grant (departure).
    pub async fn leave(&self, parent: &str, actor: &str) -> ApiResult<Membership> {
        let mut membership = self.membership(parent).await?;
        let grant = membership
            .grant
            .clone()
            .filter(|_| membership.state == MembershipState::Acknowledged)
            .ok_or_else(|| rejected("not a current member of that network"))?;
        let repudiation = member::repudiate(&grant, &self.identity, signing_time()).await?;
        let repudiation = serde_json::to_value(&repudiation).map_err(VtnError::from)?;
        self.client(&membership.url)
            .post(
                &format!("/v1/entries/{}/repudiate", encode_did(self.did())),
                &json!({ "repudiation": repudiation }),
            )
            .await
            .map_err(peer)?;
        membership.state = MembershipState::Departed;
        membership.repudiation = Some(repudiation);
        membership.updated_at = Utc::now();
        self.store.put_membership(parent, &membership).await?;
        tracing::info!(parent, actor, "left parent network");
        Ok(membership)
    }

    /// Repudiate a parent network's listing of this one (VTI-VTN-012).
    pub async fn repudiate_listing(&self, url: &str, actor: &str) -> ApiResult<Membership> {
        let url = url.trim_end_matches('/');
        let (client, parent, profile) = self.parent_session(url).await?;
        let listing = self.own_listing(&client, &parent).await?;
        let repudiation = member::repudiate(&listing, &self.identity, signing_time()).await?;
        let repudiation = serde_json::to_value(&repudiation).map_err(VtnError::from)?;
        client
            .post(
                &format!("/v1/entries/{}/repudiate", encode_did(self.did())),
                &json!({ "repudiation": repudiation }),
            )
            .await
            .map_err(peer)?;
        let membership = Membership {
            parent: parent.clone(),
            url: url.to_string(),
            parent_name: profile["profile"]["name"].as_str().map(str::to_string),
            state: MembershipState::Repudiated,
            listing,
            grant: None,
            acknowledgement: None,
            repudiation: Some(repudiation),
            groups: Vec::new(),
            updated_at: Utc::now(),
        };
        self.store.put_membership(&parent, &membership).await?;
        tracing::info!(parent, actor, "repudiated a parent network's listing");
        Ok(membership)
    }

    /// The local role a delivery from `parent` to `group` is for: `Some` only if this network
    /// is a current member of `parent` and registered `group` with it.
    pub(crate) async fn upstream_role(
        &self,
        parent: &str,
        group: &str,
    ) -> ApiResult<Option<String>> {
        Ok(self
            .store
            .membership::<Membership>(parent)
            .await?
            .filter(|m| m.state == MembershipState::Acknowledged)
            .and_then(|m| {
                m.groups
                    .into_iter()
                    .find(|g| g.group == group)
                    .map(|g| g.local_role)
            }))
    }
}
