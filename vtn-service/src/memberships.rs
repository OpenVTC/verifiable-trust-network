//! This network as a member of other networks (nesting, VTI-VTN-030).
//!
//! When a parent network lists this one, this network's admins decide, through the NNM,
//! to acknowledge, repudiate, or later leave. Each step is signed by this network's own
//! identity, its VTA-provisioned DID:
//!
//! Every request to the parent is a `vtn/*` Trust Task signed by this network, so the parent
//! sees a listed party. There is no sign-in.
//!
//! 1. Read the parent's profile at `url`; its DID must be the network the admin named.
//! 2. Read this network's entry there (`vtn/entries/show`), and verify the listing is the
//!    parent's.
//! 3. Register this network's **network group** for each role the parent requires (and
//!    any others asked for), with `vtn/groups/register`. Deliveries for the parent's role
//!    then come to this network as `vtn/relay/deliver`, which passes them on to its own
//!    members' groups.
//! 4. Acknowledge the parent's membership offer (`vtn/membership/offer`, then
//!    `vtn/membership/acknowledge`). Then verify the grant the parent signs: issued by the
//!    parent, naming this network, and matching the acknowledgement.

use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::RequestPayload;
use vti_specs_vtn::vtn::entries::show::v0_1 as entries_show;
use vti_specs_vtn::vtn::membership::{
    acknowledge::v0_1 as acknowledge, offer::v0_1 as offer, repudiate::v0_1 as repudiate,
};
use vti_vtn::VtnError;
use vti_vtn::credentials::member;
use vti_vtn::groups::{self, network_group_id};
use vti_vtn::model::EntryKind;
use vti_vtn::tasks::TRUST_TASKS_PATH;
use vti_vtn::verify::verify_signed_by;
use vti_vtn::vocab::LISTS_V1;
use vti_vtn::{ClientError, VtnClient};

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

/// The parent refused, or could not be reached.
fn peer(e: ClientError) -> ApiError {
    ApiError::Upstream(e.to_string())
}

/// Allow for clock skew between networks on what we sign.
fn signing_time() -> DateTime<Utc> {
    Utc::now() - Duration::seconds(30)
}

/// A `vtn/*` payload from its JSON.
fn payload<P: DeserializeOwned>(json: Value) -> ApiResult<P> {
    serde_json::from_value(json).map_err(|e| ApiError::BadRequest(e.to_string()))
}

impl Network {
    pub async fn memberships(&self) -> ApiResult<Vec<Membership>> {
        Ok(self.store.memberships().await?)
    }

    pub async fn membership(&self, parent: &str) -> ApiResult<Membership> {
        self.store
            .membership(parent)
            .await?
            .ok_or_else(|| ApiError::coded("notMember", format!("not a member of {parent}")))
    }

    /// The network at `url`, which must be `network`: its client and profile.
    async fn parent_at(&self, url: &str, network: &str) -> ApiResult<(VtnClient, Value)> {
        if network == self.did() {
            return Err(rejected("a network cannot be a member of itself"));
        }
        let client = self.client(url);
        let profile = client.profile().await.map_err(peer)?;
        if profile["did"].as_str() != Some(network) {
            return Err(ApiError::coded(
                "networkMismatch",
                format!("{url} answers as {}, not {network}", profile["did"]),
            ));
        }
        Ok((client, profile))
    }

    /// Send `json` as task `P` to `parent`, signed by this network.
    async fn ask<P>(&self, client: &VtnClient, parent: &str, json: Value) -> ApiResult<Value>
    where
        P: RequestPayload + DeserializeOwned,
        P::Response: serde::Serialize,
    {
        let answer = client
            .task(&self.identity, parent, &payload::<P>(json)?)
            .await
            .map_err(peer)?;
        Ok(serde_json::to_value(answer).map_err(VtnError::from)?)
    }

    /// Our entry at the parent, with its listing verified as the parent's.
    async fn own_listing(&self, client: &VtnClient, parent: &str) -> ApiResult<Value> {
        let answer = self
            .ask::<entries_show::Payload>(client, parent, json!({ "did": self.did() }))
            .await
            .map_err(|e| match e {
                ApiError::Upstream(m) => ApiError::coded(
                    "notListed",
                    format!("{parent} does not list this network: {m}"),
                ),
                other => other,
            })?;
        let listing = answer["entry"]["listing"].clone();
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
            return Err(ApiError::coded(
                "unknownRole",
                format!(
                    "this network defines no role {:?} to serve {:?} with",
                    mapping.local_role, mapping.parent_role
                ),
            ));
        }
        let group = network_group_id(self.did(), &mapping.local_role);
        // Deliveries come here as `vtn/relay/deliver`.
        let endpoint = format!("{}{TRUST_TASKS_PATH}", self.base_url);
        let registration = groups::register(
            &self.identity,
            parent,
            &mapping.parent_role,
            &group,
            &endpoint,
        )
        .await?;
        let accepted: Value = client
            .send_request(&registration, parent)
            .await
            .map_err(peer)?;
        let acceptance = accepted["group"]["acceptance"].clone();
        verify_signed_by(&acceptance, parent, self.resolver.as_ref(), Utc::now()).await?;
        Ok(UpstreamGroup {
            parent_role: mapping.parent_role.clone(),
            local_role: mapping.local_role.clone(),
            group,
            registration,
            acceptance,
        })
    }

    /// Accept the listing of this network by `network`, reached at `url`.
    ///
    /// `roles` maps parent roles to this network's roles. Any role the parent requires that
    /// is not mapped is served by this network's role of the same name.
    pub async fn join(
        &self,
        url: &str,
        network: &str,
        roles: Vec<RoleMapping>,
        actor: &str,
    ) -> ApiResult<Membership> {
        let url = url.trim_end_matches('/');
        let (client, profile) = self.parent_at(url, network).await?;
        let parent = network.to_string();
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
            let group = self
                .register_upstream(&client, &parent, mapping)
                .await
                .map_err(|e| match e {
                    ApiError::Coded {
                        local: "unknownRole",
                        message,
                        details,
                    } => ApiError::Coded {
                        local: "roleUnassigned",
                        message,
                        details,
                    },
                    other => other,
                })?;
            upstream.push(group);
        }

        let offer = self
            .ask::<offer::Payload>(&client, &parent, json!({}))
            .await?["offer"]
            .clone();
        if offer["issuer"].as_str() != Some(parent.as_str())
            || offer["credentialSubject"]["id"].as_str() != Some(self.did())
        {
            return Err(rejected(
                "the parent's offer is not a membership of this network",
            ));
        }
        let ack = member::acknowledge(&offer, &self.identity, signing_time(), None).await?;
        let ack_json = serde_json::to_value(&ack).map_err(VtnError::from)?;
        let answer = self
            .ask::<acknowledge::Payload>(&client, &parent, json!({ "acknowledgement": ack_json }))
            .await?;
        let grant = answer["entry"]["grant"].clone();
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
            return Err(ApiError::coded(
                "notMember",
                "not a current member of that network",
            ));
        }
        let (client, _) = self.parent_at(&membership.url, parent).await?;
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
            .ok_or_else(|| ApiError::coded("notMember", "not a current member of that network"))?;
        let repudiation = member::repudiate(&grant, &self.identity, signing_time()).await?;
        let repudiation = serde_json::to_value(&repudiation).map_err(VtnError::from)?;
        let client = self.client(&membership.url);
        self.ask::<repudiate::Payload>(&client, parent, json!({ "repudiation": repudiation }))
            .await?;
        membership.state = MembershipState::Departed;
        membership.repudiation = Some(repudiation);
        membership.updated_at = Utc::now();
        self.store.put_membership(parent, &membership).await?;
        tracing::info!(parent, actor, "left parent network");
        Ok(membership)
    }

    /// Repudiate the listing of this network by `network`, reached at `url` (VTI-VTN-012).
    pub async fn repudiate_listing(
        &self,
        url: &str,
        network: &str,
        actor: &str,
    ) -> ApiResult<Membership> {
        let url = url.trim_end_matches('/');
        let (client, profile) = self.parent_at(url, network).await?;
        let parent = network.to_string();
        let listing = self.own_listing(&client, &parent).await?;
        let repudiation = member::repudiate(&listing, &self.identity, signing_time()).await?;
        let repudiation = serde_json::to_value(&repudiation).map_err(VtnError::from)?;
        self.ask::<repudiate::Payload>(&client, &parent, json!({ "repudiation": repudiation }))
            .await?;
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
