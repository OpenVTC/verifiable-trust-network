//! Network rooms and their passes (see `vtn_core::rooms`).
//!
//! **Assumption A17:** the network issues room passes. Hosting the room is a room host's job
//! (`vti-rooms` / `room-host`, with the room owned by the network's DID), and that host
//! honours a pass as a VAC rooted at the network. The chain links a person presents are
//! handed to them by their community. The person's sign-in challenge comes from
//! `/v1/auth/challenge`.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vtn_client::CredentialState;
use vtn_core::VtnError;
use vtn_core::groups::network_group_id;
use vtn_core::rooms::{self, ChainLink, MAX_CHAIN};

use crate::error::{ApiError, ApiResult};
use crate::network::Network;

/// A room the network opens for a role.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RoomDef {
    pub id: String,
    pub name: String,
    /// Everyone in a group registered (directly or through member networks) for this role.
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Where the room is hosted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How long a pass lasts.
    #[serde(default = "default_pass_minutes")]
    pub pass_minutes: i64,
}

fn default_pass_minutes() -> i64 {
    60
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PassRequest {
    /// The holder's signed sign-in document (challenge from `/v1/auth/challenge`).
    pub authentication: Value,
    /// The holder's membership credential from their group.
    pub membership: Value,
    /// Links from that group up to a group registered here, nearest first.
    #[serde(default)]
    pub chain: Vec<ChainLink>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoomPass {
    pub room: RoomDef,
    pub pass: Value,
    /// The networks the evidence passed through, from the holder's group up.
    pub via: Vec<String>,
}

fn refuse(why: impl Into<String>) -> ApiError {
    ApiError::Vtn(VtnError::Rejected(why.into()))
}

impl Network {
    pub fn rooms(&self) -> &[RoomDef] {
        &self.settings.rooms
    }

    async fn status_ok(&self, credential: &Value, what: &str) -> ApiResult<()> {
        match self.status.check(credential).await {
            Ok(CredentialState::Valid) => Ok(()),
            Ok(state) => Err(refuse(format!("{what} is {state:?}"))),
            Err(e) => Err(refuse(format!("{what}'s status is indeterminate: {e}"))),
        }
    }

    /// Issue a pass for `room` to the signed-in holder, on the evidence in `request`.
    /// `holder` is the DID the request's authentication proved.
    pub async fn room_pass(
        &self,
        room_id: &str,
        holder: &str,
        request: &PassRequest,
    ) -> ApiResult<RoomPass> {
        let room = self
            .rooms()
            .iter()
            .find(|r| r.id == room_id)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(format!("no room {room_id}")))?;
        let now = Utc::now();
        let mut group = rooms::verify_group_membership(
            &request.membership,
            holder,
            self.resolver.as_ref(),
            now,
        )
        .await?;
        self.status_ok(&request.membership, "the membership credential")
            .await?;

        let mut via = Vec::new();
        let mut links = request.chain.iter();
        for _ in 0..=MAX_CHAIN {
            // Registered here, for the room's role, by a current member?
            let registered = self
                .groups(Some(&room.role))
                .await?
                .into_iter()
                .find(|g| g.group == group);
            if let Some(g) = registered {
                let current = self
                    .store
                    .entry(&g.member)
                    .await?
                    .is_some_and(|e| e.state.is_membership());
                if !current {
                    return Err(refuse("the group's member is not a current member"));
                }
                let mut pass = rooms::room_pass(
                    self.did(),
                    holder,
                    &room.id,
                    now,
                    Duration::minutes(room.pass_minutes),
                )?;
                self.identity.sign_credential(&mut pass).await?;
                tracing::info!(holder, room = %room.id, via = ?via, "room pass issued");
                return Ok(RoomPass {
                    room,
                    pass: serde_json::to_value(pass).map_err(VtnError::from)?,
                    via,
                });
            }
            // Otherwise the next link must lift this group into a network's group.
            let link = links
                .next()
                .ok_or_else(|| refuse("the evidence does not reach a group registered here"))?;
            let verified = rooms::verify_link(link, self.resolver.as_ref(), now).await?;
            if verified.group != group {
                return Err(refuse("the chain is out of order"));
            }
            self.status_ok(&link.acceptance, "a group acceptance")
                .await?;
            via.push(verified.network.clone());
            group = network_group_id(&verified.network, &verified.role);
        }
        Err(refuse("the chain is too long"))
    }
}
