//! Network rooms and their passes (see `vti_vtn::rooms`).
//!
//! **Assumption A17:** the network issues room passes. Hosting the room is a room host's job
//! (`vti-rooms` / `room-host`, with the room owned by the network's DID), and that host
//! honours a pass as a VAC rooted at the network. The chain links a person presents are
//! handed to them by their community. The person asks with `vtn/rooms/pass`, signed by
//! themselves: the signer is the holder the pass names.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_vtn::CredentialState;
use vti_vtn::VtnError;
use vti_vtn::groups::network_group_id;
use vti_vtn::rooms::{self, ChainLink, MAX_CHAIN};

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
pub struct RoomPass {
    pub room: RoomDef,
    pub pass: Value,
    /// The networks the evidence passed through, from the holder's group up.
    pub via: Vec<String>,
}

/// The holder or their membership does not qualify.
fn not_eligible(why: impl Into<String>) -> ApiError {
    ApiError::coded("notEligible", why)
}

/// The chain of group evidence does not hold.
fn chain_invalid(why: impl Into<String>) -> ApiError {
    ApiError::coded("chainInvalid", why)
}

impl Network {
    pub fn rooms(&self) -> &[RoomDef] {
        &self.settings.rooms
    }

    /// A credential's status is valid. Revoked, suspended or indeterminate fails
    /// (VTI-REG-012).
    async fn status_ok(&self, credential: &Value, what: &str) -> Result<(), String> {
        match self.status.check(credential).await {
            Ok(CredentialState::Valid) => Ok(()),
            Ok(state) => Err(format!("{what} is {state:?}")),
            Err(e) => Err(format!("{what}'s status is indeterminate: {e}")),
        }
    }

    /// Issue a pass for `room_id` to `holder`, the request's signer, on the evidence they
    /// present: `membership` (their group's VMC naming them) and `chain`, the links from that
    /// group up to a group registered here, nearest first.
    pub async fn room_pass(
        &self,
        room_id: &str,
        holder: &str,
        membership: &Value,
        chain: &[ChainLink],
    ) -> ApiResult<RoomPass> {
        let room = self
            .rooms()
            .iter()
            .find(|r| r.id == room_id)
            .cloned()
            .ok_or_else(|| ApiError::coded("unknownRoom", format!("no room {room_id}")))?;
        let now = Utc::now();
        let mut group =
            rooms::verify_group_membership(membership, holder, self.resolver.as_ref(), now)
                .await
                .map_err(|e| not_eligible(e.to_string()))?;
        self.status_ok(membership, "the membership credential")
            .await
            .map_err(not_eligible)?;

        let mut via = Vec::new();
        let mut links = chain.iter();
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
                    return Err(not_eligible("the group's member is not a current member"));
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
            let link = links.next().ok_or_else(|| {
                not_eligible("the evidence does not reach a group registered here")
            })?;
            let verified = rooms::verify_link(link, self.resolver.as_ref(), now)
                .await
                .map_err(|e| chain_invalid(e.to_string()))?;
            if verified.group != group {
                return Err(chain_invalid("the chain is out of order"));
            }
            self.status_ok(&link.acceptance, "a group acceptance")
                .await
                .map_err(chain_invalid)?;
            via.push(verified.network.clone());
            group = network_group_id(&verified.network, &verified.role);
        }
        Err(chain_invalid("the chain is too long"))
    }
}
