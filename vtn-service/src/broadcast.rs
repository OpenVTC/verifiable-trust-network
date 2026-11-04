//! Broadcast to a role across the network, cascading through member networks.
//!
//! - **Send:** an admin sends to a role. The network signs a message and delivers it to the
//!   endpoint of every group its acknowledged members registered for that role. Each delivery
//!   carries a hop signed by this network.
//! - **Receive** (`vtn/relay/deliver`): a parent network delivers to this network's network
//!   group. The request's signer is the delivering network, and must be one this network is a
//!   current member of. The envelope is verified end to end (origin signature, hop chain, hop
//!   limit, expiry); its last hop must be the signer's, addressed to the group this network
//!   registered with it. Then it is relayed on to this network's own groups for the local
//!   role.
//!
//! Each network expands only its own groups, so no network learns another's roster. The
//! sender learns which groups accepted, counted through relays (the receipts), and never who
//! is in them.
//!
//! Delivery is HTTPS, one request per group per hop: a `vtn/relay/deliver` Trust Task, signed
//! by this network, to a member network's group (`<network DID>#role-<role>`, A14), and
//! `{ envelope }` posted to any other group's endpoint (a community's inbox, until
//! `vtc/networks` 0.2 gives communities a task for it). A delivery that fails in transport is
//! **queued** in the store and retried with exponential backoff, until it succeeds, the
//! message expires, or `relay.max_attempts` is reached. The broadcast's receipt is updated
//! as it goes. A refusal is final, and not retried.
//!
//! **Assumption A15:** retries cover this network's own deliveries; a relaying network
//! queues its own. Receipts already returned up the chain are not revised after a later
//! retry downstream. TSP/DIDComm delivery is still to come.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinSet;
use vti_specs_vtn::vtn::relay::deliver::v0_1 as specs;
use vti_vtn::VtnError;
use vti_vtn::groups::network_group_id;
use vti_vtn::identity::Identity;
use vti_vtn::relay::{self, DeliveryStatus, Envelope, Outgoing, Receipt};
use vti_vtn::{ClientError, VtnClient};

use crate::error::{ApiError, ApiResult};
use crate::network::Network;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Sent,
    Received,
}

/// A broadcast this network sent or relayed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastRecord {
    pub id: String,
    pub direction: Direction,
    /// The local role it went to.
    pub role: String,
    pub message: Value,
    /// For a received broadcast: the network that delivered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// For a sent broadcast: the admin who sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub at: DateTime<Utc>,
    pub receipts: Vec<Receipt>,
    /// Groups reached, counted through relays.
    pub reached: usize,
}

/// A delivery waiting for a retry.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OutboxItem {
    pub message_id: String,
    pub group: String,
    pub member: String,
    pub endpoint: String,
    pub envelope: Envelope,
    pub attempts: u32,
    pub next_attempt: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_error: String,
}

/// The answer to a relay delivery (`vtn/relay/deliver`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayResponse {
    pub status: DeliveryStatus,
    #[serde(default)]
    pub relayed: Vec<Receipt>,
}

fn rejected(why: impl Into<String>) -> ApiError {
    ApiError::Vtn(VtnError::Rejected(why.into()))
}

impl Network {
    /// Send `outgoing` to every group registered for its role.
    pub async fn broadcast(&self, outgoing: Outgoing, actor: &str) -> ApiResult<BroadcastRecord> {
        if self.role(&outgoing.role).is_none() {
            return Err(rejected(format!(
                "this network defines no role {:?}",
                outgoing.role
            )));
        }
        let message = relay::new_message(
            &self.identity,
            &outgoing,
            Duration::hours(self.settings.relay.ttl_hours),
            Utc::now(),
        )
        .await?;
        let id = message["id"].as_str().unwrap_or_default().to_string();
        // Marked seen, so a copy routed back here through a cycle is a duplicate.
        self.store.first_sighting(&id).await?;
        let receipts = self.fan_out(&message, Vec::new(), &outgoing.role).await?;
        let record = BroadcastRecord {
            id: id.clone(),
            direction: Direction::Sent,
            role: outgoing.role,
            message,
            from: None,
            actor: Some(actor.to_string()),
            at: Utc::now(),
            reached: receipts.iter().map(Receipt::reached).sum(),
            receipts,
        };
        self.store.put_broadcast(&id, &record).await?;
        tracing::info!(id, role = %record.role, reached = record.reached, actor, "broadcast sent");
        Ok(record)
    }

    /// `from`, the request's signer, delivers to this network's group for `local_role`.
    pub async fn receive(
        &self,
        from: &str,
        local_role: &str,
        envelope: Envelope,
    ) -> ApiResult<RelayResponse> {
        if !self.settings.relay.accept {
            return Err(ApiError::Forbidden);
        }
        let joined = self
            .store
            .membership::<crate::memberships::Membership>(from)
            .await?
            .is_some_and(|m| m.state == crate::memberships::MembershipState::Acknowledged);
        if !joined {
            return Err(ApiError::coded(
                "notMember",
                format!("{from} is not a network this one is a member of"),
            ));
        }
        if self.role(local_role).is_none() {
            return Err(ApiError::coded(
                "unknownRole",
                format!("this network defines no role {local_role:?}"),
            ));
        }
        let invalid = |why: String| ApiError::coded("envelopeInvalid", why);
        let verified = relay::verify(
            &envelope,
            self.resolver.as_ref(),
            Utc::now(),
            self.settings.relay.max_hops,
        )
        .await
        .map_err(|e| invalid(e.to_string()))?;
        if verified.from != from {
            return Err(invalid(format!(
                "the envelope's last hop is {}'s, not the deliverer's",
                verified.from
            )));
        }
        let group = network_group_id(self.did(), local_role);
        if verified.to != group {
            return Err(invalid(
                "the envelope is not addressed to this network's group".into(),
            ));
        }
        if self.upstream_role(from, &group).await?.as_deref() != Some(local_role) {
            return Err(ApiError::coded(
                "unknownRole",
                format!("this network did not register {group} with {from}"),
            ));
        }
        if !self.store.first_sighting(&verified.id).await? {
            return Ok(RelayResponse {
                status: DeliveryStatus::Duplicate,
                relayed: Vec::new(),
            });
        }
        let receipts = self
            .fan_out(&envelope.message, envelope.hops.clone(), local_role)
            .await?;
        let record = BroadcastRecord {
            id: verified.id.clone(),
            direction: Direction::Received,
            role: local_role.to_string(),
            message: envelope.message,
            from: Some(verified.from.clone()),
            actor: None,
            at: Utc::now(),
            reached: receipts.iter().map(Receipt::reached).sum(),
            receipts: receipts.clone(),
        };
        self.store.put_broadcast(&verified.id, &record).await?;
        tracing::info!(
            id = %verified.id,
            origin = %verified.origin,
            from = %verified.from,
            role = local_role,
            reached = record.reached,
            "broadcast relayed"
        );
        Ok(RelayResponse {
            status: DeliveryStatus::Delivered,
            relayed: receipts,
        })
    }

    pub async fn broadcasts(&self) -> ApiResult<Vec<BroadcastRecord>> {
        let mut all: Vec<BroadcastRecord> = self.store.broadcasts().await?;
        all.sort_by_key(|b| std::cmp::Reverse(b.at));
        Ok(all)
    }

    pub async fn broadcast_record(&self, id: &str) -> ApiResult<BroadcastRecord> {
        self.store
            .broadcast(id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("no broadcast {id}")))
    }

    /// Deliver `message` to every current member's group for `role`, each with a new hop.
    async fn fan_out(
        &self,
        message: &Value,
        hops: Vec<Value>,
        role: &str,
    ) -> ApiResult<Vec<Receipt>> {
        let id = message["id"].as_str().unwrap_or_default().to_string();
        let mut set = JoinSet::new();
        for group in self.groups(Some(role)).await? {
            // Only current members are delivered to; a suspended member's groups wait.
            let current = self
                .store
                .entry(&group.member)
                .await?
                .is_some_and(|e| e.state.is_membership());
            if !current {
                continue;
            }
            if hops.len() + 1 > self.settings.relay.max_hops {
                set.spawn(async move {
                    (
                        Receipt {
                            group: group.group,
                            member: group.member,
                            status: DeliveryStatus::Refused,
                            detail: Some("hop limit reached".into()),
                            network: false,
                            relayed: Vec::new(),
                        },
                        None,
                    )
                });
                continue;
            }
            let identity: Identity = self.identity.clone();
            let client = self.client("");
            let (message, mut hops, id, role) =
                (message.clone(), hops.clone(), id.clone(), role.to_string());
            set.spawn(async move {
                let receipt =
                    |status, detail: Option<String>, relayed: Option<Vec<Receipt>>| Receipt {
                        group: group.group.clone(),
                        member: group.member.clone(),
                        status,
                        detail,
                        network: relayed.is_some(),
                        relayed: relayed.unwrap_or_default(),
                    };
                match relay::new_hop(&identity, &id, &group.group, &role, hops.len()).await {
                    Ok(hop) => hops.push(hop),
                    Err(e) => {
                        return (
                            receipt(DeliveryStatus::Failed, Some(e.to_string()), None),
                            None,
                        );
                    }
                }
                let envelope = Envelope { message, hops };
                let target = Target {
                    member: &group.member,
                    group: &group.group,
                    endpoint: &group.endpoint,
                };
                let r = deliver(&client, &identity, target, envelope.clone(), receipt).await;
                let retry = (r.status == DeliveryStatus::Failed)
                    .then(|| (group.endpoint.clone(), envelope));
                (r, retry)
            });
        }
        let expires_at = message["expiresAt"]
            .as_str()
            .and_then(|t| t.parse::<DateTime<Utc>>().ok())
            .unwrap_or_else(Utc::now);
        let mut receipts = Vec::new();
        while let Some(done) = set.join_next().await {
            let (mut receipt, retry) =
                done.map_err(|e| ApiError::Vtn(VtnError::Internal(e.to_string())))?;
            if let Some((endpoint, envelope)) = retry
                && self.settings.relay.max_attempts > 1
                && expires_at > Utc::now()
            {
                let item = OutboxItem {
                    message_id: id.clone(),
                    group: receipt.group.clone(),
                    member: receipt.member.clone(),
                    endpoint,
                    envelope,
                    attempts: 1,
                    next_attempt: Utc::now() + self.backoff(1),
                    expires_at,
                    last_error: receipt.detail.clone().unwrap_or_default(),
                };
                self.store.put_outbox(&id, &receipt.group, &item).await?;
                receipt.status = DeliveryStatus::Queued;
            }
            receipts.push(receipt);
        }
        receipts.sort_by(|a, b| a.group.cmp(&b.group));
        Ok(receipts)
    }
}

impl Network {
    fn backoff(&self, attempts: u32) -> Duration {
        let base = self.settings.relay.retry_base_seconds.max(1);
        Duration::seconds((base << attempts.saturating_sub(1).min(16)).min(3600))
    }

    /// Deliveries waiting for a retry.
    pub async fn outbox(&self) -> ApiResult<Vec<OutboxItem>> {
        Ok(self.store.outbox().await?)
    }

    /// Retry queued deliveries that are due (all of them with `force`). Returns how many were
    /// attempted.
    pub async fn retry_due(&self, force: bool) -> ApiResult<usize> {
        let now = Utc::now();
        let mut attempted = 0;
        for mut item in self.store.outbox::<OutboxItem>().await? {
            if !force && item.next_attempt > now {
                continue;
            }
            if item.expires_at <= now {
                self.settle(
                    &item,
                    DeliveryStatus::Failed,
                    Some("expired before delivery".into()),
                    None,
                )
                .await?;
                continue;
            }
            attempted += 1;
            let group = item.group.clone();
            let member = item.member.clone();
            let receipt = |status, detail: Option<String>, relayed: Option<Vec<Receipt>>| Receipt {
                group: group.clone(),
                member: member.clone(),
                status,
                detail,
                network: relayed.is_some(),
                relayed: relayed.unwrap_or_default(),
            };
            let target = Target {
                member: &item.member,
                group: &item.group,
                endpoint: &item.endpoint,
            };
            let r = deliver(
                &self.client(""),
                &self.identity,
                target,
                item.envelope.clone(),
                receipt,
            )
            .await;
            if r.status == DeliveryStatus::Failed {
                item.attempts += 1;
                item.last_error = r.detail.clone().unwrap_or_default();
                if item.attempts >= self.settings.relay.max_attempts {
                    let detail = format!(
                        "gave up after {} attempts: {}",
                        item.attempts, item.last_error
                    );
                    self.settle(&item, DeliveryStatus::Failed, Some(detail), None)
                        .await?;
                } else {
                    item.next_attempt = now + self.backoff(item.attempts);
                    self.store
                        .put_outbox(&item.message_id, &item.group, &item)
                        .await?;
                    self.update_receipt(&item.message_id, &item.group, |rc| {
                        rc.detail = Some(format!("attempt {}: {}", item.attempts, item.last_error));
                    })
                    .await?;
                }
            } else {
                self.settle(
                    &item,
                    r.status,
                    r.detail.clone(),
                    Some((r.network, r.relayed)),
                )
                .await?;
            }
        }
        Ok(attempted)
    }

    /// Resolve a queued delivery: remove it and record the outcome on the broadcast.
    async fn settle(
        &self,
        item: &OutboxItem,
        status: DeliveryStatus,
        detail: Option<String>,
        relayed: Option<(bool, Vec<Receipt>)>,
    ) -> ApiResult<()> {
        self.store
            .remove_outbox(&item.message_id, &item.group)
            .await?;
        self.update_receipt(&item.message_id, &item.group, |rc| {
            rc.status = status;
            rc.detail = detail.clone();
            if let Some((network, relayed)) = relayed.clone() {
                rc.network = network;
                rc.relayed = relayed;
            }
        })
        .await
    }

    async fn update_receipt(
        &self,
        message_id: &str,
        group: &str,
        change: impl FnOnce(&mut Receipt),
    ) -> ApiResult<()> {
        let _guard = self.write.lock().await;
        let Some(mut record) = self.store.broadcast::<BroadcastRecord>(message_id).await? else {
            return Ok(());
        };
        if let Some(rc) = record.receipts.iter_mut().find(|r| r.group == group) {
            change(rc);
        }
        record.reached = record.receipts.iter().map(Receipt::reached).sum();
        self.store.put_broadcast(message_id, &record).await?;
        Ok(())
    }

    /// Retry due deliveries every `every`, for the life of the process.
    pub fn spawn_retry_worker(self: &std::sync::Arc<Self>, every: std::time::Duration) {
        let network = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                if let Err(e) = network.retry_due(false).await {
                    tracing::warn!(error = %e, "delivery retry pass failed");
                }
            }
        });
    }
}

/// Where one delivery goes.
struct Target<'a> {
    member: &'a str,
    group: &'a str,
    endpoint: &'a str,
}

impl Target<'_> {
    /// The member network's local role, when the group is a network group (A14).
    fn network_role(&self) -> Option<&str> {
        self.group
            .strip_prefix(self.member)
            .and_then(|rest| rest.strip_prefix("#role-"))
    }
}

async fn deliver(
    client: &VtnClient,
    identity: &Identity,
    target: Target<'_>,
    envelope: Envelope,
    receipt: impl Fn(DeliveryStatus, Option<String>, Option<Vec<Receipt>>) -> Receipt,
) -> Receipt {
    let Some(role) = target.network_role() else {
        // A community's inbox: any 2xx is acceptance.
        return match client
            .post_url(target.endpoint, &json!({ "envelope": envelope }))
            .await
        {
            Ok(_) => receipt(DeliveryStatus::Delivered, None, None),
            Err(e) if matches!(e.status(), Some(403 | 422)) => {
                receipt(DeliveryStatus::Refused, Some(e.to_string()), None)
            }
            Err(e) => receipt(DeliveryStatus::Failed, Some(e.to_string()), None),
        };
    };
    let payload: specs::Payload = match serde_json::from_value(json!({
        "role": role,
        "envelope": envelope,
    })) {
        Ok(p) => p,
        Err(e) => return receipt(DeliveryStatus::Failed, Some(e.to_string()), None),
    };
    let request = match vti_vtn::tasks::sign_request(identity, target.member, &payload).await {
        Ok(r) => r,
        Err(e) => return receipt(DeliveryStatus::Failed, Some(e.to_string()), None),
    };
    match client
        .send_request_to::<RelayResponse>(target.endpoint, &request, target.member)
        .await
    {
        Ok(r) => receipt(r.status, None, Some(r.relayed)),
        // The member network declined it: final. A server-side failure may pass.
        Err(e @ ClientError::Refused { status, .. }) if status < 500 => {
            receipt(DeliveryStatus::Refused, Some(e.to_string()), None)
        }
        Err(e) => receipt(DeliveryStatus::Failed, Some(e.to_string()), None),
    }
}
