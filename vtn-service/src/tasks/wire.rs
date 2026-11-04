//! The `vtn/_shared/0.1` shapes, from what this service stores.
//!
//! The stored types keep their own field names (snake_case on [`Entry`], `at` on records),
//! so a store written before Trust Tasks still reads. What goes on the wire is the
//! specification's: each response is then held to its published schema by
//! `vti_trust_task_server::typed::respond`, so a shape this module gets wrong is refused as
//! an internal error rather than sent.

use serde::Serialize;
use serde_json::{Map, Value, json};
use vti_vtn::groups::RegisteredGroup;
use vti_vtn::model::{Entry, Issued, StateChange};

use crate::broadcast::{BroadcastRecord, OutboxItem, RelayResponse};
use crate::memberships::{Membership, UpstreamGroup};
use crate::rooms::{RoomDef, RoomPass};
use crate::store::AuditEvent;

fn value(v: impl Serialize) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// `object` without its `null` members: an absent optional is omitted, never `null`.
fn compact(mut object: Map<String, Value>) -> Value {
    object.retain(|_, v| !v.is_null());
    Value::Object(object)
}

fn issued(issued: &Issued) -> Value {
    json!({ "credential": issued.credential, "statusIndex": issued.status_index })
}

fn state_change(change: &StateChange) -> Value {
    let mut m = Map::new();
    m.insert("changedAt".into(), value(change.at));
    m.insert("from".into(), value(change.from));
    m.insert("to".into(), value(change.to));
    m.insert("reason".into(), value(&change.reason));
    compact(m)
}

/// `Entry`, the administrator's view.
pub fn entry(entry: &Entry) -> Value {
    let mut m = Map::new();
    m.insert("did".into(), value(&entry.did));
    m.insert("kind".into(), value(entry.kind));
    m.insert("label".into(), value(&entry.label));
    m.insert("profile".into(), value(&entry.profile));
    m.insert("state".into(), value(entry.state));
    m.insert("createdAt".into(), value(entry.created_at));
    m.insert("updatedAt".into(), value(entry.updated_at));
    m.insert("listing".into(), issued(&entry.listing));
    m.insert(
        "offer".into(),
        entry.offer.as_ref().map_or(Value::Null, issued),
    );
    m.insert(
        "grant".into(),
        entry.grant.as_ref().map_or(Value::Null, issued),
    );
    m.insert("ack".into(), value(&entry.ack));
    m.insert("repudiation".into(), value(&entry.repudiation));
    m.insert(
        "history".into(),
        Value::Array(entry.history.iter().map(state_change).collect()),
    );
    compact(m)
}

pub fn entries(all: &[Entry]) -> Value {
    Value::Array(all.iter().map(entry).collect())
}

pub fn audit_event(event: &AuditEvent) -> Value {
    let mut m = Map::new();
    m.insert("occurredAt".into(), value(event.at));
    m.insert("did".into(), value(&event.did));
    m.insert("event".into(), value(event.event));
    m.insert("to".into(), value(event.to));
    m.insert("actor".into(), value(&event.actor));
    m.insert("reason".into(), value(&event.reason));
    compact(m)
}

/// `RegisteredGroup`: the acceptance is the credential itself.
pub fn group(group: &RegisteredGroup) -> Value {
    json!({
        "member": group.member,
        "role": group.role,
        "group": group.group,
        "endpoint": group.endpoint,
        "registration": group.registration,
        "acceptance": group.acceptance.credential,
        "registeredAt": group.registered_at,
    })
}

pub fn broadcast(record: &BroadcastRecord) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), value(&record.id));
    m.insert("direction".into(), value(record.direction));
    m.insert("role".into(), value(&record.role));
    m.insert("message".into(), record.message.clone());
    m.insert("from".into(), value(&record.from));
    m.insert("actor".into(), value(&record.actor));
    m.insert("recordedAt".into(), value(record.at));
    m.insert("receipts".into(), value(&record.receipts));
    m.insert("reached".into(), value(record.reached));
    compact(m)
}

pub fn outbox_item(item: &OutboxItem) -> Value {
    json!({
        "messageId": item.message_id,
        "group": item.group,
        "member": item.member,
        "endpoint": item.endpoint,
        "envelope": item.envelope,
        "attempts": item.attempts,
        "nextAttemptAt": item.next_attempt,
        "expiresAt": item.expires_at,
        "lastError": item.last_error,
    })
}

/// The `vtn/relay/deliver` response: `relayed` is always present.
pub fn relay_response(response: &RelayResponse) -> Value {
    json!({ "status": response.status, "relayed": response.relayed })
}

fn upstream_group(group: &UpstreamGroup) -> Value {
    json!({
        "parentRole": group.parent_role,
        "localRole": group.local_role,
        "group": group.group,
        "registration": group.registration,
        "acceptance": group.acceptance,
    })
}

/// `UpstreamMembership`: the parent is `network`, its name `name`.
pub fn membership(membership: &Membership) -> Value {
    let mut m = Map::new();
    m.insert("network".into(), value(&membership.parent));
    m.insert("url".into(), value(&membership.url));
    m.insert("name".into(), value(&membership.parent_name));
    m.insert("state".into(), value(membership.state));
    m.insert("listing".into(), membership.listing.clone());
    m.insert("grant".into(), value(&membership.grant));
    m.insert("acknowledgement".into(), value(&membership.acknowledgement));
    m.insert("repudiation".into(), value(&membership.repudiation));
    m.insert(
        "groups".into(),
        Value::Array(membership.groups.iter().map(upstream_group).collect()),
    );
    m.insert("updatedAt".into(), value(membership.updated_at));
    compact(m)
}

/// `RoomDef`, camelCase (the configuration file keeps `pass_minutes`).
pub fn room(room: &RoomDef) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), value(&room.id));
    m.insert("name".into(), value(&room.name));
    m.insert("role".into(), value(&room.role));
    m.insert("description".into(), value(&room.description));
    m.insert("url".into(), value(&room.url));
    m.insert("passMinutes".into(), value(room.pass_minutes));
    compact(m)
}

pub fn room_pass(pass: &RoomPass) -> Value {
    json!({ "room": room(&pass.room), "pass": pass.pass, "via": pass.via })
}
