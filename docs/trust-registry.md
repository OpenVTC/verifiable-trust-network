# Trust registry

A VTN can publish its membership to a trust registry as TRQP records. A verifier that
already trusts the registry then asks "has this network authorised X as a `member`?" without
speaking `vtn/*`, and without taking the network's word for it. The network stays the
source of truth: every record is derived from an entry, and changes with it.

Design: `docs/vtn-design.md` §7. Assumption: A23.

## What is published

| TRQP | Value |
|---|---|
| `entity_id` | the listed community's or network's DID |
| `authority_id` | this network's DID |
| `action` | `member` for an acknowledged entry; `lists` for a listed, unacknowledged one, only with `publish = "members-and-listed"` |
| `resource` | `vtn` |
| `context` | `kind` (`community` or `network`), `name`, `governanceFramework` `{iri, version}`, and the ids of the `listing` and `grant` credentials that evidence the record |

- A suspended, removed, departed or repudiated entry has **no** record. A suspended member's
  record comes back when it is reinstated.
- A listed party is never published as a `member`: unacknowledged is not membership
  (VTI-VTN-013). With `members-and-listed` it is published under `lists`, and its `lists`
  record is replaced by `member` when it acknowledges, never both.
- The records are flat. "Is X in WHN through Health-AU?" is a path, which the registry cannot
  answer; ask the network's federated directory (`vtn/directory/federated`).

## Configure

`vtn.toml`:

```toml
[registry]
did = "did:webvh:QmRegistry…:registry.example.org"   # the registry's DID
query_url = "https://registry.example.org"            # its public query base (TRQP REST, Trust Task HTTPS)
publish = "members"                                  # or "members-and-listed"
sync_interval_secs = 3600                            # full reconcile; changes are projected at once
```

Or `[trust_registry]` in the `vtn setup` file, with the same keys. Setup then also names the
registry in the network's DID document (below).

The network advertises the registry in its profile, `GET /.well-known/vtn`:

```json
"trustRegistry": {
  "did": "did:webvh:QmRegistry…:registry.example.org",
  "queryUrl": "https://registry.example.org",
  "authority": "<this network's DID>",
  "resource": "vtn",
  "actions": { "member": "member", "listed": "lists" },
  "publishes": "members"
}
```

and lets its landing page query `query_url`'s origin from the browser (the page's
`connect-src`), so a visitor checks a record with the registry itself.

## The registry's side

One registry serves the VTC and the VTN: each writer writes only under its own DID as
`authority_id`, so neither can touch the other's records. On the registry
(`affinidi-trust-registry-rs`):

- **`ADMIN_DIDS`**: add this network's DID beside the VTC's. Nothing in `ADMIN_AUTHORITIES`:
  an admin always may write under its own DID.
- **`ACL_MODE`**: with `ExplicitDeny` (the default) anyone can query; with `ExplicitAllow`
  only the readers you allow can, and a verifier you did not allow gets no answer. The
  records are meant for third parties, so `ExplicitDeny` is usual.
- **`ENABLE_REST=true`** and **`TR_PUBLIC_URL`**, *only if the registry serves HTTPS*: the
  public query surface `query_url` names. A DIDComm/TSP-only registry has none: leave
  `query_url` unset.
- **`CORS_ALLOWED_ORIGINS`**, with HTTPS only: add this network's origin
  (`https://vtn.example.org`) so its landing page can query the registry from a visitor's
  browser.
- **Version**: registries 0.29 and later speak `registry/record/*/0.3` and
  `registry/authorization/0.2`; `nnm` falls back to `authorization/0.1` for older ones.

## Finding the registry from the network's DID

TRQP v2 recommends that an authority's registry be "machine-discoverable via the
`authority_id`". The network's DID document carries a `TrustRegistry` referral naming the
registry by DID:

```json
{
  "id": "<network DID>#trust-registry",
  "type": "TrustRegistry",
  "serviceEndpoint": {
    "uri": "<registry DID>",
    "profile": "https://trustoverip.org/profiles/trqp/v2"
  }
}
```

A verifier resolves one hop to the registry's DID document, picks a transport, queries, and
**confirms the answer names this network as its authority**. A referral is only the
network's own claim about where to ask; the registry's answer is what counts.

- **New network:** `[trust_registry]` in the setup file fills the template's
  `SERVICE_TRUST_REGISTRY` slot (`vta_sdk::did_templates::referral_service`).
- **Existing network** (its DID is already minted): add the service on the VTA, which holds
  the DID's keys, then publish the new log entry where the DID log is served:
  `pnm dids edit <network DID>` with the entry above. A `did:webvh` log is append-only, so
  this is a new version of the DID, not a rewrite.

## Adding existing members

Nothing to do by hand. When `vtn` starts with `[registry]` set, it reconciles at once: every
entry is projected, and every member already there is put. It reconciles again shortly after
every lifecycle change (list, acknowledge, suspend, reinstate, remove, depart, repudiate)
and every `sync_interval_secs`.

A reconcile puts each record that should exist and deletes each record under this
network's authority and `resource = vtn` that should not: the registry's own list when it
can enumerate, else a local mirror of what this network wrote. A failed write is simply
retried by the next reconcile, since the projection is recomputed from the entries every
time. The last reconcile is logged (`trust registry projection incomplete` when anything
failed) and kept in the `registry` keyspace.

## Writes

The Affinidi registry accepts record writes (`registry/record/put`, `/delete`) over **DIDComm
or TSP** only, from a DID in `ADMIN_DIDS`. Its HTTPS binding is read-only, and a registry
may serve no HTTPS at all. So the network writes over its own **DIDComm session**:

```toml
[messaging]
mediator_did = "did:webvh:QmMediator…:mediator.example.org"   # the network's mediator
request_timeout_secs = 20                                     # wait for each answer
```

or `[messaging]` in the `vtn setup` file, with the same keys. Then:

- `vtn` holds one socket at the mediator as its own DID (`vti_common::host_session`, the
  session the witness and the ballot box run), reconnecting with backoff, and closes it on
  shutdown.
- Each write is a `registry/record/put/0.3` or `delete/0.2` Trust Task, and the reconcile's
  list is `registry/record/query/0.3` under this network's authority. Each names the registry
  as `recipient`, carries `issuedAt`, and is signed for `authentication` by the network's
  key, authcrypted as the network: what the registry checks before it takes a write from a
  DID in `ADMIN_DIDS`. The registry signs every answer.
- The first reconcile waits for the session to connect, and another runs each time it comes
  back. A reconcile that could not write everything is retried after 30 s, backing off to
  10 minutes; a complete one waits `sync_interval_secs`.
- Without `[messaging]` nothing is written: the projection is computed and reported
  (`writer = none` in the log), and `nnm registry records` shows every member as `missing`.

What has to be in place:

1. **The network's DID** routes DIDComm through the mediator: a `DIDCommMessaging` service
   and a key-agreement key. The `vtn-host` template has the key (`#key-1`) and, from the
   setup file's `[messaging]`, the service (`SERVICE_DIDCOMM`). For a DID already minted, add
   the service on the VTA and publish the new log entry:

   ```json
   {
     "id": "<network DID>#didcomm",
     "type": "DIDCommMessaging",
     "serviceEndpoint": [{ "uri": "<mediator DID>", "accept": ["didcomm/v2"] }]
   }
   ```

   with `pnm dids edit <network DID>`, as for the `TrustRegistry` referral below.
2. **The mediator** accepts the network's DID: the same mediator the VTC uses works, as long
   as its ACL lets this DID connect (an `ExplicitAllow` mediator needs it added). The mediator
   authenticates the network by resolving its DID, so the DID must resolve first.
3. **The registry** has the network's DID in `ADMIN_DIDS` (below) and serves DIDComm through
   a mediator the network can reach.
4. **The keys**: the session uses the identity's provisioned keys from the `[secrets]` store
   (its Ed25519 and X25519 keys), so `[messaging]` needs a provisioned `[identity]`.

## Checking records

Anyone, with the network's URL:

```sh
nnm registry status          # the registry, its query URL, and whether it answers
nnm registry check <did>     # does the registry say <did> is a member, or listed?
nnm registry records         # every entry against the registry: ok, missing, stale (administrators)
```

Every answer must name this network as its authority, or `nnm` refuses it. Without `nnm`,
any TRQP client asks the registry directly:

```sh
curl -s https://registry.example.org/authorization -H 'content-type: application/json' -d '{
  "entity_id": "<party DID>", "authority_id": "<network DID>",
  "action": "member", "resource": "vtn" }'
```

## Privacy

- `members` publishes only what the network's index already says to the public: who is a
  member. With `[directory] visibility = "members"` or `"admins"`, publishing to an open
  registry makes membership public anyway. Decide which you want, and use an
  `ExplicitAllow` registry, or no registry, for a private network.
- `members-and-listed` also publishes who the network has listed but who has **not**
  accepted. A listing is one-sided (VTI-VTN-010), so this states the network's interest in a
  party that may never have agreed to anything. Use it only where listings are public by
  governance.
