# Verifiable Trust Network (VTN) — Design

Status: **Draft for discussion** · 2026-11-02 · Owner: Glenn Gore

## 1. Summary

A **VTN** is a curated, nestable set of communities (VTCs) and other networks
(VTNs). It exists for two things: **joint recognition** and **discovery** of the
parties it lists. It also gives the network a way to reach a role across every
member, e.g. *every admin group in the network*, without the VTN ever holding a
roster of people.

This design implements the existing normative chapter
`dtgwg-vti-spec/spec/11a-vtn.md` (VTI-VTN-001…063). It does not redefine it. The
hard rules from that chapter that shape everything below:

| Rule | Consequence for the design |
|---|---|
| Listing is one-sided (VTN-010) | Anyone can create a VTN and list anyone. Membership is a separate, two-sided state. |
| Every entry states ack / unack / repudiated (VTN-011/012) | Entry state is first-class data, in the index, the credentials and the graph view. |
| Unacknowledged ≠ membership (VTN-013) | No membership credential (VMC) is issued until the listed party acknowledges. |
| Listing is not transitive recognition (VTN-022/023) | Recognising a VTN never implies recognising what it lists, unless a relying party adopts an explicit, named policy. |
| Nesting must not flatten (VTN-030…033) | Results, search hits and the graph always carry the **path**: each hop with its own owner and ack state. |
| A VTN grants nothing and never touches VTC membership (VTN-060…063) | The VTN never stores people. Cascading groups are resolved by delegation to each member, not by copying rosters. |

What this design adds beyond the spec:

1. A concrete **DTG credential mapping** for every VTN relationship, covering listing, membership, recognition, group registration and repudiation.
2. **Network groups**: members register their own groups, such as an admin group or a notification group, against roles the VTN defines. These cascade through nested VTNs, so a broadcast reaches every registered group.
3. A **network index and federated search** that preserves the path.
4. A **DTG graph view** of the network, drawn from the credentials themselves.
5. A recommendation on spec open question **D9**, i.e. whether a VTN is its own node type or a VTC in a curation role.

## 2. Worked example: World Health Network

```
WHN  (VTN, owner: a world-health body)
├── Health-AU  (VTN, national)          acknowledged member
│   ├── Health-NSW (VTN, state)         acknowledged member
│   │   ├── St Vincent's   (VTC)        acknowledged member
│   │   └── Westmead       (VTC)        listed, unacknowledged
│   └── Health-VIC (VTN, state)         acknowledged member
│       └── Alfred Health  (VTC)        acknowledged member
├── Health-NZ  (VTN, national)          listed, unacknowledged
└── MSF        (VTC, direct)            acknowledged member
Lateral: Health-AU ⇄ Health-NZ          mutual recognition (VRC pair)
```

- WHN lists Health-NZ before Health-NZ agrees. The listing is legitimate, but
  WHN must show it as *unacknowledged* and must not call Health-NZ a member.
- WHN never lists St Vincent's itself. It lists Health-AU, which lists
  Health-NSW, which lists St Vincent's. A search for "St Vincent's" from WHN
  returns the whole path, and each of its three hops has its own ack state.
- WHN's governance requires every member to register an `admins` group. An
  "all admins" broadcast from WHN therefore reaches:
  - Health-AU's registered `admins` group. That group is itself a *network
    group*, aggregating the state networks' `admins` groups, which in turn
    aggregate the VTC admin groups.
  - MSF's `admins` group, directly.

  WHN learns nobody's identity in the process.

## 3. Relationship model

A VTN relationship has three **independent axes**. Keeping them separate is the
core of the design, because the spec's warnings are all about one axis being
read as another.

| Axis | Question it answers | Sides | Evidence |
|---|---|---|---|
| **Listing** | Does the VTN list X? | 1 (VTN) | Listing VSC (VTN → X) |
| **Membership** | Have X and the VTN agreed that X is a member? | 2 | VMC grant (VTN → X) + VMC ack (X → VTN, `digestMultibase` of grant) |
| **Recognition** | Does A trust B's members and credentials? | 1 per direction | VRC (A → B), projected to A's trust registry `recognise` record |

The "best practice" the brief describes (dual recognition) is the strongest
combination:

```
Listed ──(X acknowledges)──► Member ──(X recognises VTN, VTN recognises X)──► Member + mutually recognised
   │
   └──(X repudiates)──► Repudiated (still published, VTN-012)
```

### 3.1 Entry lifecycle

| State | Meaning | Credentials live |
|---|---|---|
| `listed` | The VTN listed X. X has not responded. | Listing VSC |
| `acknowledged` | X accepted the listing. This is membership. | Listing VSC, VMC grant, VMC ack |
| `repudiated` | X rejects the listing. The VTN keeps publishing the entry *with* the repudiation (VTN-012), or removes it. | Listing VSC, Repudiation VSC (X → VTN) |
| `suspended` | The VTN has paused the entry under its governance framework. | As above, VMC grant status = suspended |
| `removed` | The VTN delisted X. | All VTN-issued credentials revoked (status list, VTN-053) |
| `departed` | X withdrew. | X revokes its VMC ack. VTN revokes the grant and listing. |

A party may also **apply** to a VTN, using the same join-request flow as a VTC
(§6). An admitted applicant goes straight to `acknowledged`.

## 4. DTG credential mapping

Every relationship is a DTG credential, and every half of a two-sided edge is
its own credential with its own status. This is the DTG spec's model: no
co-signing and no pair ID (body.md:645).

| Relationship | Type | Issuer → Subject | Key claims | `issuerScope` |
|---|---|---|---|---|
| VTN lists X | **VSC**, predicate `vtn:lists/1` (new profile) | VTN → X | `object.value = { kind: community\|network, framework: <IRI>@<version> }` | public |
| X repudiates listing | **VSC**, predicate `vtn:repudiates/1` (new) | X → VTN | `object.digestMultibase` = listing VSC | public |
| X is a member of VTN (grant) | **VMC** | VTN → X | `credentialStatus` | public |
| X accepts membership (ack) | **VMC** | X → VTN | `credentialSubject.digestMultibase` = grant digest | public |
| A recognises B | **VRC** | A → B | One VRC per direction. Mirrored into A's trust registry as `(B, A, recognise, trust-graph)`. | public |
| Invitation to join VTN | **VIC** (VTN variant, body.md:660) | VTN → prospective X | single-use, short-lived | directed |
| X registers group G for network role R | **VSC**, predicate `vtn:servesRole/1` (new) | X → G | `object.value = { network: VTN, role: R }`. Proof that G belongs to X is the existing community→group `AuthorityCredential`. | public |
| VTN accepts G's registration | **VSC**, predicate `vtn:groupRegistered/1` (new) | VTN → G | `object.digestMultibase` = the servesRole VSC | public |
| VTN admin roles | **VAC** `role:<name>` | VTN → admin | Same convention as VTC (`new_community_role_vac`) | directed |
| Conformance / endorsement | **VSC** `dtg:endorses` (VEC profile) | VTN → X | what, framework + version, period (VTN-051). Confers no authority (VTN-052). | public |

Why the listing is a **VSC** rather than a VMC: a VSC "attests, never
establishes" (body.md:790), which matches a one-sided listing exactly. It also
satisfies VTN-013, because no membership credential exists until X acknowledges.

**Spec gaps to raise with the DTG WG** (none blocks a prototype, since VSC
profiles can live under a VTN-controlled namespace first). Items 1 and 3, plus
the listing-vs-grant ordering question, are raised in DTG WG discussion
[#82](https://github.com/trustoverip/dtgwg-cred-spec/discussions/82)
(source: `docs/wg/dtg-issue-vmc-vtn-membership.md`):

1. VMC subject list (body.md:375) names "member VTC" only. VTN-as-member-of-VTN needs to be added explicitly.
2. Cross-community recognition is currently a TRQP record, not a credential. Proposal: the VRC is the evidence and the registry record is its projection. This matches the capability-module "VTC is source of truth, registry is projection" pattern.
3. VMC lifecycle and status location are deferred in the spec (body.md:434). The VTN needs it now because of VTN-053. Interim: a status list on every VTN-issued credential, plus a short `validUntil` on the ack.
4. Register the `vtn:*` predicate profiles at `registry.trustoverip.org/dtg/vsc/...` once they are stable.

## 5. Network groups (cascading)

This is the main new capability: the network as a delivery fabric for a role,
not just a list.

### 5.1 Concepts

- **Network role:** a named slot defined in the VTN's governance framework, e.g. `admins`, `notifications`, `security-contacts` or `data-protection-officers`. Each role states:
  - whether registering a group for it is **required for admission**
  - who may **send** to it
  - the **message classes** it accepts (e.g. notice, request-for-action, data-room invite)
- **Registered group:** a group a member owns and registers for a role.
  - VTC members register an existing VTC group, which already has its own `did:webvh` and community→group `AuthorityCredential` (see `vti` `docs/03-vtc/groups.md`).
  - VTN members register one of their own **network groups** (next bullet).
- **Network group:** a VTN-owned group, with its own DID minted by the VTN's VTA, for one role. Its members are registered *groups*, never people. It is how the cascade composes. Health-AU's `admins` network group is what Health-AU registers with WHN as its `admins` group.

```
WHN:admins (network group)
 ├── Health-AU:admins (network group) ── registered by Health-AU
 │     ├── Health-NSW:admins (network group)
 │     │     └── StVincents:admins (VTC group → people)
 │     └── Health-VIC:admins (network group)
 │           └── Alfred:admins (VTC group → people)
 └── MSF:admins (VTC group → people)
```

### 5.2 Admission integration

A VTN's join manifest can list `requiredRoles: ["admins"]`. Admission is
`refer` until the applicant has registered a group for each required role, so
the VMC grant is only issued once the network can reach the member's admins.
This is the brief's "part of the joining admission". It reuses the VTC ceremony
pipeline: the `admission.rego` facts include `registeredRoles`.

### 5.3 Broadcast and delivery

```
sender (VTN admin, VAC role:broadcaster)
  → vtn/broadcast/send { role: admins, class: notice, body, ttl }
  → VTN checks broadcast.rego, signs the envelope as WHN:admins
  → fan-out to each registered group DID   (TSP > DIDComm > REST)
      → network group? re-sign/relay to its registered groups (recursive)
      → VTC group?     the VTC relays to group members via member_push
```

Rules:

- **The roster stays with the owner.** Each hop expands only its own groups.
  WHN learns that Health-AU's group accepted delivery, and nothing about who is
  in it. This is the network version of VTN-062 and of the room host's
  "never a roster".
- **Each hop applies its own policy.** Health-AU may rate-limit, delay or
  refuse relay from WHN under its own `relay.rego`. A member chose to be
  reachable, not to be controlled.
- **Provenance chain.** The envelope keeps the original sender and appends one
  signed hop per relay, so a recipient sees *WHN → Health-AU → Health-NSW →
  St Vincent's admins*. This is the messaging equivalent of "nesting must not
  flatten".
- **Loops and overlap.** Overlap is expected (VTN-040), and a VTC listed by two
  networks under WHN would otherwise get duplicates. Handle it with:
  - a global `messageId`
  - per-recipient-group dedup
  - a hop limit (default 8, matching the DTG attenuation depth)
- **Receipts.** Each registered group returns a signed delivery receipt
  (accepted / refused / relayed-n), aggregated back up the tree. The VTN sees
  per-member reach, never per-person reach.
- **Replies** go to a reply address set by the sender, typically a network data room (§5.4), so that broadcast never becomes a reply-all storm.

### 5.4 Network data rooms

A VTN can own data rooms (`ownerDid` = VTN DID) and bind them to a network
group, e.g. a "Pandemic Response" room for `WHN:admins`. Rooms only honour
credentials they issue themselves (`vti-rooms` invariant I5), so admission works
like this:

1. A person presents the chain:
   - VMC (person ← VTC group)
   - servesRole VSC (VTC → group, role `admins`)
   - VMC pair at each hop up to the VTN
2. The room verifies each hop's credentials and status, using the same
   per-hop evaluation as VTN-032.
3. The room issues its own room credential. From then on, `vti-rooms-dtg`
   `ChainVerifier` applies unchanged.

The cascade is evaluated at admission time and not cached as a roster. A
person removed from St Vincent's admin group loses their next admission, and
the room credential's short `validUntil` bounds how long the old one lasts.

## 6. VTN vs VTC: shared surface, different semantics

| Surface | VTC | VTN |
|---|---|---|
| Identity | VTA-provisioned DID | Same (VTN-001) |
| Admins / ACL | Roles + capabilities, approvals/step-up | **Same model** (VTN-004/005). Roles: owner, curator, broadcaster, auditor. |
| Policies | Rego bundle: admission, join, removal, … | Rego bundle: `listing`, `admission`, `removal`, `group_registration`, `broadcast`, `relay`, `directory`, `recognition` |
| Member list | People (and groups), two-sided | **Entries**: communities/networks, each with a kind and an ack state, one-sided allowed |
| Join | Join manifest → submit → decide | Same flow and shapes. The applicant is a community/network acting through its admins. Adds `requiredRoles`. |
| Groups | Groups of people, own DID | **Network groups**: groups of groups, one per role, cascading |
| Data rooms | Community rooms | Network rooms, admission via cascade chain |
| Directory | Members, per-viewer projection | **Network index**, federated search with paths |
| Messaging | Per-member push | Broadcast to network roles, relayed per hop |
| Recognition | Registry record | VRC-evidenced, registry-projected; explicit "extend recognition to listed parties" policy (VTN-023) as opt-in config |
| Graph view | n/a | DTG network view (§8) |
| Must not | n/a | Create trust contexts, derive keys, touch member state (VTN-060…063) |

### 6.1 Decision on D9 (node type vs VTC role)

**Decided (2026-11-02): the VTN is a new service, `vtn-service`, a distinct
node type built on a shared community kernel extracted from `vtc-service`.**
The VTI spec's D9 remains open at the working group. Our implementation takes
the "distinct node type" branch, and that position will go to the WG.

- **Not a VTC "curation mode."**
  - The member-list, directory, groups and messaging semantics all differ: entries vs people, groups-of-groups, relay.
  - Building it as a mode would make most VTC requirements conditional, which is the cost the spec itself names.
  - The VTN must also be *unable* to do things a VTC does: hold people, mint member state, create trust contexts. That is easier to guarantee in a binary that has no such code paths.
- **Not a from-scratch service either.**
  - Extract the parts that really are shared into a `vti-community-core` crate: ACL/roles/approvals, the ceremony pipeline + Rego host, the audit tail + hooks pattern, status lists, the admin-SPA shell, website deploy, rooms ownership, and the join-request shapes.
  - Both services depend on it, which keeps drift low.
- The spec's requirements are written to survive either answer, so this choice is reversible at the spec level.

## 7. Discovery and search

- **Network index:** a signed, paginated document the VTN publishes. Each entry has:
  - DID, kind, ack state, listing/VMC credential IDs
  - profile snapshot: name, description, sector/jurisdiction tags
  - registered roles
  - for networks, a pointer to the child's own index

  Each response carries the governance framework IRI + version and the determination time (VTN-024).
- **Federated search** (`vtn/directory/query`): the VTN searches its own index and, down to a depth limit, the cached signed indexes of its network members.
  - Every hit returns its **path** with each hop's ack state, e.g. `WHN →(ack) Health-AU →(ack) Health-NSW →(unack) Westmead`.
  - Child index entries keep the child's signature, so WHN never presents Health-NSW's entries as its own (VTN-033).
- **Registry projection:** trust-registry records `(X, VTN, lists|member, vtn)`. This lets existing TRQP clients answer "is X in network N" without a new protocol.
  - The records are flat 4-tuples, so a path query is answered by the VTN, not the registry.
- **Unavailable child index ⇒ indeterminate**, never "not present" (VTI-REG-012).

## 8. DTG graph visualisation

Every VTN exposes `vtn/graph/export`: nodes and edges where **each edge is one
credential**, with status. The admin UI and the public site render it.

- **Nodes:** VTN, VTC, network group, registered group. People are never shown, because a VTN has no people.
- **Edges:** one visual element per credential half:

  | Edge | Rendering |
  |---|---|
  | listing | dashed |
  | VMC grant + ack | solid (half-solid if only one half is valid) |
  | repudiation | red marker on the listing |
  | VRC | arc; arrowheads show direction, so mutual = both |
  | `servesRole` | thin, to group nodes |
  | revoked / suspended / expired | greyed with status badge |

- **Nested networks** render as collapsible containers labelled with their
  *own* owner and framework. Expanding one fetches the child's signed export
  lazily, so the view stays a list of lists and never flattens.
- **"To the extent it can":** the VTN only knows its own credentials plus what
  members publish. VTC internals show only what the VTC chooses to publish
  (e.g. member count, consented directory entries). Unknown or unreachable
  subtrees render as "indeterminate".
- **Interactions:**
  - click an edge to see the credential JSON and verify it in the browser
  - trace the path from the root to a node
  - filter by ack state, kind or role
  - toggle the "broadcast reach" overlay for a role
- **Tech:** reuse the D3 force/pack layouts from `dtg-demo`. Do not reuse its data generator: it predates `issuerScope`, the current context and VMC ack digests.

## 9. Changes required in the VTC

A VTC needs a small **"network membership" capability module**:

1. Receive listings, then acknowledge or repudiate them. This issues the VMC ack or the repudiation VSC.
2. Apply to a VTN through the VTN join flow, acting as the community, with admin approval and step-up.
3. Register a group for a network role. This issues the servesRole VSC.
4. **Group relay:** accept a broadcast addressed to one of its group DIDs, check `relay.rego`, then fan out through `member_push` and return a receipt.
5. Admin UI panel "Networks": list of networks that list us, our state in each, our registered groups, and the inbound broadcast log.
6. Optional: issue a VRC to recognise a VTN, projected into the registry.

## 10. Trust-task families (spec-first in `dtgwg-trust-tasks-tf`)

```
vtn/listings/{create,update,remove,list}
vtn/entries/{acknowledge,repudiate,depart}        (called by listed party)
vtn/join-requests/{manifest,submit,supplement,withdraw,status,decide}
vtn/roles/{define,list}                           (network roles)
vtn/groups/{register,deregister,list}
vtn/broadcast/{send,status}  + vtn/relay/deliver  (hop-to-hop)
vtn/directory/{index,query}
vtn/graph/export
vtn/recognition/{issue,revoke,list}
vtn/rooms/*                                       (reuse community-rooms shapes)
```

Generated into `vti-specs-vtn`, consumed by `vtn-service` and `vtn-client`. CLI
support goes in `cnm-cli`.

## 11. Delivery plan

**Progress (2026-11-02):** Phase 1 network-side is done, and most of phase 2 too:
- `vtn-core`, `vtn-client`, `vtn-service` and `nnm-cli` are built.
- The network is VTA-provisioned and admins sign in by DID.
- The landing page has a directory with configurable visibility.
- Nested membership works: a VTN can join a parent.
- Roles, required-role admission, and cascading broadcast with signed hop chains and receipts are in (A14, A15).

Not yet done:
- the VTC-side network-membership module
- federated search (phase 3)
- the graph UI (phase 3)
- network data rooms (phase 4)
- a durable delivery queue

| Phase | Scope | Exit criterion |
|---|---|---|
| 0 | Extract `vti-community-core` from `vtc-service`, with no behaviour change | VTC test suite green on the extracted core |
| 1 | `vtn-service`: identity, ACL, listings, ack/repudiate, VMC pair, status, network index; VTC network-membership module (ack/repudiate) | WHN → Health-AU → Health-NSW → St Vincent's running locally with mixed ack states |
| 2 | Join flow, `requiredRoles`, group registration, network groups, broadcast + relay + receipts | "All admins" broadcast reaches three levels with dedup and a provenance chain |
| 3 | Graph export + visualisation, federated search with paths | Graph renders the example. Every edge verifies in the browser. |
| 4 | Network data rooms via cascade admission; VRC recognition + registry projection | Admins from two VTCs in different states join one WHN room |
| — | In parallel: DTG WG items in §4, D9 position paper | — |

## 12. Open questions

1. **Broadcast abuse.** Anyone can create a VTN and list anyone. Members only receive broadcasts for groups *they* registered, which already requires acknowledgement, but the defaults still need deciding: rate limits and message-class allowlists in the VTC's `relay.rego`.
2. **Privacy of registered groups.** Is the existence of "St Vincent's admins" group DID sensitive? A role's group DIDs may need to be visible only to the VTN and its admins, not in the public index.
3. **Should a removal cascade?** If Health-AU is removed from WHN, `WHN:admins` drops Health-AU's group. That is correct, but Health-AU's own network is unaffected (VTN-063). Confirm that is the intended behaviour.
4. **Recognition shortcut.** Should the VTC expose "recognise everyone this VTN lists as acknowledged" as a one-click policy (VTN-023)? It must name the framework version and must be re-confirmed when that version changes.
5. **Who signs for a community** when it acts as a VTN member: the VTC DID through its VTA with admin step-up (proposed), or a delegated admin through a VDC?
6. **Index freshness** for federated search. Options: push on change (hooks pattern) vs a TTL on the cache.
