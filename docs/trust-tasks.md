# The VTN over Trust Tasks

This is the contract for moving `vtn-service` from its interim REST API (A9) to Trust Tasks. The `vtn/*` specifications in `dtgwg-trust-tasks-tf` are written from it. Once they are published, they are normative and this file is history.

## What stays REST

Only artifacts that verifiers and browsers fetch by URL stay REST:

| Route | Why |
|---|---|
| `GET /` | the landing page itself |
| `GET /.well-known/vtn` | the network profile, found from a URL before anything is signed |
| `GET /v1/status/{purpose}` | Bitstring Status Lists, dereferenced from `credentialStatus` |
| `GET /v1/index` | the signed network index, a self-verifying document (VTI-VTN-024) |
| `GET /v1/credentials/{id}` | a credential by `id`, so a graph edge can be dereferenced |

The index and credential fetch keep `[directory] visibility`. In a restricted network they answer only a request carrying a signed Trust Task document in the `Trust-Task` header, which is the VTI convention for authenticated GETs. Everything else is a Trust Task at `POST /v1/trust-tasks`. `/v1/auth/*` goes away.

## Who is asking

Every request is a signed Trust Task document. The proof's signer is the caller. There are no sessions.

- **Administrator.** The signer is in `[admin] dids`, or is a key delegated by one through `auth/signing-key/enroll`.
- **Listed party.** The signer is the DID of an entry: a community or a network.
- **Peer network.** The signer is a network this one has joined. It may deliver broadcasts.
- **Person.** The signer is a person's DID, or a browser key delegated by that person through `auth/oob/*`. Where `[directory] visibility = "members"` requires it, the payload carries `membership`: the person's VMC from a member community, holder-bound to the signer's identity.
- **Anyone.** A read task under `visibility = "public"` accepts any signer. Proof is OPTIONAL for those tasks, so a page that has not signed in can still read.

**Browser sign-in reuses existing specs:**
- `auth/oob/{request,claim,prove,respond,redeem,cancel}` lets a wallet approve a browser key.
- `auth/signing-key/{enroll,authorize,list,revoke}` handles delegated keys.

This replaces A13's `vtn-signin:` link.

## Trust Tasks are the API; credentials are the proof

Every operation is a Trust Task, but no Trust Task document is ever the evidence of a relationship. Evidence is always a DTG credential that a verifier can check later, against its issuer's keys and status lists, without asking anyone:

| Relationship | Evidence | Issuer → subject |
|---|---|---|
| listing | `lists/1` VSC (registry) | network → party |
| membership | VMC grant + VMC acknowledgement carrying its digest | network ↔ party |
| repudiation, departure | `repudiates/1` VSC (registry) | party → network |
| group serving a role | `groupRegistered/1` VSC (OpenVTC namespace, A1) carrying the digest of the signed `vtn/groups/register` request; revocable through the network's status list | network → group |
| a person's membership | the person's VMC from a member community | community → person |
| room pass | a short-lived credential | network → person |

A Trust Task carries these credentials and asks for them to be issued. Its signature authenticates the request, and only the request. `servesRole/1` is retired: the member's signed `vtn/groups/register` request replaces it, and the `groupRegistered/1` acceptance binds that request by digest. The digest is SHA-256 over the JCS form of the request **including** its proof (the step digest, not the task digest), so a re-signed copy is a different registration. A registered endpoint is `https://`. Room-pass chains carry `ChainLink { registration, acceptance }`. A verifier checks each acceptance's signature, its digest and its status. A status that is revoked, suspended or cannot be determined fails the check (VTI-REG-012).

## Lifetimes

Anything that authorizes without being revocable is kept short:

| What | Lifetime |
|---|---|
| A Trust Task request | accepted within 10 minutes of its `issuedAt` (the VTI acceptance window). A request's own `expiresAt` adds nothing beyond that |
| A browser or delegated key (`auth/oob` session, `auth/signing-key`) at a VTN | at most 24 hours, 8 hours by default. This is the VTN's cap, well inside the framework's 30-day ceiling |
| A room pass | at most 24 hours (`passMinutes` ≤ 1440), 60 minutes by default |
| A broadcast message | at most 7 days after `sentAt`, 24 hours by default. The outbox stops retrying when it expires |

Credentials that evidence relationships (the table above) are revocable through status lists, so their validity follows the relationship rather than a short clock.

## Shared shapes: `vtn/_shared/0.1/`

The shapes are those of `vti-vtn` today, in camelCase. `Entry.createdAt` and `Entry.updatedAt` change from today's snake_case.

| File | Defs |
|---|---|
| `entry.schema.json` | `Did`, `EntryKind` (community\|network), `EntryState` (listed\|acknowledged\|repudiated\|suspended\|removed\|departed), `EntryProfile {description?, url?, tags[]}`, `Issued {credential, statusIndex}`, `StateChange {at, from?, to, reason?}`, `Entry` (admin view), `IndexEntry` (published view), `Credential` (open object: a DTG credential), `Membership` (a person's VMC, open object), `AuditEvent {at, did, event, to, actor, reason?}` |
| `directory.schema.json` | `DirectoryEntry`, `DirectorySummary`, `PathHop`, `FederatedEntry`, `Unreachable` |
| `graph.schema.json` | `Graph {nodes, edges}`, `Node`, `Edge`, `NodeKind`, `EdgeRole`, `EdgeStatus` |
| `groups.schema.json` | `RoleName` (`^[a-z][a-z0-9-]{0,62}$`), `RoleDef`, `RegisteredGroup {member, role, group, endpoint, registration, acceptance, registeredAt}`, `ChainLink {registration, acceptance}` (signed Trust Task documents, open objects) |
| `relay.schema.json` | `Envelope {message, hops[]}`, `DeliveryStatus`, `Receipt`, `BroadcastRecord`, `OutboxItem` |
| `membership.schema.json` | `UpstreamMembership {network, url, name?, state, listing, grant?, acknowledgement?, repudiation?, groups[], updatedAt}`, `RoleMapping {parentRole, localRole}`, `UpstreamGroup` |
| `rooms.schema.json` | `RoomDef {id, name, role, description?, url?, passMinutes}`, `RoomPass {room, pass, via[]}` |

## The tasks

The recipient is always the network. "Consequential" means `issuedAt` is REQUIRED, and the spec carries `## Authorization` and the four `## Security & Privacy` subsections. Error codes are `vtn/<slug>:<local>`, alongside the standard `permissionDenied`, `notFound`, `alreadyExists` and `malformedRequest`.

### A listed party, toward the network

| Slug | Caller | Request | Response | Codes |
|---|---|---|---|---|
| `vtn/entries/show` | anyone the directory admits; a party may always read its own entry | `{did, membership?}` | `{entry: IndexEntry}` | `notFound` for an unpublished entry, as for an absent one |
| `vtn/membership/offer` | the listed party (`issuer` = entry) | `{}` | `{offer: Credential}`, the unsigned grant (A2) | `notListed`, `alreadyMember` |
| `vtn/membership/acknowledge` | the listed party | `{acknowledgement: Credential}` | `{entry: IndexEntry}`, with the now-signed grant | `notListed`, `acknowledgementInvalid`, `rolesUnregistered` (`details.roles`) |
| `vtn/membership/repudiate` | the listed party | `{repudiation: Credential}` | `{entry: IndexEntry}` | `notListed`, `repudiationInvalid` |
| `vtn/groups/register` | a listed party or member | `{role, group, endpoint}` | `{group: RegisteredGroup}` | `notListed`, `unknownRole`, `groupTaken` |
| `vtn/relay/deliver` | a peer network this one has joined | `{role, envelope}` | `{status, relayed: Receipt[]}` | `notMember`, `unknownRole`, `envelopeInvalid` |
| `vtn/roles/list` | anyone the directory admits; listed parties always | `{}` | `{roles: RoleDef[]}` | |
| `vtn/rooms/list` | anyone the directory admits | `{membership?}` | `{rooms: RoomDef[]}` | |
| `vtn/rooms/pass` | a person | `{room, membership, chain: ChainLink[]}` | `{pass: RoomPass}` | `unknownRoom`, `notEligible`, `chainInvalid` |

### Reading the published set (governed by `visibility`)

| Slug | Request | Response | Codes |
|---|---|---|---|
| `vtn/directory/search` | `{q?, kind?, state?, membersOnly?, membership?}` | `{entries: DirectoryEntry[]}` | |
| `vtn/directory/federated` | the same | `{determinedAt, results: FederatedEntry[], unreachable: Unreachable[]}` | |
| `vtn/directory/summary` | `{membership?}` | `{summary: DirectorySummary}`; answered without the directory gate when `show_counts` | |
| `vtn/graph/show` | `{includeExited?, membership?}`; `includeExited` is for administrators only | `{graph: Graph}` | |
| `vtn/graph/member` | `{did, membership?}` | `{graph: Graph}` | `notMember`, `memberUnreachable` |

### Administration (`issuer` is an administrator)

| Slug | Request | Response | Codes |
|---|---|---|---|
| `vtn/listings/create` | `{did, kind, label?, description?, url?, tags?}` | `{entry: Entry}` | `alreadyExists` |
| `vtn/listings/update` | `{did, label?, description?, url?, tags?}` | `{entry}` | |
| `vtn/listings/suspend` | `{did, reason?}` | `{entry}` | `invalidTransition` |
| `vtn/listings/reinstate` | `{did, reason?}` | `{entry}` | `invalidTransition` |
| `vtn/listings/remove` | `{did, reason?}` | `{entry}` | `invalidTransition` |
| `vtn/listings/list` | `{state?}` | `{entries: Entry[]}` | |
| `vtn/listings/show` | `{did}` | `{entry: Entry}` | |
| `vtn/audit/list` | `{did?, limit?}` | `{events: AuditEvent[]}` | |
| `vtn/groups/list` | `{role?}` | `{groups: RegisteredGroup[]}` | |
| `vtn/broadcasts/send` | `{role, class?, subject, body, replyTo?}` | `{broadcast: BroadcastRecord}` | `unknownRole` |
| `vtn/broadcasts/list` | `{limit?}` | `{broadcasts: BroadcastRecord[]}` | |
| `vtn/broadcasts/show` | `{id}` | `{broadcast}` | |
| `vtn/outbox/list` | `{}` | `{items: OutboxItem[]}` | |
| `vtn/outbox/retry` | `{}` | `{attempted}` | |

### This network as a member of a parent (`issuer` is an administrator)

These mirror `vtc/networks/*`, because a network joins a parent the way a community does.

| Slug | Request | Response | Codes |
|---|---|---|---|
| `vtn/memberships/list` | `{}` | `{memberships: UpstreamMembership[]}` | |
| `vtn/memberships/join` | `{url, network, roles: RoleMapping[]}` | `{membership}` | `notListed`, `networkMismatch`, `roleUnassigned`, `networkRefused` |
| `vtn/memberships/repudiate` | `{url, network}` | `{membership}` | `notListed`, `networkMismatch`, `networkRefused` |
| `vtn/memberships/leave` | `{network}` | `{membership}` | `notMember`, `networkRefused` |
| `vtn/memberships/groups/add` | `{network, parentRole, localRole}` | `{membership}` | `notMember`, `unknownRole`, `networkRefused` |

## Consequential tasks

`issuedAt` and proof are REQUIRED, and a consumer MAY require an operation-bound step-up for them:

- `membership/acknowledge` and `membership/repudiate`
- `groups/register`
- `relay/deliver`
- `rooms/pass`
- every `listings/*` except `list` and `show`
- `broadcasts/send` and `outbox/retry`
- `memberships/join`, `repudiate`, `leave` and `groups/add`

## Order of work

1. Write the `vtn/*` 0.1 specs and `vtn/_shared/0.1` in the TF repo, and fix the `vtc/networks/*` examples, which still show the interim `lists/1` IRI and `kind`.
2. Extract the VTC's Trust Task server spine into a shared VTI crate, and move `vtc-service` onto it.
3. Add a `vti-specs-vtn` crate in VTI, and move the `vti-vtn` client onto Trust Tasks.
4. Move `vtn-service`, `nnm` and the landing page onto Trust Tasks, and retire A9, A13 and the group VSCs.
5. Write `vtc/networks/*` 0.2, so the VTC side uses `vtn/groups/register` and `vtn/membership/*`.
