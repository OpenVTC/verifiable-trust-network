# Changelog

Notable changes to this workspace. From the first release on, entries are generated from
conventional commits by [git-cliff](https://git-cliff.org) via release-plz
(`cliff.toml`, `release-plz.toml`). Don't edit released sections by hand: write a
conventional-commit PR title and a real commit body (see CONTRIBUTING.md).

## Unreleased

### Features

- **service**: browser sign-in (A13). The network serves `auth/oob/*` through `vti-oob-server`, shared with the VTC: a wallet approves the landing page's own key, which then signs directory, graph, entry, role and room reads as the approver, for at most `[auth] browser_key_hours` (8 by default, 24 at most). No session, no cookie. `/.well-known/vtn` publishes `signIn` (link host, flow, scope).
- **templates**: `vtn-host` advertises `TrustTaskHTTPS` and `SignInPortal`, which a wallet needs to find the network.
- **landing page**: "Sign in with a wallet" on a restricted directory: the trigger link, the number to type into the wallet, and the approved key kept in this browser until it ends.

- **service**: the API is `vtn/*` 0.1 Trust Tasks at `POST /v1/trust-tasks`, all 33, through the shared `vti-trust-task-server` pipeline. Every request is signed by its caller and every answer by the network; there is no sign-in and no session. Duplicate ids are recorded in the store, so a document executes once even across a restart. Payloads and responses are held to their published schemas, and refusals carry the codes the specifications declare.
- **service**: broadcasts reach a member network as `vtn/relay/deliver`, signed by the delivering network, which must be one the receiver joined. A network registers its `/v1/trust-tasks` as its group's endpoint.
- **service**: this network joins, leaves and repudiates a parent over `vtn/*` tasks; `memberships/join` and `repudiate` name the parent's DID, and a URL answering as another network is `networkMismatch`.
- **service**: repeated transitions are answered with the entry as it stands, and `listings/update` changes only the fields named (A22).
- **nnm**: every command is a signed `vtn/*` task. `nnm token` and `nnm login` are gone with the sessions; `memberships join` and `repudiate` take `--parent <did>`.
- **landing page**: reads the directory, counts and graph with unsigned `vtn/*` tasks.

### Breaking

- **service**: the REST API is removed (A9). Only `/`, `/.well-known/vtn`, `/v1/status/*`, `/v1/index` and `/v1/credentials/{id}` remain, and the last two only under `visibility = "public"` (A21). `/v1/auth/*`, sessions and the `vtn-signin:` link are gone; browser sign-in returns with `auth/oob/*` (A13).
- **service**: `[relay] ttl_hours` defaults to 24 and may be at most 168; a room `id` must match `^[a-z0-9][a-z0-9-]{0,62}$` (A20).

- **core**: listings and repudiations use the registered DTG predicates `https://registry.trustoverip.org/dtg/vsc/lists/1` and `…/repudiates/1` (dtgwg-vsc-registry #33). A listing's `object.value` is `{ nodeType: "VTC" | "VTN", framework }`, replacing `kind`. A joining network checks that its parent lists it with `nodeType: VTN`. Listings issued under the interim `openvtc.org` IRI must be re-issued.
- **core**: VTN domain model: entries (community or network), the entry lifecycle (listed → acknowledged → suspended / repudiated / removed / departed), and DTG credential builders. A listing is a VSC under `lists/1` (A1). The membership offer is unsigned, and the VMC grant is signed only after the party's acknowledgement (A2). Repudiation and departure are VSCs under `repudiates/1`.
- **core**: W3C Bitstring Status Lists for revocation and suspension, the signed network index (VTI-VTN-011/024/031), and the DTG graph export with one edge per credential.
- **core**: pluggable, purpose-checked key resolution. Credentials verify under `assertionMethod` and admin sign-in under `authentication` (VTI-KEY-022).
- **service**: the `vtn` binary: fjall store via `vti-common`, the public and admin HTTP API, and an audit log.
- **service**: `vtn setup` provisions the network's `did:webvh` on a VTA from the `vtn-host` DID template, and keeps the keys in a `vti-secrets` store (VTI-VTN-001).
- **service**: administrators are DIDs and sign in by challenge-response. This replaces the earlier bearer token.
- **service**: the network landing page, with a searchable member directory. Directory visibility is `public`, `members` or `admins`. Members sign in with their entity DID, or a person signs in by presenting a membership credential from a member community.
- **core**: network roles and group registration. A member signs a `servesRole/1` VSC for one of its groups (member → group, naming network, role and delivery endpoint), and the network answers with a `groupRegistered/1` VSC. A VTN serves a parent's role with its own *network group* (`<DID>#role-<name>`, A14).
- **core**: broadcast envelopes. The message is signed by the origin network, plus one signed hop per relay step. Verification checks the origin's signature, expiry, the hop limit, and an unbroken chain in which each hop is signed by the network that owns the previous hop's group (VTI-VTN-032/033 for messages).
- **client**: `vtn-client`, a shared HTTP client (DID sign-in bound to the expected network DID) and a Bitstring Status List checker. Lists are verified as signed by the credential's issuer and cached briefly. An unreachable list is indeterminate, never valid (VTI-REG-012).
- **service**: nested membership. A VTN joins a parent network that lists it: it signs in as itself, verifies its listing, registers its network groups for the parent's required roles, acknowledges, and verifies the grant. It can also serve further roles, leave (departure), or repudiate a parent's listing.
- **service**: required roles. A party must register a group for each `required` role before its acknowledgement is accepted. Groups are revoked and dropped when a member departs or is removed.
- **service**: cascading broadcast to a role. Delivery goes to every current member's registered group. A network group relays into its own members' groups, so no network learns another's roster. Repeats are dropped by message id (which also breaks cycles), deliveries from networks this one is not a member of are refused, and a hop limit applies. Receipts are aggregated back up the chain.
- **service**: a person's membership credential is checked against the issuing community's status list at sign-in (A12 resolved).
- **service**: federated directory search (`/v1/directory/federated`, the landing page's *Include member networks* toggle, and `nnm directory --federated`). Searches the signed indexes of acknowledged member networks, down to `[directory] federate_depth`. Every result carries its path, with each hop's own entry state, and unreachable members are reported as indeterminate (VTI-VTN-032/033, VTI-REG-012, A16).
- **service**: the landing page's *Trust graph* tab. It draws the network's DTG graph from its credentials. Each membership line is two halves (the network's grant and the member's acknowledgement), listed-only edges are dashed, repudiations are red, and suspended or revoked edges show their status. Selecting a node shows the credentials that are its evidence. A member network expands in place, inside its own labelled boundary, from its verified signed index (`/v1/graph/member/{did}`), so nesting is never flattened (VTI-VTN-033). `#graph` and `#graph-expanded` deep links are supported.
- **service**: wallet sign-in from the landing page (A13):
  - The page starts a login (`POST /v1/auth/login`) and shows a `vtn-signin:` link.
  - A wallet signs the challenge with its DID, optionally presenting a membership credential, and posts it.
  - The page polls with a secret only it holds and receives the session, which is handed over once.
  - Wallets check that the endpoint answers as the network the link names before signing. `nnm login <link>` acts as the wallet for admins.
- **service**: a durable delivery queue. A broadcast delivery that fails in transport is queued in the store (`outbox`) and retried with exponential backoff by a background worker, until it succeeds, the message expires, or `relay.max_attempts` is reached. The broadcast's receipts are updated as retries resolve, and a new `queued` delivery status is added. Refusals are not retried. Admins can see and force retries with `/v1/admin/outbox[/retry]` and `nnm outbox [--retry]`.
- **service**: network room passes (design §5.4, A17). `[[rooms]]` opens a room for a role. A person proves who they are with a sign-in document, and presents their group's membership credential plus one registration/acceptance link per network level. The network verifies every link (signature and status) and walks the chain to a group registered here for the room's role, then issues a short-lived `room:enter` VAC scoped to the room. Rooms are listed at `/v1/rooms` (and with `nnm rooms`); passes are issued at `POST /v1/rooms/{id}/pass`.
- **service**: `status_cache_seconds` sets how long fetched status lists are trusted (A18).
- **nnm**: the Network Network Manager CLI: admin keys, networks, sign-in, curation commands, entry profiles, graph, index and audit. Also `roles`, `groups`, `broadcast`, `broadcasts`, and `memberships list|join|serve|leave|repudiate`.

### Documentation

- Design (`docs/vtn-design.md`), working assumptions on open WG questions (`docs/assumptions.md`), and the DTG WG proposal for VMC support of VTN membership (discussion #82, PR #83).
