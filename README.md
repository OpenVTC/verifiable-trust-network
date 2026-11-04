# Verifiable Trust Network (VTN)

A VTN is a curated, nestable set of communities (VTCs) and other networks (VTNs). It is
used for joint recognition and discovery. Every relationship in it is evidenced by a DTG
credential.

- Design: [`docs/vtn-design.md`](docs/vtn-design.md)
- Assumptions on open WG questions: [`docs/assumptions.md`](docs/assumptions.md)
- Normative requirements: `dtgwg-vti-spec/spec/11a-vtn.md` (VTI-VTN-*)

## Crates

| Crate | What |
|---|---|
| `vtn-service` | The `vtn` binary. It holds the network's VTA-provisioned identity (`vtn setup`), a fjall-backed store (via `vti-common`), and the `vtn/*` Trust Task API. |
| `nnm-cli` | The `nnm` binary, the **Network Network Manager**. It is the operator CLI for VTNs, as `pnm` is for a person and `cnm` for a community. It holds the operator's admin key and signs each request to a network with it. |

## Status

Phase 1 of the delivery plan, implemented:

- **Listing.** The network lists a VTC or VTN one-sidedly, by signing a listing VSC.
- **Membership.**
  1. The listed party fetches the unsigned membership offer.
  2. It signs a VMC acknowledgement.
  3. The network then signs the VMC grant, which completes the membership edge.
- **Repudiation.** A party can repudiate its listing; the listing stays published alongside the repudiation. A member can repudiate its grant, which counts as departing.
- **Network actions.** The network can suspend, reinstate and remove entries. These are reflected in W3C Bitstring Status Lists, for revocation and suspension.
- **Publishing.** Signed network index, DTG graph export (one edge per credential), and an audit log.
- **VTA-provisioned identity.** The network's `did:webvh` and keys come from its VTA (VTI-VTN-001). Parties' `did:webvh` keys are resolved with purpose checks.
- **Trust Task API.** Every operation is a `vtn/*` Trust Task (trusttasks.org, `vtn/*/0.1`), signed by its caller: there is no sign-in and no session. A Trust Task answer is never evidence of a relationship; the credentials it carries are (`docs/trust-tasks.md`).
- **Admin access.** Administrators are DIDs, listed in `admins`. The `nnm` signs each request with the operator's admin key.
- **Nested networks.** A VTN joins a parent network that lists it (`nnm memberships join <url>`), sending the parent `vtn/*` tasks signed by its own identity, and can later leave or repudiate.
- **Roles, groups and broadcast.** The network defines roles (`[[roles]]`, e.g. `admins`). Members register a group per role, and `required` roles gate admission. `nnm broadcast --role admins …` reaches every registered group. Member networks receive it as `vtn/relay/deliver` and relay into their own members' groups, one signed hop at a time, without sharing rosters. Receipts come back up the chain.
- **Network rooms.** `[[rooms]]` opens a room for a role. A person in any group registered for that role, directly or through member networks, gets a short-lived room pass by presenting their group evidence.
- **Trust graph.** The landing page's *Trust graph* tab draws the DTG graph from the credentials, and member networks expand in place.
- **Landing page and directory.** Served at `/`: the network's profile, member counts, and a searchable directory (by name, tags, description or DID; filterable by kind and acknowledgement). `[directory] visibility` is `public`, `members` or `admins`. A public directory is read with unsigned Trust Tasks. For a restricted one, a member community or network, or an administrator, signs in from a wallet: the wallet approves the page's own key (`auth/oob/*`, A13), which then reads as them for up to `[auth] browser_key_hours`. A person presenting a membership credential from a member community reads with their own tools.

Not yet built (see the design's delivery plan):
- the VTC side on `vtn/*` tasks (`vtc/networks/*` 0.2); a community's group inbox is still `{ envelope }` over HTTPS (A15)
- VTI roles and approvals
- trust-task transports (TSP/DIDComm)
- TSP/DIDComm delivery transports (A15)

## Run

### On a VTA (production)

```sh
nnm keys generate                                    # your admin DID: put it in `admins`
vtn setup --setup-key-out setup-key.json --context vtn
#   at the VTA:  pnm contexts create --id vtn --name "Verifiable Trust Network" \
#                  --admin-did <setup DID> --admin-expires 1h
#                pnm did-templates create templates/vtn-host.json --context vtn
cp vtn-setup.example.toml vtn-setup.toml             # edit, then:
vtn setup --from vtn-setup.toml                      # VTA mints the did:webvh, keys go to [secrets]
vtn --config /srv/vtn/vtn.toml serve
nnm networks add whn https://whn.example.org
nnm status
```

### Development (no VTA)

```sh
nnm keys generate
cp vtn.example.toml vtn.toml        # put the DID in `admins`
cargo run --bin vtn -- init         # local did:key identity
cargo run --bin vtn -- serve
nnm networks add dev http://127.0.0.1:8400
```

## NNM

```sh
nnm keys generate | import --did --key-id --private-key-multibase | show
nnm networks add <name> <url> | list | use <name> | remove <name>
nnm status
nnm entries [<did>]
nnm list <did> --kind community|network [--label <label>] [--description …] [--url …] [--tag …]
nnm profile <did> [--label …] [--description …] [--url …] [--tag …]
nnm directory [terms…] [--kind community|network] [--members-only] [--federated]
nnm roles
nnm groups [--role admins]
nnm broadcast --role admins --subject "…" --body "…" [--class notice] [--reply-to <room>]
nnm broadcasts [<id>]
nnm outbox [--retry]
nnm rooms
nnm memberships list | join <url> [--parent <did>] [--role parent=local] | serve <parent> <parent=local> | leave <parent> | repudiate <url> [--parent <did>]
nnm suspend|reinstate|remove <did> [--reason <text>]
nnm graph [--include-exited] [--out graph.json]
nnm index                     # public directories only (A21)
nnm audit
```

## API

Everything is a `vtn/*` 0.1 Trust Task at `POST /v1/trust-tasks`, signed for
`authentication` by its caller (`vti_vtn::tasks`, `VtnClient::task`). The contract and the
error codes are in [`docs/trust-tasks.md`](docs/trust-tasks.md); the normative specifications
are on [trusttasks.org](https://trusttasks.org/spec/vtn/).

| Who | Tasks |
|---|---|
| A listed party | `entries/show`, `membership/{offer,acknowledge,repudiate}`, `groups/register`, `roles/list` |
| A parent network this one joined | `relay/deliver` |
| A person | `rooms/{list,pass}` |
| A reader the directory admits | `directory/{search,federated,summary}`, `graph/{show,member}`, `entries/show`, `roles/list`, `rooms/list` (unsigned under `visibility = "public"`) |
| An administrator | `listings/{create,update,suspend,reinstate,remove,list,show}`, `audit/list`, `groups/list`, `broadcasts/{send,list,show}`, `outbox/{list,retry}`, `memberships/{list,join,repudiate,leave,groups/add}` |

Only what is fetched by URL stays a plain `GET`:

| Path | |
|---|---|
| `/` | Landing page with the searchable directory |
| `/.well-known/vtn` | DID, profile, roles and directory visibility |
| `/v1/status/{revocation\|suspension}` | Signed `BitstringStatusListCredential` |
| `/v1/index` | Signed index of published entries (`visibility = "public"` only, A21) |
| `/v1/credentials/{id}` | A credential the network issued or holds (`visibility = "public"` only, A21) |

A listed party signs its acknowledgement and repudiation with
`vti_vtn::credentials::member::{acknowledge, repudiate}`, and its group registration with
`vti_vtn::groups::register`.

## Repository

| | |
|---|---|
| `CHANGELOG.md` | Unreleased changes. From the first release on, generated by release-plz with git-cliff from conventional commits (`release-plz.toml`, `cliff.toml`) |
| `CONTRIBUTING.md` | Spec-first rules, conventional commits, DCO |
| `deny.toml` | cargo-deny policy, shared with the VTI workspace |
| `.github/` | CI (fmt, clippy `-D warnings`, test, MSRV, cargo-deny), Dependabot, PR template, DCO |
| `templates/vtn-host.json` | The VTA DID template a network is provisioned from |
| `CLAUDE.md` | Working notes for AI-assisted development |

## Test

```sh
cargo test
```

`vtn-service/tests/cascade.rs` runs live networks over real HTTP:
- WHN, with Health-AU as a member network.
- St Vincent's, a community in Health-AU.
- A cycle back to WHN.

A broadcast from WHN reaches St Vincent's through Health-AU with a verifiable hop chain, and the cycle is caught as a duplicate. The tests also cover forged relays, suspension, leaving, and status-checked member credentials.

`vtn-service/tests/network_api.rs` runs the World Health Network example over HTTP. Health-AU,
a second running VTN, acknowledges its listing, and MSF repudiates its own. Health-AU is then
suspended, reinstated, and departs, and is listed again.
