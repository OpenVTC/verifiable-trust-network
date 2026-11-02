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
| `vtn-core` | Domain model, entry lifecycle, DTG credential builders and verification, status lists, network index, graph export. Holds no I/O. |
| `vtn-service` | The `vtn` binary. It holds the network's VTA-provisioned identity (`vtn setup`), a fjall-backed store (via `vti-common`), the HTTP API, and admin sign-in by DID. |
| `nnm-cli` | The `nnm` binary, the **Network Network Manager**. It is the operator CLI for VTNs, as `pnm` is for a person and `cnm` for a community. It holds the operator's admin key, signs in to networks, and runs curation commands. |

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
- **Admin access.** Administrators are DIDs. They sign in by challenge-response from the `nnm`.
- **Landing page and directory.** Served at `/`: the network's profile, member counts, and a searchable directory (by name, tags, description or DID; filterable by kind and acknowledgement). `[directory] visibility` is `public`, `members` or `admins`. Members sign in as their VTC or VTN DID, or as a person presenting a membership credential from a member community.

Not yet built (see the design's delivery plan):
- network groups and broadcast relay
- federated search
- the graph UI
- network data rooms
- VTI roles and approvals
- trust-task transports (TSP/DIDComm)
- a VTN acknowledging *its own* listing in a parent network from the NNM

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
nnm directory [terms…] [--kind community|network] [--members-only]
nnm token
nnm suspend|reinstate|remove <did> [--reason <text>]
nnm graph [--include-exited] [--out graph.json]
nnm index
nnm audit
```

## API

**Public:**

| Method | Path | |
|---|---|---|
| GET | `/` | Landing page with the searchable directory |
| GET | `/.well-known/vtn` | DID, profile and directory visibility |
| GET | `/v1/directory?q=&kind=&state=&members_only=` | Directory search (visibility-gated) |
| GET | `/v1/directory/summary` | Member counts (public unless `show_counts = false`) |
| GET | `/v1/index` | Signed index of published entries, each with `kind` and `acknowledged` |
| GET | `/v1/graph` | DTG graph: nodes, and one edge per credential with its status |
| GET | `/v1/status/{revocation\|suspension}` | Signed `BitstringStatusListCredential` |
| GET | `/v1/credentials/{id}` | A credential the network issued or holds |
| GET | `/v1/entries/{did}` | One published entry |
| GET | `/v1/entries/{did}/offer` | Unsigned VMC grant, for the listed party to acknowledge |
| POST | `/v1/entries/{did}/acknowledge` | `{ "acknowledgement": <VMC signed by did> }` |
| POST | `/v1/entries/{did}/repudiate` | `{ "repudiation": <VSC signed by did> }` |

Index, graph, entries, credentials and directory follow `[directory] visibility`.

**Sign-in:** `POST /v1/auth/challenge { did }`, then `POST /v1/auth/session { authentication }`. The `authentication` document is `{ type: "VtnAdminAuthentication", did, challenge, audience }`, signed for `authentication`. A person may add `membership`: a VMC from a member community naming them. The session's role is decided at sign-in: admin, member (entity or by credential), or listed. `GET /v1/auth/session` shows it.

**Admin** (`Authorization: Bearer <session>`):

| Method | Path | |
|---|---|---|
| POST | `/v1/admin/entries` | `{ "did", "kind": "community"\|"network", "label"? }` lists a party |
| GET | `/v1/admin/entries[/{did}]` | Full entries, including history |
| POST | `/v1/admin/entries/{did}/{suspend\|reinstate\|remove}` | `{ "reason"? }` |
| GET | `/v1/admin/graph?include_exited=true` | Graph, including removed and departed entries |
| POST | `/v1/admin/entries/{did}/profile` | `{ "label"?, "description"?, "url"?, "tags"? }` edits the directory profile |
| GET | `/v1/admin/audit` | Audit log, with the acting admin DID |
| GET | `/v1/admin/whoami` | The signed-in admin |

A listed party signs with `vtn_core::credentials::member::{acknowledge, repudiate}`.

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

`vtn-service/tests/network_api.rs` runs the World Health Network example over HTTP. Health-AU,
a second running VTN, acknowledges its listing, and MSF repudiates its own. Health-AU is then
suspended, reinstated, and departs, and is listed again.
