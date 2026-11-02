# Changelog

Notable changes to this workspace. From the first release on, entries are generated from
conventional commits by [git-cliff](https://git-cliff.org) via release-plz
(`cliff.toml`, `release-plz.toml`). Don't edit released sections by hand: write a
conventional-commit PR title and a real commit body (see CONTRIBUTING.md).

## Unreleased

### Features

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
- **nnm**: the Network Network Manager CLI: admin keys, networks, sign-in, curation commands, entry profiles, graph, index and audit. Also `roles`, `groups`, `broadcast`, `broadcasts`, and `memberships list|join|serve|leave|repudiate`.

### Documentation

- Design (`docs/vtn-design.md`), working assumptions on open WG questions (`docs/assumptions.md`), and the DTG WG proposal for VMC support of VTN membership (discussion #82, PR #83).
