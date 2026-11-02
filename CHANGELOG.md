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
- **nnm**: the Network Network Manager CLI: admin keys, networks, sign-in, curation commands, entry profiles, graph, index and audit.

### Documentation

- Design (`docs/vtn-design.md`), working assumptions on open WG questions (`docs/assumptions.md`), and the DTG WG proposal for VMC support of VTN membership (discussion #82, PR #83).
