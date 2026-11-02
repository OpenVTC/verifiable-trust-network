# verifiable-trust-network

The Verifiable Trust Network (VTN): a curated, nestable set of communities (VTCs) and
networks, every relationship a DTG credential. Spec: `dtgwg-vti-spec/spec/11a-vtn.md`
(VTI-VTN-*). Design: `docs/vtn-design.md`. Open-WG assumptions: `docs/assumptions.md` (A<n>).

## Crates

- `vtn-core`: pure domain logic with no I/O. Covers the model, lifecycle, credentials, verification (`KeyResolver`), status lists, index, graph and directory.
- `vtn-service`: the `vtn` binary. Holds the store (`vti-common`), routes, admin and member auth, VTA provisioning (`vtn setup`, `templates/vtn-host.json`), and the landing page (`vtn-service/web/`).
- `nnm-cli`: the `nnm` binary, the Network Network Manager. It is the operator CLI, a sibling of PNM and CNM.

## Rules

- A VTN aggregates; it grants nothing. Never let it change a VTC's membership, create trust contexts or derive keys (VTI-VTN-060..063).
- Unacknowledged is never membership (VTI-VTN-013). Every published entry carries its ack state.
- Verify signatures with a purpose: `assertionMethod` for credentials, `authentication` for sign-in.
- New WG-dependent behaviour gets an `A<n>` in `docs/assumptions.md`.
- Before declaring done: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
