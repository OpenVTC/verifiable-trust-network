# verifiable-trust-network

The Verifiable Trust Network (VTN): a curated, nestable set of communities (VTCs) and
networks, every relationship a DTG credential. Spec: `dtgwg-vti-spec/spec/11a-vtn.md`
(VTI-VTN-*). Design: `docs/vtn-design.md`. Open-WG assumptions: `docs/assumptions.md` (A<n>).

## Crates

The protocol lives in VTI's `vti-vtn` crate (verifiable-trust-infrastructure), shared with the VTC: the model, lifecycle, credentials, verification (`KeyResolver`), status lists, index, graph, directory, groups, relay envelopes and room passes, and (feature `client`) the `vtn/*` Trust Task client and status-list checker. Protocol changes go there first.

- `vtn-service`: the `vtn` binary. Holds the store (`vti-common`), the `vtn/*` Trust Task API (`tasks/`, on `vti-trust-task-server`), the URL-fetched artifacts (`routes.rs`), who-is-asking (`auth.rs`), VTA provisioning (`vtn setup`, `templates/vtn-host.json`), the landing page (`vtn-service/web/`), group registration (`groups.rs`), nested membership (`memberships.rs`), and broadcast and relay (`broadcast.rs`).
- `nnm-cli`: the `nnm` binary, the Network Network Manager. It is the operator CLI, a sibling of PNM and CNM.

## Rules

- A VTN aggregates; it grants nothing. Never let it change a VTC's membership, create trust contexts or derive keys (VTI-VTN-060..063).
- Unacknowledged is never membership (VTI-VTN-013). Every published entry carries its ack state.
- Verify signatures with a purpose: `assertionMethod` for credentials, `authentication` for Trust Task requests.
- The API is `vtn/*` Trust Tasks (`vtn-service/src/tasks/`). A new operation is a spec in the TF repo first, pinned in VTI's `vti-specs-vtn`; REST is only for what is fetched by URL (`docs/trust-tasks.md`).
- New WG-dependent behaviour gets an `A<n>` in `docs/assumptions.md`.
- Before declaring done: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
