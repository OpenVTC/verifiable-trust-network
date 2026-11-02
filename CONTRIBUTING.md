# Contribution Guidelines

Thank you for contributing! This repository follows the OpenVTC conventions of
[verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
(Code of Conduct, CLA, DCO sign-off).

## The specifications

This workspace implements the Verifiable Trust Network chapter of the VTI specification
(`dtgwg-vti-spec/spec/11a-vtn.md`, requirements `VTI-VTN-*`) on the DTG credentials
specification (`dtgwg-cred-spec`). Where code and specification disagree, the
specification is what is correct.

- **Cite requirements by identifier** (`VTI-VTN-013`) in PR descriptions, in comments that
  explain a constraint, and in the names of tests that hold a requirement.
- **Open WG questions are assumptions, not decisions.** Each one is recorded in
  [`docs/assumptions.md`](docs/assumptions.md) as `A<n>` and named at the code that
  depends on it. A change that adds, moves or retires an assumption updates that file in
  the same PR.

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check advisories bans sources licenses
```

The minimum supported Rust version is the `rust-version` in the root `Cargo.toml`. It is
the same as the VTI workspace, whose published crates (`vti-common`, `vta-sdk`,
`vti-secrets`, `dtg-credentials`) this one builds on.

## Commits and changelog

- **PR titles are conventional commits**: `feat(service): …`, `fix(core): …`,
  `feat(nnm)!: …` for a breaking change. Scopes: `core`, `service`, `nnm`, `docs`, `ci`,
  `deps`.
- **Squash merges** make the PR title the commit subject. The body should say what
  changed, why, and what it breaks. **The commit message is the changelog entry**:
  release-plz builds `CHANGELOG.md` from it with git-cliff (`cliff.toml`). Don't edit
  released sections by hand.
- **Sign off every commit** (`git commit -s`) for the DCO.
