<!--
Title: a conventional commit, e.g. `fix(service): …`, or `feat(core)!: …` for a breaking
change. It becomes the changelog entry.
-->

## What and why

## Requirements

<!-- VTI-VTN-… / DTG identifiers this implements or touches, and any assumption
(A<n> in docs/assumptions.md) it adds, changes or retires. -->

## Checklist

- [ ] Tests cover the change
- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `docs/assumptions.md` updated if an open-WG assumption changed
- [ ] No `version =` edits in any `Cargo.toml` (release-plz owns versions)
