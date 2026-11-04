# vtn-service

The `vtn` binary: a Verifiable Trust Network service.

- **Identity:** `vtn setup` provisions the network's `did:webvh` on a VTA from the
  [`vtn-host`](../templates/vtn-host.json) DID template, and keeps the keys in a
  `vti-secrets` store (VTI-VTN-001). `vtn init` creates a development `did:key` instead.
- **Store:** fjall, through `vti-common`.
- **API:** `vtn/*` Trust Tasks at `POST /v1/trust-tasks` (`src/tasks/`), through the shared
  `vti-trust-task-server` pipeline: size, freshness, recipient, the task's own policy, the
  proof, a store-backed duplicate-id record, then dispatch, with every answer signed. See
  the root [README](../README.md#api).
- **Callers:** every request is signed, and its signer is the caller. Administrators are
  DIDs in `admins`. Members are their VTC or VTN DID, or a person presenting a membership
  credential from a member community in the request's `membership`.
- **Landing page** (`web/index.html`, served at `/`): the network's profile and a
  searchable member directory. Who may see the directory is set in configuration:

```toml
[directory]
visibility  = "public"   # "public" | "members" | "admins"
show_counts = true       # show member counts even when the directory is restricted
```

`visibility` governs every read that reveals the published set: the directory, the graph,
entries and rooms. Status lists and the network profile stay public. The index and
credential fetch are unsigned `GET`s, so a restricted network does not serve them (A21). A
listed party always reads its own entry and offer, by signing as itself.
