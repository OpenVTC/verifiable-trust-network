# vtn-service

The `vtn` binary: a Verifiable Trust Network service.

- **Identity:** `vtn setup` provisions the network's `did:webvh` on a VTA from the
  [`vtn-host`](../templates/vtn-host.json) DID template, and keeps the keys in a
  `vti-secrets` store (VTI-VTN-001). `vtn init` creates a development `did:key` instead.
- **Store:** fjall, through `vti-common`.
- **API:** listing, membership, repudiation, status lists, the signed index, and the DTG
  graph. See the root [README](../README.md#api).
- **Sign-in:** administrators are DIDs and sign in from the NNM. Members sign in as their
  VTC or VTN DID, or as a person presenting a membership credential from a member
  community.
- **Landing page** (`web/index.html`, served at `/`): the network's profile and a
  searchable member directory. Who may see the directory is set in configuration:

```toml
[directory]
visibility  = "public"   # "public" | "members" | "admins"
show_counts = true       # show member counts even when the directory is restricted
```

`visibility` governs every read that reveals the published set: the directory, the index,
the graph, entries and credentials. Status lists and the network profile stay public. In
a restricted network, a listed party reads its own offer only when signed in as itself.
