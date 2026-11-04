# nnm-cli

`nnm`, the **Network Network Manager**: the operator CLI for Verifiable Trust Networks,
as `pnm` is for a person and `cnm` for a community.

```sh
nnm keys generate                       # your admin DID: add it to the network's `admins`
nnm networks add whn https://whn.example.org
nnm status                              # checks the network's DID and your admin key
nnm list <did> --kind community --label "MSF" --description "…" --tag ngo
nnm profile <did> --description "…" --tag emergency
nnm directory emergency --members-only
nnm entries [<did>]
nnm suspend|reinstate|remove <did> --reason "…"
nnm graph --out graph.json
nnm audit
```

The admin key is kept in `$NNM_HOME/profile.json` (default `~/.nnm/profile.json`), with
owner-only permissions (assumption A11). Every command is a `vtn/*` Trust Task signed with
it, addressed to the network DID recorded by `nnm networks add`; `nnm` refuses a service
that answers as a different DID, and the network refuses a request addressed to another.
