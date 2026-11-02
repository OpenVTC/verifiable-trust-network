# vtn-core

The domain logic of a Verifiable Trust Network (VTN). It does no I/O, so it can be used
by the service, the NNM, tests and a future browser build alike.

| Module | What |
|---|---|
| `model` | Entries (community or network), entry state, entry profile, network profile, directory `Visibility` |
| `lifecycle` | The entry state machine. Membership is reachable only through the listed party's acknowledgement (VTI-VTN-013). |
| `credentials` | DTG credential builders: listing VSC, unsigned membership offer, and the member-side `acknowledge` / `repudiate` |
| `verify` | Credential and signed-document verification behind a purpose-checked `KeyResolver` (`assertionMethod` / `authentication`) |
| `identity` | Signing as a party through any `affinidi_data_integrity` signer: a local key, or a VTA-minted one |
| `status` | W3C Bitstring Status Lists, for revocation and suspension |
| `index`, `graph`, `directory` | The signed index, the DTG graph export (one edge per credential), and directory search |

Behaviour that depends on open working-group questions is marked `A<n>`. See
[`../docs/assumptions.md`](../docs/assumptions.md).
