# vtn-client

Talking to a Verifiable Trust Network from outside it. Used by the `nnm` CLI and by
`vtn-service` when one network deals with another: a VTN joining a parent network, or a
relay hop in a broadcast.

- `VtnClient`: the network's profile, DID sign-in (challenge → `authentication`-signed
  document → session), and authenticated JSON requests. A sign-in is bound to the network
  DID the caller expects, never to what the server claims.
- `StatusChecker`: resolves a credential's `credentialStatus` against its issuer's W3C
  Bitstring Status Lists. Each list credential is verified as signed by the credential's
  issuer, and lists are cached briefly. An unreachable or unverifiable list is
  *indeterminate* (an error), never "not revoked" (VTI-REG-012).
