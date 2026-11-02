# Working assumptions

These are the assumptions the implementation makes where the DTG and VTI working groups
haven't decided yet. The code names each one as `A<n>`. When the WG decides, change the code
at the places listed for that assumption.

WG threads:
- [dtgwg-cred-spec discussion #82](https://github.com/trustoverip/dtgwg-cred-spec/discussions/82)
- [PR #83](https://github.com/trustoverip/dtgwg-cred-spec/pull/83)

| # | Assumption | Open question | Where |
|---|---|---|---|
| A1 | **A listing is a VSC**, under predicate `https://openvtc.org/vtn/vsc/lists/1`. It is not an unacknowledged VMC grant. The VTN profiles (`lists`, `repudiates`, `servesRole`, `groupRegistered`) live in an OpenVTC namespace until they are registered. | #82 item 3 | `vtn-core/src/vocab.rs`, `credentials::listing_vsc` |
| A2 | **Membership is offered unsigned.** The network publishes the VMC grant's claims without a proof. The party signs an acknowledgement over their digest, and the network signs the grant only after that. The digest excludes `proof`, so the acknowledgement matches the signed grant. This satisfies both DTG Core (grant before acknowledgement, digest-bound) and VTI-VTN-013 (no membership credential before the party agrees). | #82 item 3 | `credentials::membership_offer`, `Network::acknowledge` |
| A3 | **A VTN's members may be VTCs or VTNs.** The VMC subject can be either. | PR #83 item 1 | used throughout; entries carry `kind` |
| A4 | **The member's acknowledgement declares `issuerScope: public`.** If no `validUntil` is given, it defaults to the grant's. The network does not hold the acknowledgement's status, so the graph marks it `unchecked`. | PR #83 item 5, issue #75 | `credentials::member::acknowledge`, `graph::export` |
| A5 | **The identity is VTA-provisioned (done).** `vtn setup` asks the VTA to mint the network's `did:webvh` from the `vtn-host` template (`templates/vtn-host.json`), registered in the context. The service keeps the VTA-minted keys in a `vti-secrets` store and signs with the Ed25519 key, `#key-0`. Parties are resolved through the VTA SDK's purpose-checking resolver (VTI-KEY-022). The remaining assumptions: <ul><li>The template is operator-registered rather than a VTA built-in.</li><li>Only the Ed25519 key signs. A post-quantum second proof, as the VTC does, comes later.</li><li>`vtn init` keeps a development `did:key` with no VTA.</li></ul> | — | `vtn-service/src/{setup,identity}.rs` |
| A6 | **Admins are DIDs** listed in `admins` in `vtn.toml`. They sign in with a challenge, which they sign for `authentication`. This is what the NNM does. Sessions are held in memory. VTI roles (owner, curator, broadcaster, auditor) and approvals/step-up (VTI-VTN-004/005) are still to come. | — | `vtn-service/src/auth.rs` |
| A7 | **Status lists:** each issued credential gets one index, used in both the `revocation` and the `suspension` Bitstring Status List. The VTN serves both lists itself. | — | `vtn-core/src/status.rs` |
| A8 | **Repudiation semantics:** <ul><li>Repudiating the listing makes the entry `repudiated`. The listing stays published next to the repudiation, and the pending offer is revoked.</li><li>Repudiating the grant makes the entry `departed`. Everything the network issued for it is revoked.</li><li>The network may list a party again after it repudiates. The old listing is revoked. Whether that is allowed is a governance-framework question.</li></ul> | VTI-VTN-012 | `lifecycle.rs`, `Network::repudiate`, `Network::list` |
| A9 | **REST only.** The routes are shaped like the trust-task families in `docs/vtn-design.md` §10. Generated `vti-specs-vtn` types, plus TSP/DIDComm, come later. | — | `routes.rs` |
| A10 | **This is a standalone workspace.** It depends on the published `vti-common` for its store. It does not wait for the `vti-community-core` extraction (design phase 0). | — | `Cargo.toml` |
| A11 | **The NNM keeps the admin key in its profile file** (`~/.nnm/profile.json`, 0600). PNM and CNM use the OS keyring or a VTA. The admin DID can be a `did:key` the NNM generates, or a VTA-minted DID imported with `nnm keys import`. | — | `nnm-cli/src/profile.rs` |
| A12 | **A person's member sign-in checks the membership credential's signature and validity window, but not its status.** The credential must be a VMC grant naming the person, issued by an acknowledged member community. The community's status list is not fetched; the credential's validity window bounds the exposure. | — | `Network::verify_member_credential` |
| A13 | **Browser sign-in for members is a pasted session token.** The landing page accepts a session token from a wallet or the NNM. A wallet sign-in flow, like the VTC member portal's trigger links (VTI-LNK-*), is still to come. | — | `vtn-service/web/index.html` |
