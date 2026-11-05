# Verifying a network and its members

Anyone can check whether a community or network is a member of a VTN, without an account
and without trusting the VTN's word. There are four ways, from quickest to most
independent. What each one proves, and what it doesn't, is set out below.

The rules every check follows:

- **Listing is one-sided.** A network may list a party without asking. The entry is a
  **member** only once the party has acknowledged the listing (VTI-VTN-011, 013). "Listed,
  not acknowledged" is not membership.
- **Indeterminate is never "not a member"** (VTI-REG-012). A registry that can't be
  reached, a status list that can't be fetched, or a credential that can't be verified
  gives no answer. It never gives a negative one.
- **The network and its trust registry must agree.** When one says member and the other
  doesn't, the answer is indeterminate until it is resolved.

## 1. Check membership on the network's page

The landing page's **Check membership** button, visible to everyone, opens a dialog. Enter a
DID and it shows:

- **the trust registry's verdict.** The registry is asked directly from your browser, not
  through the VTN, with a TRQP authorization query for
  `(entity_id = DID, authority_id = network DID, action = "member", resource = "vtn")`.
  If there's no member record, it asks again with `action = "lists"`. The answer is
  member, listed, no record, or unreachable;
- **the network's own answer** (`vtn/entries/show`), and whether the two agree. "Full
  verification" opens the Verify tab for that DID.

Deep links: `https://<network>/#check=<did>` opens the dialog and runs the check, and
`https://<network>/#verify=<did>` opens the Verify tab. Each directory row has a "Verify"
link.

**What it proves:** what the registry and the network say, and that they say the same.
**What it doesn't:** that either is honest. Both answers come from systems the network
controls or chose. A browser can't be asked to query a registry that doesn't allow the
network's site (CORS); the page then says the registry was unreachable.

## 2. The Verify tab

The same check, credential by credential:

| Check | How |
|---|---|
| The network's answer | Its proof names the network's DID |
| Listing (network → party) | Issuer, subject, validity window, a proof by the issuer's key |
| Membership grant (network → party) | The same |
| Acknowledgement (party → network) | The same, issued by the party |
| Status | VTN-issued credentials against the network's revocation and suspension lists, decoded in the browser. The acknowledgement against the party's own lists, as the network checks them |
| Trust registry | Asked directly, as above; it must agree |

The tab also shows **About this network's trust**:
- the network's DID and governance framework, and the directory's visibility;
- the registry it publishes to, what it publishes, and the record shape;
- links to the signed index and the status lists;
- commands to check it yourself.

On a directory that isn't public, an outsider can check the registry but can't see the
entry or its credentials. The tab says so. A member or administrator who signs in sees
them.

**What it doesn't do:** verify signatures cryptographically. The page would have to fetch
the network's keys from the network itself, which proves little. Use `nnm verify` for
that.

## 3. `nnm verify`: independent verification

```sh
nnm verify https://vtn.example did:webvh:…:member \
  --expect did:webvh:…:network      # the network DID you expect
  [--registry https://registry.example]  # default: the one the network's profile names
  [--json] [--resolver-url <did resolver>]
```

It needs no admin key or profile, and trusts nothing the network says without checking it:

1. It reads the network's profile, which must answer as `--expect`.
2. It reads the entry with an unsigned `vtn/entries/show`. The answer must be signed by the
   network's DID, resolved independently.
3. It checks every credential against its issuer's resolved keys, for `assertionMethod`:
   - the listing and the grant against the network's keys;
   - the acknowledgement against the party's keys.

   Each must name the right subject, be inside its validity window, and not be revoked or
   suspended on its issuer's status lists, which are themselves verified as signed by that
   issuer.
4. It asks the trust registry for `(did, network, member, vtn)`, then for `lists`: over TRQP
   when the registry serves HTTPS (`--registry`, or the profile's `queryUrl`). For a
   DIDComm/TSP-only registry it asks through the network (`vtn/registry/check`), and counts
   the answer only when the registry's own signature on it verifies against the registry's
   DID, resolved here, reading the records itself. The report says `relayed by the network`.
   An answer the registry did not sign is indeterminate.

Exit code: `0` member, `1` not a member (listed only, suspended, revoked or absent), `2`
indeterminate (including when the network and the registry disagree). Example:

```
did:webvh:…:first-vtc: MEMBER
network:  https://vtn.openvtc.net (did:webvh:…:squeeze-magic)
network says:  acknowledged
registry says: member (https://registry.example)

  [ok  ] network identity: answers as did:webvh:…:squeeze-magic
  [ok  ] network answer: signed by did:webvh:…:squeeze-magic
  [ok  ] listing credential: issued by …, about …, valid from …
  [ok  ] listing status: not revoked or suspended (or carries no status)
  [ok  ] membership grant: …
  [ok  ] acknowledgement: issued by did:webvh:…:first-vtc, about did:webvh:…:squeeze-magic, …
  [ok  ] trust registry: holds (did, network, member, vtn)
```

For a directory that isn't public, step 2 can't be done. The registry's answer then stands
alone, and with no registry the answer is indeterminate.

## 4. Ask the registry directly

The registry the network publishes to is named in its profile (`GET /.well-known/vtn`,
`trustRegistry`). Any TRQP client can ask it:

```sh
curl -s -X POST https://registry.example/authorization \
  -H 'content-type: application/json' \
  -d '{"authority_id":"<network DID>","entity_id":"<DID>","action":"member","resource":"vtn"}'
```

`200 { "authorized": true }` means a member record. `404` means no record; ask again with
`"action":"lists"` for a listed party, if the network publishes those (`publishes:
"members-and-listed"`). The network writes these records with its own DID as the authority,
so no other writer to the same registry can add or remove them.

## 5. Verify the credentials with any VC tool

Every credential is a W3C Verifiable Credential (DTG), signed `eddsa-jcs-2022`:
- the listing and grant by the network;
- the acknowledgement by the member.

Download them from the directory's credential links (or the Verify tab's raw answer) and
verify them with any VC verifier that resolves `did:webvh` and checks Bitstring Status
Lists.

## For a browser to query the registry

A registry that speaks **DIDComm or TSP only** cannot be asked from a browser. The page then
asks the network to relay (`vtn/registry/check`): the network asks the registry over its own
session and returns the registry's signed answer, and the page says the answer was relayed,
and whether it is signed by the registry's DID. That is weaker than asking directly; for the
full check run `nnm verify`, which verifies the registry's signature on the relayed answer
against the registry's DID, resolved independently.

For a registry that serves HTTPS, the landing page queries it from the visitor's browser.
That needs two things:

- the network's profile names the registry's public query URL (`trustRegistry.queryUrl`),
  and the page's Content-Security-Policy allows it;
- the registry allows the network's site as a CORS origin. On the Affinidi trust registry,
  add the network's URL to `CORS_ALLOWED_ORIGINS`.
