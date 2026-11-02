VMC for VTN membership: members of a VTN are VTCs *and* VTNs

## Context

The VTI spec's VTN chapter (`dtgwg-vti-spec/spec/11a-vtn.md`) defines a VTN that lists both communities and other networks, nested to any depth (VTI-VTN-030…033). Listing may be one-sided, and becomes membership only once the listed party acknowledges it (VTI-VTN-010…014). We are starting an implementation (a separate `vtn-service`), and every VTN relationship needs to be a DTG credential. The VMC is the natural fit for VTN membership, and the spec already goes most of the way:

- The VMC's purpose covers membership "in a VTC or VTN" (§VMC, Purpose).
- The issuer of the community-issued VMC may be a VTN (§VMC, Schema, `issuer`).
- Where both ends are communities, `digestMultibase` is the grant/ack discriminator (§VMC, Schema, intro paragraph).
- The VIC has a VTN-invitation variant (§VIC).

This issue asks the WG to close the remaining gaps so that a VTN's membership edges, including nested ones, are fully specified.

## 1. Subject of a VTN-issued VMC: VTC **or VTN**

§VMC Schema, `credentialSubject.id` for the community-issued VMC currently reads: *"…or, for VTN-to-VTC membership, a member VTC"*. VTN-to-VTN membership (e.g. state networks → national network → global network) isn't named. §VIC has the same gap: the VTN-invitation subject is *"DID of the prospective member VTC"*.

**Proposed:** "…or, for VTN membership, a member VTC or a member VTN" in both places.

## 2. Membership does not chain through nesting

If VTC *C* ∈ VTN *N1* and *N1* ∈ VTN *N2*, the two VMC pairs establish two edges. They do not establish *C* ∈ *N2*. The VTI spec requires this (VTI-VTN-032/033, VTI-REG-024), but nothing in the credential spec stops a verifier from composing VMC pairs into an implied membership.

**Proposed** (Membership Edge Completion): *A VMC pair establishes membership only between its two parties. A verifier MUST NOT infer membership of a party in a VTN from a chain of VMC pairs through intermediate networks. Each pair in such a chain is evaluated independently.*

## 3. Listing vs grant ordering

The two specs order things differently:

- **DTG spec:** the community-issued VMC is issued **first**, and the acknowledgement carries its digest. An unacknowledged grant is legitimate; it just isn't evidence of membership (§Membership Edge Completion).
- **VTI-VTN-013:** a VTN *"MUST NOT issue a membership credential to a party that has not acknowledged its entry."*

So how should a one-sided VTN **listing** be expressed?

- **(a) As an unacknowledged VMC grant.** No new vocabulary, and consistent with Membership Edge Completion. However, it contradicts VTI-VTN-013 as worded, and it makes a grant mean both "you are a member if you accept" and "we list you whether or not you accept".
- **(b) As a VSC under a `lists` predicate profile** (subject = listed party, object value = `{ kind: community | network, framework }`). The VMC grant is issued only once the listed party has agreed. Repudiation is a VSC from the listed party carrying the listing's `digestMultibase`.

We lean towards **(b)**. A listing is a statement about a third party ("attests, never establishes"), whereas a grant is an offer of membership. If the WG agrees, should `lists` / `repudiates` be core profiles in the DTG VSC registry, or should they live in a VTN-owned namespace?

## 4. Anchor sets that contain networks

§Edge Verifiability defines the anchor set as a set of VTCs and notes that *"a VTN is the common case of such an anchor set."* Once a VTN's members include VTNs, "anchor set = this VTN" is ambiguous: does it mean its direct VTC members only, or every VTC reachable through member networks?

**Proposed:** expanding a VTN into an anchor set is a verifier policy. That policy MUST name the VTN, the version of its governance framework, and the nesting depth it follows. Only **completed** VMC pairs count at each hop. This mirrors VTI-VTN-023.

## 5. Status of the member-issued VMC when the member is a community

The editor's note on the membership lifecycle defers where a verifier discovers the status of the member-issued VMC. When the member is a VTC or VTN, it already runs its own status list, so status under the member's control is available today. VTI-VTN-053 requires removal to show up in credential status.

**Question:** may a member-issued VMC whose issuer is a VTC/VTN carry `credentialStatus` now, ahead of the general mechanism?

## 6. Related issues

- **#53 (`nodeType`):** `VTC` / `VTN` on the VMC subject would let a verifier tell whether an entry points at members or at further entries (VTI-VTN-031). Please confirm that the `VTN` definition there allows members that are VTNs.
- **#75 (`issuerScope` of a community identifier):** this affects the scope a community-member declares on its acknowledgement.
