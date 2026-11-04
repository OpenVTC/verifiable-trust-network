//! Who is asking. Every request is a signed Trust Task document and the proof's signer is
//! the caller (VTI-VTN-004): there is no sign-in and no session (`docs/trust-tasks.md`).
//!
//! What a caller may do follows from their [`Standing`], decided per request:
//! - **Admin:** the signer is in `admins` (the NNM signs this way).
//! - **Member, as an entity:** the signer is a member VTC or VTN of this network.
//! - **Member, by credential:** the signer is a person (or agent) whose request carries a
//!   membership credential (VMC) naming them, issued by a community that is a current
//!   member of this network. The holder's proof plus the community's grant is sufficient
//!   (DTG Core, Membership Edge Completion).
//! - **Listed:** the signer is listed but not a member. It reads its own entry and offer.
//! - **Anyone:** an unsigned request, or a signer with no standing here.
//!
//! Browser keys a wallet approves (`auth/oob/*`) and keys an administrator delegates
//! (`auth/signing-key/*`) come later; until then a signer is a DID acting as itself.

use vti_vtn::model::Visibility;

/// The administrators of this network.
#[derive(Debug, Clone)]
pub struct Auth {
    admins: Vec<String>,
}

impl Auth {
    pub fn new(admins: Vec<String>) -> Self {
        Self { admins }
    }

    pub fn admins(&self) -> &[String] {
        &self.admins
    }

    pub fn is_admin(&self, did: &str) -> bool {
        self.admins.iter().any(|a| a == did)
    }
}

/// What a request's signer is to this network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Unsigned, or a signer with no relationship here.
    Anyone,
    /// Listed, not (or no longer) a member.
    Listed,
    /// A member VTC or VTN, as itself.
    MemberEntity,
    /// A person presenting a member community's VMC.
    MemberByCredential {
        community: String,
    },
    Admin,
}

impl Standing {
    pub fn is_admin(&self) -> bool {
        matches!(self, Standing::Admin)
    }

    pub fn is_member(&self) -> bool {
        matches!(
            self,
            Standing::MemberEntity | Standing::MemberByCredential { .. }
        )
    }
}

/// May a caller of `standing` read the published set under `visibility`?
pub fn can_read_directory(visibility: Visibility, standing: &Standing) -> bool {
    match visibility {
        Visibility::Public => true,
        Visibility::Members => standing.is_admin() || standing.is_member(),
        Visibility::Admins => standing.is_admin(),
    }
}
