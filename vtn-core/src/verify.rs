//! Verifying credentials a listed party sends the network.
//!
//! Key resolution goes through [`KeyResolver`], which is told the purpose the proof claims:
//! the key must be authorised for it in the signer's DID document (VTI-KEY-022). Credentials
//! are verified under `assertionMethod`, admin sign-in under `authentication`.
//! [`LocalDidKeyResolver`] resolves `did:key` with no I/O; the service resolves `did:webvh`
//! through the VTA SDK's purpose-checking resolver.

use std::future::Future;
use std::pin::Pin;

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use chrono::{DateTime, Utc};
use dtg_credentials::{DTGCredential, DTGCredentialType, digests_match};
use serde_json::Value;

use crate::did_key::did_of_verification_method;
use crate::error::{Result, VtnError};
use crate::vocab::REPUDIATES_V1;

/// The proof purpose a credential's proof must carry.
pub const ASSERTION_METHOD: &str = "assertionMethod";
/// The proof purpose an admin sign-in document's proof must carry.
pub const AUTHENTICATION: &str = "authentication";

pub type KeyFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

/// Resolves a verification method to its public key bytes, refusing a key the DID document
/// does not authorise for `purpose`.
pub trait KeyResolver: Send + Sync {
    fn resolve<'a>(&'a self, verification_method: &'a str, purpose: &'a str) -> KeyFuture<'a>;
}

/// `did:key` only, no I/O. A `did:key`'s key is implicitly authorised for every signing
/// purpose.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalDidKeyResolver;

impl KeyResolver for LocalDidKeyResolver {
    fn resolve<'a>(&'a self, verification_method: &'a str, _purpose: &'a str) -> KeyFuture<'a> {
        Box::pin(async move {
            if !verification_method.starts_with("did:key:") {
                return Err(VtnError::Rejected(format!(
                    "cannot resolve {verification_method}: only did:key resolves locally"
                )));
            }
            Ok(
                affinidi_data_integrity::did_vm::resolve_did_key(verification_method)?
                    .public_key_bytes,
            )
        })
    }
}

/// Check `proof` was made by a key of `expected_signer` for `purpose`, and resolve that key.
async fn signer_key(
    proof: &DataIntegrityProof,
    expected_signer: &str,
    purpose: &str,
    resolver: &dyn KeyResolver,
) -> Result<Vec<u8>> {
    if did_of_verification_method(&proof.verification_method) != expected_signer {
        return Err(VtnError::Rejected(format!(
            "proof by {} is not a key of {expected_signer}",
            proof.verification_method
        )));
    }
    if proof.proof_purpose != purpose {
        return Err(VtnError::Rejected(format!(
            "proof purpose is {}, expected {purpose}",
            proof.proof_purpose
        )));
    }
    resolver.resolve(&proof.verification_method, purpose).await
}

/// Verify a signed JSON document (not a DTG credential): its `proof` was made by
/// `expected_signer` for `purpose`. Used for admin sign-in.
pub async fn verify_document(
    document: &Value,
    expected_signer: &str,
    purpose: &str,
    resolver: &dyn KeyResolver,
) -> Result<()> {
    let mut unsigned = document.clone();
    let proof = unsigned
        .as_object_mut()
        .and_then(|o| o.remove("proof"))
        .ok_or_else(|| VtnError::Rejected("document is not signed".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof)
        .map_err(|e| VtnError::Rejected(format!("unreadable proof: {e}")))?;
    let key = signer_key(&proof, expected_signer, purpose, resolver).await?;
    proof.verify_with_public_key(&unsigned, &key, VerifyOptions::new())?;
    Ok(())
}

/// Parse `json`, and check it was signed by a verification method of `expected_issuer` and
/// is within its validity window at `at`.
pub async fn verify_signed_by(
    json: &Value,
    expected_issuer: &str,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<DTGCredential> {
    let credential: DTGCredential = serde_json::from_value(json.clone())
        .map_err(|e| VtnError::Rejected(format!("not a DTG credential: {e}")))?;

    if credential.issuer() != expected_issuer {
        return Err(VtnError::Rejected(format!(
            "issued by {}, expected {expected_issuer}",
            credential.issuer()
        )));
    }
    let proof = credential
        .credential()
        .proof
        .as_ref()
        .ok_or_else(|| VtnError::Rejected("credential is not signed".into()))?;
    let key = signer_key(proof, expected_issuer, ASSERTION_METHOD, resolver).await?;
    credential.verify_proof_with_public_key(&key)?;

    if credential.valid_from() > at {
        return Err(VtnError::Rejected("credential is not yet valid".into()));
    }
    if credential.valid_until().is_some_and(|until| until <= at) {
        return Err(VtnError::Rejected("credential has expired".into()));
    }
    Ok(credential)
}

/// Verify a membership acknowledgement from `member` against the `offer` it must answer.
pub async fn verify_acknowledgement(
    ack: &Value,
    offer: &DTGCredential,
    member: &str,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<DTGCredential> {
    let ack_credential = verify_signed_by(ack, member, resolver, at).await?;
    if ack_credential.subject() != offer.issuer() {
        return Err(VtnError::Rejected(
            "acknowledgement does not name this network".into(),
        ));
    }
    if !ack_credential.acknowledges(offer)? {
        return Err(VtnError::Rejected(
            "acknowledgement does not match the membership offer".into(),
        ));
    }
    Ok(ack_credential)
}

/// What a repudiation refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repudiated {
    Listing,
    Grant,
}

/// Verify a repudiation VSC from `member`, and say which of `listing` / `grant` it targets.
pub async fn verify_repudiation(
    repudiation: &Value,
    member: &str,
    network: &str,
    listing: &Value,
    grant: Option<&Value>,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<Repudiated> {
    let vsc = verify_signed_by(repudiation, member, resolver, at).await?;
    if !matches!(vsc.type_(), DTGCredentialType::Statement)
        || vsc.predicate() != Some(REPUDIATES_V1)
    {
        return Err(VtnError::Rejected(format!(
            "not a {REPUDIATES_V1} statement"
        )));
    }
    if vsc.subject() != network {
        return Err(VtnError::Rejected(
            "repudiation does not name this network".into(),
        ));
    }
    let digest = vsc
        .subject_digest()
        .ok_or_else(|| VtnError::Rejected("repudiation names no credential".into()))?;

    if digests_match(digest, &dtg_credentials::digest_multibase_json(listing)?)? {
        return Ok(Repudiated::Listing);
    }
    if let Some(grant) = grant
        && digests_match(digest, &dtg_credentials::digest_multibase_json(grant)?)?
    {
        return Ok(Repudiated::Grant);
    }
    Err(VtnError::Rejected(
        "repudiation names neither this entry's listing nor its grant".into(),
    ))
}
