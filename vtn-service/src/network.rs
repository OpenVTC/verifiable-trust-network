//! The network: curation, membership and publication.
//!
//! Every mutation runs under one write lock. A VTN's write rate is a curator's, not a
//! crowd's, so serialising them buys simple, obviously-correct status allocation and state
//! transitions at no practical cost.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use dtg_credentials::{DTGCredential, DTGCredentialType};
use serde_json::Value;
use tokio::sync::Mutex;
use vtn_core::VtnError;
use vtn_core::credentials::{listing_vsc, membership_offer};
use vtn_core::directory::{self, DirectoryEntry, DirectoryQuery, DirectorySummary};
use vtn_core::graph::{self, EdgeStatus, Graph};
use vtn_core::identity::Identity;
use vtn_core::index::{self, NetworkIndex};
use vtn_core::lifecycle::{Event, transition};
use vtn_core::model::{
    Entry, EntryKind, EntryProfile, EntryState, Issued, NetworkProfile, StateChange,
};
use vtn_core::status::{self, Purpose, credential_status};
use vtn_core::verify::{
    KeyResolver, Repudiated, verify_acknowledgement, verify_repudiation, verify_signed_by,
};

use vtn_client::{CredentialState, StatusChecker, VtnClient};
use vtn_core::groups::RoleDef;

use crate::config::RelayConfig;
use crate::error::{ApiError, ApiResult};
use crate::store::{AuditEvent, VtnStore};

/// Network behaviour from configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    pub grant_validity: Duration,
    pub roles: Vec<RoleDef>,
    pub relay: RelayConfig,
    pub directory: crate::config::DirectoryConfig,
    pub rooms: Vec<crate::rooms::RoomDef>,
    pub status_cache: Duration,
}

pub struct Network {
    pub profile: NetworkProfile,
    pub(crate) identity: Identity,
    pub(crate) base_url: String,
    pub(crate) store: VtnStore,
    pub(crate) resolver: Arc<dyn KeyResolver>,
    pub(crate) status: StatusChecker,
    pub(crate) http: reqwest::Client,
    pub(crate) settings: Settings,
    pub(crate) directory: crate::config::DirectoryConfig,
    pub(crate) index_cache:
        Mutex<std::collections::HashMap<String, (DateTime<Utc>, vtn_core::index::NetworkIndex)>>,
    pub(crate) write: Mutex<()>,
}

impl Network {
    pub fn new(
        profile: NetworkProfile,
        identity: Identity,
        base_url: String,
        store: VtnStore,
        resolver: Arc<dyn KeyResolver>,
        settings: Settings,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("HTTP client");
        let status =
            StatusChecker::with_client(VtnClient::with_http(http.clone(), ""), resolver.clone())
                .with_cache_ttl(settings.status_cache);
        Self {
            profile,
            identity,
            base_url,
            store,
            resolver,
            status,
            http,
            directory: settings.directory.clone(),
            settings,
            index_cache: Mutex::default(),
            write: Mutex::new(()),
        }
    }

    /// A client for another network at `url`.
    pub(crate) fn client(&self, url: &str) -> VtnClient {
        VtnClient::with_http(self.http.clone(), url)
    }

    pub fn roles(&self) -> &[RoleDef] {
        &self.settings.roles
    }

    pub fn role(&self, name: &str) -> Option<&RoleDef> {
        self.settings.roles.iter().find(|r| r.name == name)
    }

    pub fn did(&self) -> &str {
        self.identity.did()
    }

    // ---------------------------------------------------------------- reads

    pub async fn entry(&self, did: &str) -> ApiResult<Entry> {
        self.store
            .entry(did)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("no entry for {did}")))
    }

    pub async fn entries(&self) -> ApiResult<Vec<Entry>> {
        Ok(self.store.entries().await?)
    }

    pub async fn audit(&self) -> ApiResult<Vec<AuditEvent>> {
        Ok(self.store.audit().await?)
    }

    /// The membership offer a listed party acknowledges: the unsigned grant (A2).
    pub async fn offer(&self, did: &str) -> ApiResult<Value> {
        let entry = self.entry(did).await?;
        match (&entry.offer, entry.state) {
            (Some(offer), EntryState::Listed) => Ok(offer.credential.clone()),
            _ => Err(VtnError::InvalidTransition {
                from: entry.state,
                event: "offer",
            }
            .into()),
        }
    }

    /// A credential the network issued or holds, by `id`.
    pub async fn credential(&self, id: &str) -> ApiResult<Value> {
        let not_found = || ApiError::NotFound(format!("no credential {id}"));
        let did = self
            .store
            .credential_owner(id)
            .await?
            .ok_or_else(not_found)?;
        let entry = self.entry(&did).await?;
        let id_of = |v: &Value| v.get("id").and_then(Value::as_str) == Some(id);
        [
            Some(&entry.listing.credential),
            entry.grant.as_ref().map(|g| &g.credential),
            entry.ack.as_ref(),
            entry.repudiation.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find(|v| id_of(v))
        .cloned()
        .ok_or_else(not_found)
    }

    /// The signed network index.
    pub async fn index(&self) -> ApiResult<Value> {
        let entries = self.store.entries().await?;
        let index: NetworkIndex = index::build(&self.profile, &entries, Utc::now());
        Ok(self
            .identity
            .sign_document(serde_json::to_value(index).map_err(VtnError::from)?)
            .await?)
    }

    /// The DTG graph of this network.
    pub async fn graph(&self, include_exited: bool) -> ApiResult<Graph> {
        let entries = self.store.entries().await?;
        let revoked = self.store.status_list(Purpose::Revocation).await?;
        let suspended = self.store.status_list(Purpose::Suspension).await?;
        let lookup = |i| {
            if revoked.get(i) {
                EdgeStatus::Revoked
            } else if suspended.get(i) {
                EdgeStatus::Suspended
            } else {
                EdgeStatus::Valid
            }
        };
        Ok(graph::export(
            &self.profile,
            &entries,
            &lookup,
            include_exited,
        ))
    }

    /// The signed status list credential for `purpose`.
    pub async fn status_list(&self, purpose: Purpose) -> ApiResult<Value> {
        let bits = self.store.status_list(purpose).await?;
        let unsigned =
            status::status_list_credential(self.did(), &self.base_url, purpose, &bits, Utc::now())?;
        Ok(self.identity.sign_document(unsigned).await?)
    }

    // ------------------------------------------------------- network actions

    /// List `did` (VTI-VTN-010). Needs nothing from the listed party.
    pub async fn list(
        &self,
        did: &str,
        kind: EntryKind,
        label: Option<String>,
        profile: EntryProfile,
        actor: &str,
    ) -> ApiResult<Entry> {
        if did == self.did() {
            return Err(ApiError::BadRequest("a network cannot list itself".into()));
        }
        if !did.starts_with("did:") {
            return Err(VtnError::InvalidDid(did.to_string()).into());
        }
        let _guard = self.write.lock().await;
        let existing = self.store.entry(did).await?;
        let from = existing.as_ref().map(|e| e.state);
        let to = transition(from, Event::List)?;
        let now = Utc::now();

        // Re-listing a repudiated entry: its old listing is superseded, so revoke it.
        if let Some(old) = &existing
            && old.state == EntryState::Repudiated
        {
            self.store
                .set_status(Purpose::Revocation, old.listing.status_index, true)
                .await?;
        }

        let listing = self.issue_listing(did, kind, now).await?;
        let offer = self.new_offer(did, now).await?;
        let mut history = existing.map(|e| e.history).unwrap_or_default();
        history.push(StateChange {
            at: now,
            from,
            to,
            reason: None,
        });
        let entry = Entry {
            did: did.to_string(),
            kind,
            label,
            profile,
            state: to,
            created_at: now,
            updated_at: now,
            listing,
            offer: Some(offer),
            grant: None,
            ack: None,
            repudiation: None,
            history,
        };
        self.save(&entry, Event::List, actor, None).await?;
        Ok(entry)
    }

    pub async fn suspend(
        &self,
        did: &str,
        reason: Option<String>,
        actor: &str,
    ) -> ApiResult<Entry> {
        self.network_action(did, Event::Suspend, reason, actor, |grant| {
            vec![(Purpose::Suspension, grant, true)]
        })
        .await
    }

    pub async fn reinstate(
        &self,
        did: &str,
        reason: Option<String>,
        actor: &str,
    ) -> ApiResult<Entry> {
        self.network_action(did, Event::Reinstate, reason, actor, |grant| {
            vec![(Purpose::Suspension, grant, false)]
        })
        .await
    }

    /// Delist `did`. Every credential the network issued for the entry is revoked
    /// (VTI-VTN-053); the member's own credentials are the member's (VTI-VTN-063).
    pub async fn remove(&self, did: &str, reason: Option<String>, actor: &str) -> ApiResult<Entry> {
        let _guard = self.write.lock().await;
        let mut entry = self.entry(did).await?;
        let to = transition(Some(entry.state), Event::Remove)?;
        self.revoke_all(&entry).await?;
        self.drop_groups(did).await?;
        entry.offer = None;
        self.apply(&mut entry, to, reason.clone());
        self.save(&entry, Event::Remove, actor, reason).await?;
        Ok(entry)
    }

    /// Edit an entry's directory profile. Re-issues nothing: the profile is the network's
    /// description, not part of any credential.
    pub async fn update_profile(
        &self,
        did: &str,
        label: Option<String>,
        profile: EntryProfile,
        actor: &str,
    ) -> ApiResult<Entry> {
        let _guard = self.write.lock().await;
        let mut entry = self.entry(did).await?;
        transition(Some(entry.state), Event::Update)?;
        if label.is_some() {
            entry.label = label;
        }
        entry.profile = profile;
        entry.updated_at = Utc::now();
        self.save(&entry, Event::Update, actor, None).await?;
        Ok(entry)
    }

    // -------------------------------------------------------------- directory

    pub async fn directory(&self, query: &DirectoryQuery) -> ApiResult<Vec<DirectoryEntry>> {
        Ok(directory::search(&self.store.entries().await?, query))
    }

    pub async fn directory_summary(&self) -> ApiResult<DirectorySummary> {
        Ok(directory::summary(&self.store.entries().await?))
    }

    /// Check a person's membership credential for member sign-in: a VMC grant naming
    /// `holder`, signed by a community that is a current member of this network. Returns that
    /// community's DID.
    ///
    /// The grant's status is resolved against the community's own status lists, verified as
    /// signed by the community.
    pub async fn verify_member_credential(&self, vmc: &Value, holder: &str) -> ApiResult<String> {
        let refuse = |why: &str| ApiError::Vtn(VtnError::Rejected(why.to_string()));
        let issuer = vmc
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("membership credential has no issuer"))?
            .to_string();
        let community = self
            .store
            .entry(&issuer)
            .await?
            .filter(|e| e.kind == EntryKind::Community && e.state.is_membership())
            .ok_or_else(|| {
                refuse("the credential's issuer is not a member community of this network")
            })?;
        let credential =
            verify_signed_by(vmc, &community.did, self.resolver.as_ref(), Utc::now()).await?;
        if !matches!(credential.type_(), DTGCredentialType::Membership)
            || credential.subject_digest().is_some()
        {
            return Err(refuse("not a community-issued membership credential"));
        }
        if credential.subject() != holder {
            return Err(refuse("the membership credential names someone else"));
        }
        // An unreachable or unverifiable status list is indeterminate, so refused
        // (VTI-REG-012).
        match self.status.check(vmc).await {
            Ok(CredentialState::Valid) => Ok(community.did),
            Ok(state) => Err(refuse(&format!("the membership credential is {state:?}"))),
            Err(e) => Err(refuse(&format!(
                "the membership credential's status is indeterminate: {e}"
            ))),
        }
    }

    // ------------------------------------------------ listed-party actions

    /// The listed party acknowledges: verify its VMC over the offer, then sign the grant.
    pub async fn acknowledge(&self, did: &str, ack: Value) -> ApiResult<Entry> {
        let _guard = self.write.lock().await;
        let mut entry = self.entry(did).await?;
        let to = transition(Some(entry.state), Event::Acknowledge)?;
        let missing = self.missing_required_roles(did).await?;
        if !missing.is_empty() {
            return Err(VtnError::Rejected(format!(
                "register a group for each required role before acknowledging: {}",
                missing.join(", ")
            ))
            .into());
        }
        let offer = entry
            .offer
            .clone()
            .ok_or_else(|| VtnError::Internal("listed entry has no offer".into()))?;
        let mut grant: DTGCredential =
            serde_json::from_value(offer.credential.clone()).map_err(VtnError::from)?;

        verify_acknowledgement(&ack, &grant, did, self.resolver.as_ref(), Utc::now()).await?;

        self.identity.sign_credential(&mut grant).await?;
        let grant_json = serde_json::to_value(&grant).map_err(VtnError::from)?;
        self.index_credential(&grant_json, did).await?;
        self.index_credential(&ack, did).await?;
        entry.grant = Some(Issued {
            credential: grant_json,
            status_index: offer.status_index,
        });
        entry.offer = None;
        entry.ack = Some(ack);
        self.apply(&mut entry, to, None);
        self.save(&entry, Event::Acknowledge, did, None).await?;
        Ok(entry)
    }

    /// The listed party repudiates its listing (VTI-VTN-012), or its grant (departure).
    pub async fn repudiate(&self, did: &str, repudiation: Value) -> ApiResult<Entry> {
        let _guard = self.write.lock().await;
        let mut entry = self.entry(did).await?;
        let target = verify_repudiation(
            &repudiation,
            did,
            self.did(),
            &entry.listing.credential,
            entry.grant.as_ref().map(|g| &g.credential),
            self.resolver.as_ref(),
            Utc::now(),
        )
        .await?;
        let event = match target {
            Repudiated::Listing => Event::Repudiate,
            Repudiated::Grant => Event::Depart,
        };
        let to = transition(Some(entry.state), event)?;

        match target {
            // The listing stays published, with the repudiation beside it. The offer goes:
            // there is nothing left to acknowledge.
            Repudiated::Listing => {
                if let Some(offer) = &entry.offer {
                    self.store
                        .set_status(Purpose::Revocation, offer.status_index, true)
                        .await?;
                }
            }
            Repudiated::Grant => self.revoke_all(&entry).await?,
        }
        self.drop_groups(did).await?;
        entry.offer = None;
        self.index_credential(&repudiation, did).await?;
        entry.repudiation = Some(repudiation);
        self.apply(&mut entry, to, None);
        self.save(&entry, event, did, None).await?;
        Ok(entry)
    }

    // ------------------------------------------------------------- helpers

    async fn network_action(
        &self,
        did: &str,
        event: Event,
        reason: Option<String>,
        actor: &str,
        bits: impl FnOnce(u32) -> Vec<(Purpose, u32, bool)>,
    ) -> ApiResult<Entry> {
        let _guard = self.write.lock().await;
        let mut entry = self.entry(did).await?;
        let to = transition(Some(entry.state), event)?;
        let grant = entry
            .grant
            .as_ref()
            .ok_or_else(|| VtnError::Internal("membership without a grant".into()))?
            .status_index;
        for (purpose, index, value) in bits(grant) {
            self.store.set_status(purpose, index, value).await?;
        }
        self.apply(&mut entry, to, reason.clone());
        self.save(&entry, event, actor, reason).await?;
        Ok(entry)
    }

    async fn issue_listing(
        &self,
        did: &str,
        kind: EntryKind,
        now: DateTime<Utc>,
    ) -> ApiResult<Issued> {
        let index = self.store.allocate_status_index().await?;
        let mut vsc = listing_vsc(
            self.did(),
            did,
            kind,
            &self.profile.framework,
            now,
            credential_status(&self.base_url, index),
        )?;
        self.identity.sign_credential(&mut vsc).await?;
        let credential = serde_json::to_value(&vsc).map_err(VtnError::from)?;
        self.index_credential(&credential, did).await?;
        Ok(Issued {
            credential,
            status_index: index,
        })
    }

    async fn new_offer(&self, did: &str, now: DateTime<Utc>) -> ApiResult<Issued> {
        let index = self.store.allocate_status_index().await?;
        let offer = membership_offer(
            self.did(),
            did,
            now,
            Some(now + self.settings.grant_validity),
            credential_status(&self.base_url, index),
        );
        Ok(Issued {
            credential: serde_json::to_value(&offer).map_err(VtnError::from)?,
            status_index: index,
        })
    }

    async fn revoke_all(&self, entry: &Entry) -> ApiResult<()> {
        let indexes = [
            Some(&entry.listing),
            entry.offer.as_ref(),
            entry.grant.as_ref(),
        ];
        for issued in indexes.into_iter().flatten() {
            self.store
                .set_status(Purpose::Revocation, issued.status_index, true)
                .await?;
        }
        Ok(())
    }

    async fn index_credential(&self, credential: &Value, did: &str) -> ApiResult<()> {
        if let Some(id) = credential.get("id").and_then(Value::as_str) {
            self.store.index_credential(id, did).await?;
        }
        Ok(())
    }

    fn apply(&self, entry: &mut Entry, to: EntryState, reason: Option<String>) {
        let now = Utc::now();
        entry.history.push(StateChange {
            at: now,
            from: Some(entry.state),
            to,
            reason,
        });
        entry.state = to;
        entry.updated_at = now;
    }

    /// Append an audit event without changing the entry.
    pub(crate) async fn record(
        &self,
        did: &str,
        event: Event,
        state: EntryState,
        actor: &str,
        reason: Option<String>,
    ) -> ApiResult<()> {
        self.store
            .append_audit(&AuditEvent {
                at: Utc::now(),
                did: did.to_string(),
                event,
                to: state,
                actor: actor.to_string(),
                reason,
            })
            .await?;
        Ok(())
    }

    async fn save(
        &self,
        entry: &Entry,
        event: Event,
        actor: &str,
        reason: Option<String>,
    ) -> ApiResult<()> {
        self.store.put_entry(entry).await?;
        self.store
            .append_audit(&AuditEvent {
                at: entry.updated_at,
                did: entry.did.clone(),
                event,
                to: entry.state,
                actor: actor.to_string(),
                reason,
            })
            .await?;
        tracing::info!(did = %entry.did, event = event.as_str(), state = %entry.state, actor, "entry updated");
        Ok(())
    }
}
