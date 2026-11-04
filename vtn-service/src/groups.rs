//! Groups members register for the network's roles (see `vti_vtn::groups`).

use chrono::Utc;
use serde_json::Value;
use vti_vtn::VtnError;
use vti_vtn::groups::{self, RegisteredGroup};
use vti_vtn::lifecycle::Event;
use vti_vtn::model::{EntryState, Issued};
use vti_vtn::status::{Purpose, credential_status};

use crate::error::{ApiError, ApiResult};
use crate::network::Network;

impl Network {
    /// A listed party or member registers one of its groups for a role. Authenticated by the
    /// member's signature on the `servesRole` VSC.
    pub async fn register_group(
        &self,
        member: &str,
        registration: Value,
    ) -> ApiResult<RegisteredGroup> {
        let entry = self.entry(member).await?;
        if !matches!(entry.state, EntryState::Listed | EntryState::Acknowledged) {
            return Err(VtnError::InvalidTransition {
                from: entry.state,
                event: "register-group",
            }
            .into());
        }
        let reg = groups::verify_registration(
            &registration,
            member,
            self.did(),
            self.resolver.as_ref(),
            Utc::now(),
        )
        .await?;
        if self.role(&reg.role).is_none() {
            return Err(ApiError::Vtn(VtnError::Rejected(format!(
                "this network defines no role {:?}",
                reg.role
            ))));
        }

        let _guard = self.write.lock().await;
        if let Some(old) = self.store.group(member, &reg.role).await? {
            self.store
                .set_status(Purpose::Revocation, old.acceptance.status_index, true)
                .await?;
        }
        let index = self.store.allocate_status_index().await?;
        let mut acceptance = groups::acceptance(
            self.did(),
            &reg.group,
            &registration,
            Utc::now(),
            credential_status(&self.base_url, index),
        )?;
        self.identity.sign_credential(&mut acceptance).await?;
        let acceptance = serde_json::to_value(&acceptance).map_err(VtnError::from)?;
        let group = RegisteredGroup {
            member: member.to_string(),
            role: reg.role.clone(),
            group: reg.group,
            endpoint: reg.endpoint,
            registration,
            acceptance: Issued {
                credential: acceptance,
                status_index: index,
            },
            registered_at: Utc::now(),
        };
        self.store.put_group(&group).await?;
        self.record(
            member,
            Event::Update,
            entry.state,
            member,
            Some(format!(
                "registered {} for role {}",
                group.group, group.role
            )),
        )
        .await?;
        Ok(group)
    }

    /// Registered groups, optionally for one role.
    pub async fn groups(&self, role: Option<&str>) -> ApiResult<Vec<RegisteredGroup>> {
        Ok(self
            .store
            .groups()
            .await?
            .into_iter()
            .filter(|g| role.is_none_or(|r| g.role == r))
            .collect())
    }

    /// Required roles `member` has not registered a group for.
    pub(crate) async fn missing_required_roles(&self, member: &str) -> ApiResult<Vec<String>> {
        let mut missing = Vec::new();
        for role in self.roles().iter().filter(|r| r.required) {
            if self.store.group(member, &role.name).await?.is_none() {
                missing.push(role.name.clone());
            }
        }
        Ok(missing)
    }

    /// Drop and revoke every group `member` registered. Callers hold the write lock.
    pub(crate) async fn drop_groups(&self, member: &str) -> ApiResult<()> {
        for group in self.store.groups_of(member).await? {
            self.store
                .set_status(Purpose::Revocation, group.acceptance.status_index, true)
                .await?;
            self.store.remove_group(member, &group.role).await?;
        }
        Ok(())
    }
}
