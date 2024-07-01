// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Network, NetworkError, Result};
use futures::future::join_all;
use sn_transfers::{is_genesis_spend, SignedSpend, SpendAddress, TransferError};
use std::collections::BTreeSet;

impl Network {
    /// This function verifies a single spend.
    /// This is used by nodes for spends validation, before storing them.
    /// - It checks if the spend has valid ancestry, that its parents exist on the Network
    /// - It checks that the spend has a valid signature and content
    /// - It does NOT check if the spend exists online
    /// - It does NOT check if the spend is already spent on the Network
    pub async fn verify_spend(&self, spend: &SignedSpend) -> Result<()> {
        let unique_key = spend.unique_pubkey();
        debug!("Verifying spend {unique_key}");
        spend.verify()?;

        // genesis does not have parents so we end here
        if is_genesis_spend(spend) {
            debug!("Verified {unique_key} was Genesis spend!");
            return Ok(());
        }

        // get its parents
        let parent_keys = spend.spend.ancestors.clone();
        let tasks: Vec<_> = parent_keys
            .iter()
            .map(|a| self.get_spend(SpendAddress::from_unique_pubkey(a)))
            .collect();
        let parent_spends: BTreeSet<SignedSpend> = join_all(tasks)
            .await
            .into_iter()
            .collect::<Result<BTreeSet<_>>>()
            .map_err(|e| {
                let s = format!("Failed to get parent spend of {unique_key:?}: {e}");
                warn!("{}", s);
                NetworkError::Transfer(TransferError::InvalidParentSpend(s))
            })?;

        // verify the parents
        spend.verify_parent_spends(parent_spends.iter())?;

        Ok(())
    }
}
