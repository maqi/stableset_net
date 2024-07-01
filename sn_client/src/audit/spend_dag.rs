// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls::SecretKey;
use petgraph::dot::Dot;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use sn_transfers::{
    is_genesis_spend, CashNoteRedemption, Hash, NanoTokens, OutputPurpose, SignedSpend,
    SpendAddress,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use super::dag_error::{DagError, SpendFault};

/// A DAG representing the spends from a specific Spend all the way to the UTXOs.
/// Starting from Genesis, this would encompass all the spends that have happened on the network
/// at a certain point in time.
///
/// ```text
///                                   -> Spend7 ---> UTXO_11
///                                 /
/// Genesis -> Spend1 -----> Spend2 ---> Spend5 ---> UTXO_10
///                   \
///                     ---> Spend3 ---> Spend6 ---> UTXO_9
///                     \
///                       -> Spend4 ---> UTXO_8
///
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendDag {
    /// A directed graph of spend addresses
    dag: DiGraph<SpendAddress, NanoTokens>,
    /// All the spends refered to in the dag indexed by their SpendAddress
    spends: BTreeMap<SpendAddress, DagEntry>,
    /// The source of the DAG (aka Genesis)
    source: SpendAddress,
    /// Recorded faults in the DAG
    faults: BTreeMap<SpendAddress, BTreeSet<SpendFault>>,
}

type DagIndex = usize;

/// Internal Dag entry type
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
enum DagEntry {
    NotGatheredYet(DagIndex),
    DoubleSpend(Vec<(SignedSpend, DagIndex)>),
    Spend(Box<SignedSpend>, DagIndex),
}

impl DagEntry {
    fn indexes(&self) -> Vec<DagIndex> {
        match self {
            DagEntry::NotGatheredYet(idx) => vec![*idx],
            DagEntry::DoubleSpend(spends) => spends.iter().map(|(_, idx)| *idx).collect(),
            DagEntry::Spend(_, idx) => vec![*idx],
        }
    }

    fn spends(&self) -> Vec<&SignedSpend> {
        match self {
            DagEntry::Spend(spend, _) => vec![&**spend],
            DagEntry::DoubleSpend(spends) => spends.iter().map(|(s, _)| s).collect(),
            DagEntry::NotGatheredYet(_) => vec![],
        }
    }
}

/// The result of a get operation on the DAG
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SpendDagGet {
    /// Spend does not exist in the DAG
    SpendNotFound,
    /// Spend key is refered to by known spends but does not exist in the DAG yet
    Utxo,
    /// Spend is a double spend
    DoubleSpend(Vec<SignedSpend>),
    /// Spend is in the DAG
    Spend(Box<SignedSpend>),
}

impl SpendDag {
    /// Create a new DAG with a given source
    pub fn new(source: SpendAddress) -> Self {
        Self {
            dag: DiGraph::new(),
            spends: BTreeMap::new(),
            source,
            faults: BTreeMap::new(),
        }
    }

    pub fn source(&self) -> SpendAddress {
        self.source
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let bytes = std::fs::read(path)?;
        let dag: SpendDag = rmp_serde::from_slice(&bytes)?;
        Ok(dag)
    }

    pub fn dump_to_file<P: AsRef<Path>>(&self, path: P) -> crate::Result<()> {
        let bytes = rmp_serde::to_vec(&self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Insert a spend into the dag
    /// Creating edges (links) from its ancestors and to its descendants
    /// If the inserted spend is already known, it will be ignored
    /// If the inserted spend is a double spend, it will be saved along with the previous spend
    /// Return true if the spend was inserted and false if it was already in the DAG
    pub fn insert(&mut self, spend_addr: SpendAddress, spend: SignedSpend) -> bool {
        let existing_entry = self.spends.get(&spend_addr).cloned();
        let new_node_idx = match existing_entry {
            // add new spend to the DAG
            None => {
                let node_idx = self.dag.add_node(spend_addr);
                self.spends.insert(
                    spend_addr,
                    DagEntry::Spend(Box::new(spend.clone()), node_idx.index()),
                );
                node_idx
            }
            // or upgrade a known but not gathered entry to spend
            Some(DagEntry::NotGatheredYet(idx)) => {
                self.spends
                    .insert(spend_addr, DagEntry::Spend(Box::new(spend.clone()), idx));
                let node_idx = NodeIndex::new(idx);
                self.remove_all_edges(node_idx);
                node_idx
            }
            // or upgrade spend to double spend if it is different from the existing one
            Some(DagEntry::Spend(s, idx)) => {
                let existing_spend = *s.clone();
                if existing_spend == spend {
                    return false;
                }

                let node_idx = self.dag.add_node(spend_addr);
                let double_spend = DagEntry::DoubleSpend(vec![
                    (existing_spend.clone(), idx),
                    (spend.clone(), node_idx.index()),
                ]);
                self.spends.insert(spend_addr, double_spend);
                node_idx
            }
            // or add extra spend to an existing double spend if it is unknown yet
            Some(DagEntry::DoubleSpend(vec_s)) => {
                if vec_s.iter().any(|(s, _idx)| s == &spend) {
                    return false;
                }

                let node_idx = self.dag.add_node(spend_addr);
                let mut vec_s = vec_s.clone();
                vec_s.push((spend.clone(), node_idx.index()));
                self.spends.insert(spend_addr, DagEntry::DoubleSpend(vec_s));
                node_idx
            }
        };

        // link to descendants
        for (descendant, (amount, _purpose)) in spend.spend.descendants.iter() {
            let descendant_addr = SpendAddress::from_unique_pubkey(descendant);

            // add descendant if not already in dag
            let spends_at_addr = self.spends.entry(descendant_addr).or_insert_with(|| {
                let node_idx = self.dag.add_node(descendant_addr);
                DagEntry::NotGatheredYet(node_idx.index())
            });

            // link to descendant
            for idx in spends_at_addr.indexes() {
                let descendant_idx = NodeIndex::new(idx);
                self.dag.update_edge(new_node_idx, descendant_idx, *amount);
            }
        }

        // do not link to ancestors if the spend is the source
        if spend_addr == self.source {
            return true;
        }

        // link to ancestors
        const PENDING_AMOUNT: NanoTokens = NanoTokens::from(0);
        for ancestor in spend.spend.ancestors.iter() {
            let ancestor_addr = SpendAddress::from_unique_pubkey(ancestor);

            // add ancestor if not already in dag
            let spends_at_addr = self.spends.entry(ancestor_addr).or_insert_with(|| {
                let node_idx = self.dag.add_node(ancestor_addr);
                DagEntry::NotGatheredYet(node_idx.index())
            });

            // link to ancestor
            match spends_at_addr {
                DagEntry::NotGatheredYet(idx) => {
                    let ancestor_idx = NodeIndex::new(*idx);
                    self.dag
                        .update_edge(ancestor_idx, new_node_idx, PENDING_AMOUNT);
                }
                DagEntry::Spend(ancestor_spend, idx) => {
                    let ancestor_idx = NodeIndex::new(*idx);
                    let ancestor_given_amount = ancestor_spend
                        .spend
                        .descendants
                        .iter()
                        .find(|(descendant, (_amount, _purpose))| {
                            **descendant == spend.spend.unique_pubkey
                        })
                        .map(|(_descendant, (amount, _purpose))| *amount)
                        .unwrap_or(PENDING_AMOUNT);
                    self.dag
                        .update_edge(ancestor_idx, new_node_idx, ancestor_given_amount);
                }
                DagEntry::DoubleSpend(multiple_ancestors) => {
                    for (ancestor_spend, ancestor_idx) in multiple_ancestors {
                        if ancestor_spend.address() == spend.address() {
                            let ancestor_idx = NodeIndex::new(*ancestor_idx);
                            let ancestor_given_amount = ancestor_spend
                                .spend
                                .descendants
                                .iter()
                                .find(|(descendant, (_amount, _purpose))| {
                                    **descendant == spend.spend.unique_pubkey
                                })
                                .map(|(_descendant, (amount, _purpose))| *amount)
                                .unwrap_or(PENDING_AMOUNT);
                            self.dag
                                .update_edge(ancestor_idx, new_node_idx, ancestor_given_amount);
                        }
                    }
                }
            }
        }

        true
    }

    /// Get spend addresses that probably exist as they are refered to by spends we know,
    /// but we haven't gathered them yet
    /// This includes UTXOs and unknown ancestors
    pub fn get_pending_spends(&self) -> BTreeSet<SpendAddress> {
        self.spends
            .iter()
            .filter_map(|(addr, entry)| match entry {
                DagEntry::NotGatheredYet(_) => Some(*addr),
                _ => None,
            })
            .collect()
    }

    /// Get the UTXOs: all the addresses that are refered to as children by other spends
    /// but that don't have children themselves.
    /// Those will eventually exist on the Network as the address is spent by their owners.
    pub fn get_utxos(&self) -> BTreeSet<SpendAddress> {
        let mut leaves = BTreeSet::new();
        for node_index in self.dag.node_indices() {
            if !self
                .dag
                .neighbors_directed(node_index, petgraph::Direction::Outgoing)
                .any(|_| true)
            {
                let utxo_addr = self.dag[node_index];
                leaves.insert(utxo_addr);
            }
        }
        leaves
    }

    pub fn dump_dot_format(&self) -> String {
        format!("{:?}", Dot::with_config(&self.dag, &[]))
    }

    pub fn dump_payment_forward_statistics(&self, sk: &SecretKey) -> String {
        let mut statistics: BTreeMap<String, Vec<NanoTokens>> = Default::default();

        let mut hash_dictionary: BTreeMap<Hash, String> = Default::default();

        // The following three is used in the memcheck test script.
        // Update whenever these three got changed in the script.
        let bootstrap_string = "bootstrap".to_string();
        let restart_string = "restart".to_string();
        let restarted_string = "restarted".to_string();
        let _ = hash_dictionary.insert(Hash::hash(bootstrap_string.as_bytes()), bootstrap_string);
        let _ = hash_dictionary.insert(Hash::hash(restart_string.as_bytes()), restart_string);
        let _ = hash_dictionary.insert(Hash::hash(restarted_string.as_bytes()), restarted_string);
        for i in 0..50 {
            let node_string = format!("node_{i}");
            let _ = hash_dictionary.insert(Hash::hash(node_string.as_bytes()), node_string);
        }

        for spend_dag_entry in self.spends.values() {
            if let DagEntry::Spend(signed_spend, _) = spend_dag_entry {
                if let Some(sender_hash) = signed_spend.spend.reason.get_sender_hash(sk) {
                    let sender = if let Some(readable_sender) = hash_dictionary.get(&sender_hash) {
                        readable_sender.clone()
                    } else {
                        format!("{sender_hash:?}")
                    };
                    let holders = statistics.entry(sender).or_default();
                    holders.push(signed_spend.spend.amount());
                }
            }
        }

        let mut content = "Sender, Times, Amount".to_string();
        for (sender, payments) in statistics.iter() {
            let total_amount: u64 = payments
                .iter()
                .map(|nano_tokens| nano_tokens.as_nano())
                .sum();
            content = format!("{content}\n{sender}, {}, {total_amount}", payments.len());
        }
        content
    }

    /// Merges the given dag into ours, optionally recomputing the faults after merge
    /// If verify is set to false, the faults will not be computed, this can be useful when batching merges to avoid re-verifying
    /// be sure to manually verify afterwards
    pub fn merge(&mut self, sub_dag: SpendDag, verify: bool) -> Result<(), DagError> {
        let source = self.source();
        info!(
            "Merging sub DAG starting at {:?} into our DAG with source {:?}",
            sub_dag.source(),
            source
        );
        for (addr, spends) in sub_dag.spends {
            // only add spends to the dag, ignoring utxos and not yet gathered relatives
            // utxos will be added automatically as their ancestors are added
            // edges are updated by the insert method
            match spends {
                DagEntry::NotGatheredYet(_) => continue,
                DagEntry::DoubleSpend(spends) => {
                    for (spend, _) in spends {
                        self.insert(addr, spend);
                    }
                }
                DagEntry::Spend(spend, _) => {
                    self.insert(addr, *spend);
                }
            }
        }

        // recompute faults
        if verify {
            self.record_faults(&source)?;
        }

        Ok(())
    }

    /// Get the spend at a given address
    pub fn get_spend(&self, addr: &SpendAddress) -> SpendDagGet {
        match self.spends.get(addr) {
            None => SpendDagGet::SpendNotFound,
            Some(DagEntry::NotGatheredYet(_)) => SpendDagGet::Utxo,
            Some(DagEntry::DoubleSpend(spends)) => {
                SpendDagGet::DoubleSpend(spends.iter().map(|(s, _)| s.clone()).collect())
            }
            Some(DagEntry::Spend(spend, _)) => SpendDagGet::Spend(spend.clone()),
        }
    }

    /// Get the recorded faults if any for a given spend address
    pub fn get_spend_faults(&self, addr: &SpendAddress) -> BTreeSet<SpendFault> {
        self.faults.get(addr).cloned().unwrap_or_default()
    }

    /// Helper to get underlying index of spend entry in the DAG
    /// This unstable API is used to access the underlying graph for testing purposes
    /// An empty vec is returned if the spend is not in the DAG
    pub fn get_spend_indexes(&self, addr: &SpendAddress) -> Vec<usize> {
        self.spends
            .get(addr)
            .map(|spends| spends.indexes())
            .unwrap_or_default()
    }

    /// Get all spends from the DAG
    pub fn all_spends(&self) -> Vec<&SignedSpend> {
        self.spends
            .values()
            .flat_map(|entry| entry.spends())
            .collect()
    }

    /// Get the faults recorded in the DAG
    pub fn faults(&self) -> &BTreeMap<SpendAddress, BTreeSet<SpendFault>> {
        &self.faults
    }

    /// Get all royalties from the DAG
    pub fn all_royalties(&self) -> crate::Result<Vec<CashNoteRedemption>> {
        let spends = self.all_spends();
        let mut royalties = Vec::new();
        for s in spends {
            for (_descendant, (_amount, purpose)) in s.spend.descendants.iter() {
                if let OutputPurpose::RoyaltyFee(derivation_index) = purpose {
                    let spend_addr = SpendAddress::from_unique_pubkey(&s.spend.unique_pubkey);
                    royalties.push(CashNoteRedemption::new(*derivation_index, spend_addr));
                }
            }
        }
        Ok(royalties)
    }

    /// Remove all edges from a Node in the DAG
    fn remove_all_edges(&mut self, node: NodeIndex) {
        let incoming: Vec<_> = self
            .dag
            .edges_directed(node, petgraph::Direction::Incoming)
            .map(|e| e.id())
            .collect();
        let outgoing: Vec<_> = self
            .dag
            .edges_directed(node, petgraph::Direction::Outgoing)
            .map(|e| e.id())
            .collect();
        for edge in incoming.into_iter().chain(outgoing.into_iter()) {
            self.dag.remove_edge(edge);
        }
    }

    /// helper that returns the direct ancestors of a given spend
    /// along with any faults detected
    /// On error returns the address of the missing ancestor
    fn get_direct_ancestors(
        &self,
        spend: &SignedSpend,
    ) -> Result<(BTreeSet<SignedSpend>, BTreeSet<SpendFault>), SpendAddress> {
        let addr = spend.address();
        let mut ancestors = BTreeSet::new();
        let mut faults = BTreeSet::new();
        for ancestor in spend.spend.ancestors.iter() {
            let ancestor_addr = SpendAddress::from_unique_pubkey(ancestor);
            match self.spends.get(&ancestor_addr) {
                Some(DagEntry::Spend(ancestor_spend, _)) => {
                    ancestors.insert(*ancestor_spend.clone());
                }
                Some(DagEntry::NotGatheredYet(_)) | None => {
                    warn!("Direct ancestor of {spend:?} at {ancestor_addr:?} is missing");
                    return Err(ancestor_addr);
                }
                Some(DagEntry::DoubleSpend(multiple_ancestors)) => {
                    debug!("Direct ancestor for spend {spend:?} at {ancestor_addr:?} is a double spend");
                    faults.insert(SpendFault::DoubleSpentAncestor {
                        addr,
                        ancestor: ancestor_addr,
                    });
                    let actual_ancestor: Vec<_> = multiple_ancestors
                        .iter()
                        .filter(|(s, _)| s.address() == spend.address())
                        .map(|(s, _)| s.clone())
                        .collect();
                    match actual_ancestor.as_slice() {
                        [ancestor_spend] => {
                            debug!("Direct ancestor of {spend:?} at {ancestor_addr:?} is a double spend but one of those match our parent_tx hash, using it for verification");
                            ancestors.insert(ancestor_spend.clone());
                        }
                        [ancestor1, _ancestor2, ..] => {
                            warn!("Direct ancestor of {spend:?} at {ancestor_addr:?} is a double spend and mutliple match our parent_tx hash, using the first one for verification");
                            ancestors.insert(ancestor1.clone());
                        }
                        [] => {
                            warn!("Direct ancestor of {spend:?} at {ancestor_addr:?} is a double spend and none of them match the spend parent_tx, which means the parent for this spend is missing!");
                            return Err(ancestor_addr);
                        }
                    }
                }
            }
        }
        Ok((ancestors, faults))
    }

    /// helper that returns all the descendants (recursively all the way to UTXOs) of a given spend
    fn all_descendants(&self, addr: &SpendAddress) -> Result<BTreeSet<&SpendAddress>, DagError> {
        let mut descendants = BTreeSet::new();
        let mut to_traverse = BTreeSet::from_iter(vec![addr]);
        while let Some(current_addr) = to_traverse.pop_first() {
            // get the spend at this address
            let dag_entry = match self.spends.get(current_addr) {
                Some(entry) => entry,
                None => {
                    warn!("Incoherent DAG, missing descendant spend when expecting one at: {current_addr:?}");
                    return Err(DagError::IncoherentDag(
                        *current_addr,
                        format!("Missing descendant spend in DAG at: {current_addr:?}"),
                    ));
                }
            };
            let (spends, indexes) = (dag_entry.spends(), dag_entry.indexes());

            // get descendants via spend
            let descendants_via_spend: BTreeSet<SpendAddress> = spends
                .into_iter()
                .flat_map(|s| s.spend.descendants.keys())
                .map(SpendAddress::from_unique_pubkey)
                .collect();

            // get descendants via DAG
            let descendants_via_dag: BTreeSet<&SpendAddress> = indexes
                .into_iter()
                .flat_map(|idx| {
                    self.dag
                        .neighbors_directed(NodeIndex::new(idx), petgraph::Direction::Outgoing)
                        .map(|i| &self.dag[i])
                })
                .collect();

            // report inconsistencies
            if descendants_via_dag != descendants_via_spend.iter().collect() {
                if matches!(dag_entry, DagEntry::NotGatheredYet(_)) {
                    debug!("Spend at {current_addr:?} was not gathered yet and has children refering to it, continuing traversal through those children...");
                } else {
                    warn!("Incoherent DAG at: {current_addr:?}");
                    return Err(DagError::IncoherentDag(
                        *current_addr,
                        format!("descendants via DAG: {descendants_via_dag:?} do not match descendants via spend: {descendants_via_spend:?}")
                    ));
                }
            }

            // continue traversal
            let not_transversed = descendants_via_dag.difference(&descendants);
            to_traverse.extend(not_transversed);
            descendants.extend(descendants_via_dag.iter().cloned());
        }
        Ok(descendants)
    }

    /// find all the orphans in the DAG and record them as OrphanSpend
    /// returns the list of OrphanSpend and other errors encountered in the way
    fn find_orphans(&self, source: &SpendAddress) -> Result<BTreeSet<SpendFault>, DagError> {
        let mut recorded_faults = BTreeSet::new();
        let all_addresses: BTreeSet<&SpendAddress> = self.spends.keys().collect();
        let all_descendants = self.all_descendants(source)?;
        let parents: BTreeSet<_> = self
            .get_spend_indexes(source)
            .into_iter()
            .flat_map(|idx| {
                self.dag
                    .neighbors_directed(NodeIndex::new(idx), petgraph::Direction::Incoming)
            })
            .map(|parent_idx| &self.dag[parent_idx])
            .collect();
        let non_orphans =
            BTreeSet::from_iter(all_descendants.into_iter().chain(parents).chain([source]));

        // orphans are those that are neither descandants nor source's parents nor source itself
        let orphans: BTreeSet<&SpendAddress> =
            all_addresses.difference(&non_orphans).cloned().collect();
        for orphan in orphans {
            let src = *source;
            let addr = *orphan;
            debug!("Found orphan: {orphan:?} of {src:?}");
            recorded_faults.insert(SpendFault::OrphanSpend { addr, src });
        }

        Ok(recorded_faults)
    }

    /// Checks if a double spend has multiple living descendant branches that fork
    fn double_spend_has_forking_descendant_branches(&self, spends: &Vec<&SignedSpend>) -> bool {
        // gather all living descendants for each branch
        let mut set_of_living_descendants: BTreeSet<BTreeSet<_>> = BTreeSet::new();
        for spend in spends {
            let gathered_descendants = spend
                .spend
                .descendants
                .iter()
                .map(|(descendant, (_amount, _purpose))| {
                    SpendAddress::from_unique_pubkey(descendant)
                })
                .filter_map(|a| self.spends.get(&a))
                .filter_map(|s| {
                    if matches!(s, DagEntry::NotGatheredYet(_)) {
                        None
                    } else {
                        Some(s.spends())
                    }
                })
                .flatten()
                .collect::<BTreeSet<_>>();
            set_of_living_descendants.insert(gathered_descendants);
        }

        // make sure there is no fork
        for set1 in set_of_living_descendants.iter() {
            for set2 in set_of_living_descendants.iter() {
                if set1.is_subset(set2) || set2.is_subset(set1) {
                    continue;
                } else {
                    return true;
                }
            }
        }

        false
    }

    /// Verify the DAG and record faults in the DAG
    /// If the DAG is invalid, return an error immediately, without mutating the DAG
    pub fn record_faults(&mut self, source: &SpendAddress) -> Result<(), DagError> {
        let faults = self.verify(source)?;

        self.faults.clear();
        for f in faults {
            self.faults.entry(f.spend_address()).or_default().insert(f);
        }
        Ok(())
    }

    /// Verify the DAG and return faults detected in the DAG
    /// If the DAG itself is invalid, return an error immediately
    pub fn verify(&self, source: &SpendAddress) -> Result<BTreeSet<SpendFault>, DagError> {
        info!("Verifying DAG starting off: {source:?}");
        let mut recorded_faults = BTreeSet::new();

        // verify the DAG is acyclic
        if petgraph::algo::is_cyclic_directed(&self.dag) {
            warn!("DAG is cyclic");
            return Err(DagError::DagContainsCycle(*source));
        }

        // verify DAG source exists in the DAG (Genesis in case of a complete DAG)
        debug!("Verifying DAG source: {source:?}");
        match self.spends.get(source) {
            None => {
                debug!("DAG does not contain its source: {source:?}");
                return Err(DagError::MissingSource(*source));
            }
            Some(DagEntry::DoubleSpend(_)) => {
                debug!("DAG source is a double spend: {source:?}");
                recorded_faults.insert(SpendFault::DoubleSpend(*source));
            }
            _ => (),
        }

        // identify orphans (spends that don't come from the source)
        debug!("Looking for orphans of {source:?}");
        recorded_faults.extend(self.find_orphans(source)?);

        // check all transactions
        for (addr, _) in self.spends.iter() {
            debug!("Verifying transaction at: {addr:?}");
            // get the spend at this address
            let spends = self
                .spends
                .get(addr)
                .map(|s| s.spends())
                .unwrap_or_default();

            // record double spends
            if spends.len() > 1 {
                debug!("Found a double spend entry in DAG at {addr:?}");
                recorded_faults.insert(SpendFault::DoubleSpend(*addr));
                let direct_descendants: BTreeSet<SpendAddress> = spends
                    .iter()
                    .flat_map(|s| s.spend.descendants.keys())
                    .map(SpendAddress::from_unique_pubkey)
                    .collect();
                debug!("Making the direct descendants of the double spend at {addr:?} as faulty: {direct_descendants:?}");
                for a in direct_descendants.iter() {
                    recorded_faults.insert(SpendFault::DoubleSpentAncestor {
                        addr: *a,
                        ancestor: *addr,
                    });
                }
                if self.double_spend_has_forking_descendant_branches(&spends) {
                    debug!("Double spend at {addr:?} has multiple living descendant branches, poisoning them...");
                    let poison = format!(
                        "spend is on one of multiple branches of a double spent ancestor: {addr:?}"
                    );
                    let direct_living_descendant_spends: BTreeSet<_> = direct_descendants
                        .iter()
                        .filter_map(|a| self.spends.get(a))
                        .flat_map(|s| s.spends())
                        .collect();
                    for s in direct_living_descendant_spends {
                        recorded_faults.extend(self.poison_all_descendants(s, poison.clone())?);
                    }
                }
                continue;
            }

            // skip parent Tx verification for source as we don't know its ancestors
            if addr == source {
                debug!("Skip transaction verification for source at: {addr:?}");
                continue;
            }

            // verify parent Tx
            for s in spends {
                recorded_faults.extend(self.verify_parent_tx(s)?);
            }
        }

        info!(
            "Found {} faults: {recorded_faults:#?}",
            recorded_faults.len()
        );
        Ok(recorded_faults)
    }

    /// Verifies a single spend and returns resulting errors and DAG poisoning spread
    fn verify_parent_tx(&self, spend: &SignedSpend) -> Result<BTreeSet<SpendFault>, DagError> {
        let addr = spend.address();
        let mut recorded_faults = BTreeSet::new();
        debug!("Verifying spend at: {addr:?}");

        // skip if spend matches genesis
        if is_genesis_spend(spend) {
            debug!("Skip transaction verification for Genesis at: {addr:?}");
            return Ok(recorded_faults);
        }

        // get the ancestors of this spend
        let (ancestor_spends, faults) = match self.get_direct_ancestors(spend) {
            Ok(a) => a,
            Err(missing_ancestor) => {
                debug!("Failed to get ancestor spends of {addr:?} as ancestor at {missing_ancestor:?} is missing");
                recorded_faults.insert(SpendFault::MissingAncestry {
                    addr,
                    ancestor: missing_ancestor,
                });

                let poison = format!("missing ancestor at: {missing_ancestor:?}");
                let descendants_faults = self.poison_all_descendants(spend, poison)?;
                recorded_faults.extend(descendants_faults);
                return Ok(recorded_faults);
            }
        };
        recorded_faults.extend(faults);

        // verify the tx
        if let Err(e) = spend.verify_parent_spends(&ancestor_spends) {
            warn!("Parent Tx verfication failed for spend at: {addr:?}: {e}");
            recorded_faults.insert(SpendFault::InvalidTransaction(addr, format!("{e}")));
            let poison = format!("ancestor transaction was poisoned at: {addr:?}: {e}");
            let descendants_faults = self.poison_all_descendants(spend, poison)?;
            recorded_faults.extend(descendants_faults);
        }

        Ok(recorded_faults)
    }

    /// Poison all descendants of a spend with given the poison message
    fn poison_all_descendants(
        &self,
        spend: &SignedSpend,
        poison: String,
    ) -> Result<BTreeSet<SpendFault>, DagError> {
        let mut recorded_faults = BTreeSet::new();
        let direct_descendants = spend
            .spend
            .descendants
            .iter()
            .map(|(descendant, (_amount, _purpose))| SpendAddress::from_unique_pubkey(descendant))
            .collect::<BTreeSet<_>>();
        let mut all_descendants = direct_descendants
            .iter()
            .map(|addr| self.all_descendants(addr))
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<BTreeSet<&SpendAddress>>();
        all_descendants.extend(direct_descendants.iter());

        for d in all_descendants {
            recorded_faults.insert(SpendFault::PoisonedAncestry(*d, poison.clone()));
        }

        Ok(recorded_faults)
    }
}

#[cfg(test)]
mod tests {
    use xor_name::XorName;

    use super::*;

    #[test]
    fn test_spend_dag_serialisation() {
        let mut rng = rand::thread_rng();
        let dummy_source = SpendAddress::new(XorName::random(&mut rng));
        let dag = SpendDag::new(dummy_source);
        let serialized_data = rmp_serde::to_vec(&dag).expect("Serialization failed");
        let deserialized_instance: SpendDag =
            rmp_serde::from_slice(&serialized_data).expect("Deserialization failed");
        let reserialized_data =
            rmp_serde::to_vec(&deserialized_instance).expect("Serialization failed");
        assert_eq!(reserialized_data, serialized_data);
    }
}
