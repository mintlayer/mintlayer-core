// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    utxo_entry::{IsDirty, IsFresh, UtxoEntry},
    Error, FlushableUtxoView, Utxo, UtxoSource, UtxosBlockRewardUndo, UtxosTxUndo,
    UtxosTxUndoWithSources, UtxosView,
};
use common::{
    chain::{
        block::{BlockReward, BlockRewardTransactable},
        signature::Signable,
        GenBlock, OutPointSourceId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, Id, Idable},
};
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConsumedUtxoCache {
    pub(crate) container: BTreeMap<UtxoOutPoint, UtxoEntry>,
    pub(crate) best_block: Id<GenBlock>,
}

pub struct UtxosCache<P> {
    parent: P,
    current_block_hash: Id<GenBlock>,
    // pub(crate) visibility is required for tests that are in a different mod
    pub(crate) utxos: BTreeMap<UtxoOutPoint, UtxoEntry>,
    // TODO: calculate memory usage (mintlayer/mintlayer-core#354)
    #[allow(dead_code)]
    memory_usage: usize,
}

impl<P: UtxosView> UtxosCache<P> {
    /// Returns a UtxoEntry, given the outpoint.
    // the reason why it's not a `&UtxoEntry`, is because the flags are bound to change esp.
    // when the utxo was actually retrieved from the parent.
    fn fetch_utxo_entry(&mut self, outpoint: &UtxoOutPoint) -> Result<Option<UtxoEntry>, Error> {
        if let Some(res) = self.utxos.get(outpoint) {
            return Ok(Some(res.clone()));
        }

        // since the utxo does not exist in this view, try to check from parent.
        // if the utxo exists in parent:
        // dirty is 'No' because this view does not have the utxo, therefore is different from parent
        // fresh is 'No' because this view does not have the utxo but the parent has.
        let entry = self
            .parent
            .utxo(outpoint)
            .map_err(|_| Error::ViewRead)?
            .map(|utxo| UtxoEntry::new(Some(utxo), IsFresh::No, IsDirty::No));
        if let Some(entry) = &entry {
            self.utxos.insert(outpoint.clone(), entry.clone());
        }
        Ok(entry)
    }

    pub fn new(parent: P) -> Result<Self, P::Error> {
        let current_block_hash = parent.best_block_hash()?;
        Ok(UtxosCache {
            parent,
            current_block_hash,
            utxos: BTreeMap::new(),
            memory_usage: 0,
        })
    }

    pub fn from_data(parent: P, utxos: ConsumedUtxoCache) -> Result<Self, P::Error> {
        Ok(UtxosCache {
            parent,
            current_block_hash: utxos.best_block,
            utxos: utxos.container,
            memory_usage: 0,
        })
    }

    pub fn set_best_block(&mut self, block_hash: Id<GenBlock>) {
        self.current_block_hash = block_hash;
    }

    /// Given a block reward add its outputs to the utxo set
    pub fn add_utxos_from_block_reward(
        &mut self,
        reward: &BlockReward,
        source: UtxoSource,
        block_id: &Id<GenBlock>,
        check_for_overwrite: bool,
    ) -> Result<(), Error> {
        for (idx, output) in reward.outputs().iter().enumerate() {
            let outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(*block_id), idx as u32);
            // block reward transactions can always be overwritten
            let overwrite = if check_for_overwrite {
                self.has_utxo(&outpoint).map_err(|_| Error::ViewRead)?
            } else {
                true
            };
            let utxo = Utxo::new(output.clone(), source.clone());

            self.add_utxo(&outpoint, utxo, overwrite)?;
        }
        Ok(())
    }

    /// Given a transaction add its outputs to the utxo set
    pub fn add_utxos_from_tx(
        &mut self,
        tx: &Transaction,
        source: UtxoSource,
        check_for_overwrite: bool,
    ) -> Result<(), Error> {
        let id = OutPointSourceId::from(tx.get_id());

        tx.outputs()
            .iter()
            .enumerate()
            // not all outputs should be included in the utxo set
            .filter(|(_, output)| should_include_in_utxo_set(output))
            .try_for_each(|(idx, output)| {
                let outpoint = UtxoOutPoint::new(id.clone(), idx as u32);
                // by default no overwrite allowed.
                let has_utxo = self.has_utxo(&outpoint).map_err(|_| Error::ViewRead)?;
                let overwrite = check_for_overwrite && has_utxo;
                let utxo = Utxo::new(output.clone(), source.clone());

                self.add_utxo(&outpoint, utxo, overwrite)
            })
    }

    /// Marks the inputs of a transaction as 'spent', adds outputs to the utxo set.
    /// Returns a TxUndo if function is a success or an error if the tx's input cannot be spent.
    pub fn connect_transaction(
        &mut self,
        tx: &Transaction,
        source: UtxoSource,
    ) -> Result<UtxosTxUndoWithSources, Error> {
        let sources = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(outpoint) => Some(outpoint.source_id()),
                TxInput::Account(..)
                | TxInput::AccountCommand(..)
                | TxInput::OrderAccountCommand(..) => None,
            })
            .collect();

        let utxos = tx
            .inputs()
            .iter()
            .map(|input| match input {
                TxInput::Utxo(outpoint) => self.spend_utxo(outpoint).map(Some),
                TxInput::Account(..)
                | TxInput::AccountCommand(..)
                | TxInput::OrderAccountCommand(..) => Ok(None),
            })
            .collect::<Result<Vec<_>, Error>>()?;

        self.add_utxos_from_tx(tx, source, false)?;

        Ok(UtxosTxUndoWithSources::new(utxos, sources))
    }

    // Marks outputs of a transaction as spent and inputs as unspent
    pub fn disconnect_transaction(
        &mut self,
        tx: &Transaction,
        tx_undo: UtxosTxUndo,
    ) -> Result<(), Error> {
        for (i, output) in tx.outputs().iter().enumerate() {
            let tx_outpoint = UtxoOutPoint::new(tx.get_id().into(), i as u32);

            if should_include_in_utxo_set(output) {
                self.spend_utxo(&tx_outpoint)?;
            }
        }

        assert_eq!(tx.inputs().len(), tx_undo.inner().len());

        tx.inputs()
            .iter()
            .zip(tx_undo.into_inner())
            .filter_map(|(input, undo)| {
                undo.map(|utxo| match input {
                    TxInput::Utxo(outpoint) => Ok((outpoint, utxo)),
                    TxInput::Account(..)
                    | TxInput::AccountCommand(..)
                    | TxInput::OrderAccountCommand(..) => {
                        Err(Error::TxInputAndUndoMismatch(tx.get_id()))
                    }
                })
            })
            .try_for_each(|res| {
                let (outpoint, utxo) = res?;
                self.add_utxo(outpoint, utxo, false)
            })
    }

    /// Marks the inputs of a transactable block reward as 'spent', adds outputs to the utxo set.
    /// If BlockRewardTransactable has no inputs then just adds outputs to utxo set.
    /// Returns a BlockRewardUndo if function is a success or an error if the input cannot be spent.
    pub fn connect_block_transactable(
        &mut self,
        reward_transactable: &BlockRewardTransactable,
        block_id: &Id<GenBlock>,
        height: BlockHeight,
    ) -> Result<Option<UtxosBlockRewardUndo>, Error> {
        let reward_undo: Option<UtxosBlockRewardUndo> = match reward_transactable.inputs() {
            Some(inputs) => {
                let utxos = inputs
                    .iter()
                    .filter_map(|input| match input {
                        TxInput::Utxo(outpoint) => Some(self.spend_utxo(outpoint)),
                        TxInput::Account(..)
                        | TxInput::AccountCommand(..)
                        | TxInput::OrderAccountCommand(..) => None,
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (!utxos.is_empty()).then(|| UtxosBlockRewardUndo::new(utxos))
            }
            None => None,
        };

        if let Some(outputs) = reward_transactable.outputs() {
            let source_id = OutPointSourceId::from(*block_id);
            for (idx, output) in outputs.iter().enumerate() {
                if !should_include_in_utxo_set(output) {
                    return Err(Error::InvalidBlockRewardOutputType(*block_id));
                }
                let outpoint = UtxoOutPoint::new(source_id.clone(), idx as u32);
                let utxo = Utxo::new(output.clone(), UtxoSource::Blockchain(height));
                self.add_utxo(&outpoint, utxo, false)?;
            }
        }
        Ok(reward_undo)
    }

    // Marks outputs of a block reward as spent and inputs as unspent.
    pub fn disconnect_block_transactable(
        &mut self,
        reward_transactable: &BlockRewardTransactable,
        block_id: &Id<GenBlock>,
        reward_undo: Option<UtxosBlockRewardUndo>,
    ) -> Result<(), Error> {
        if let Some(outputs) = reward_transactable.outputs() {
            for (i, _) in outputs.iter().enumerate() {
                let tx_outpoint = UtxoOutPoint::new(OutPointSourceId::from(*block_id), i as u32);
                self.spend_utxo(&tx_outpoint)?;
            }
        }

        if let Some(inputs) = reward_transactable.inputs() {
            let block_undo = reward_undo.ok_or(Error::MissingBlockRewardUndo(*block_id))?;
            inputs
                .iter()
                .zip(block_undo.into_inner().into_iter())
                .filter_map(|(tx_in, utxo)| match tx_in {
                    TxInput::Utxo(outpoint) => Some((outpoint, utxo)),
                    TxInput::Account(..)
                    | TxInput::AccountCommand(..)
                    | TxInput::OrderAccountCommand(..) => None,
                })
                .try_for_each(|(outpoint, utxo)| self.add_utxo(outpoint, utxo, false))?;
        }
        Ok(())
    }

    /// Adds an utxo entry to the cache
    pub fn add_utxo(
        &mut self,
        outpoint: &UtxoOutPoint,
        utxo: Utxo,
        possible_overwrite: bool, // TODO: change this to an enum that explains what happens
    ) -> Result<(), Error> {
        // TODO: update the memory usage
        // self.memory_usage should be deducted based on this current entry.

        let is_fresh = match self.utxos.get(outpoint) {
            None => {
                // An insert can be done. This utxo doesn't exist yet, so it's fresh.
                !possible_overwrite
            }
            Some(curr_entry) => {
                if !possible_overwrite {
                    if !curr_entry.is_spent() {
                        // Attempted to overwrite an existing utxo
                        return Err(Error::OverwritingUtxo);
                    }
                    // If the utxo exists in this cache as a 'spent' utxo and is DIRTY, then
                    // its spentness hasn't been flushed to the parent cache. We're
                    // re-adding the utxo to this cache now but we can't mark it as FRESH.
                    // If we mark it FRESH and then spend it before the cache is flushed
                    // we would remove it from this cache and would never flush spentness
                    // to the parent cache.
                    //
                    // Re-adding a 'spent' utxo can happen in the case of a re-org (the utxo
                    // is 'spent' when the block adding it is disconnected and then
                    // re-added when it is also added in a newly connected block).
                    // if utxo is spent and is not dirty, then it can be marked as fresh.
                    !curr_entry.is_dirty() || curr_entry.is_fresh()
                } else {
                    // copy from the original entry
                    curr_entry.is_fresh()
                }
            }
        };

        // create a new entry
        let new_entry = UtxoEntry::new(Some(utxo), IsFresh::from(is_fresh), IsDirty::Yes);

        // TODO: update the memory usage
        // self.memory_usage should be added based on this new entry.

        self.utxos.insert(outpoint.clone(), new_entry);

        Ok(())
    }

    /// Flags the utxo as "spent", given an outpoint.
    /// Returns the Utxo if an update was performed.
    pub fn spend_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<Utxo, Error> {
        let entry = self.fetch_utxo_entry(outpoint)?.ok_or(Error::NoUtxoFound)?;
        // TODO: update the memory usage
        // self.memory_usage must be deducted from this entry's size

        // check whether this entry is fresh
        if entry.is_fresh() {
            // This is only available in this view. Remove immediately.
            self.utxos.remove(outpoint);
        } else {
            // mark this as 'spent'
            let new_entry = UtxoEntry::new(None, IsFresh::No, IsDirty::Yes);
            self.utxos.insert(outpoint.clone(), new_entry);
        }

        entry.take_utxo().ok_or_else(|| Error::UtxoAlreadySpent(outpoint.source_id()))
    }

    /// Checks whether utxo exists in the cache
    pub fn has_utxo_in_cache(&self, outpoint: &UtxoOutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Returns a mutable reference of the utxo, given the outpoint.
    pub fn get_mut_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<Option<&mut Utxo>, Error> {
        let entry = match self.fetch_utxo_entry(outpoint)? {
            Some(entry) => entry,
            None => return Ok(None),
        };
        let utxo = match entry.utxo() {
            Some(utxo) => utxo,
            None => return Ok(None),
        };

        let utxo: &mut UtxoEntry = self.utxos.entry(outpoint.clone()).or_insert_with(|| {
            //TODO: update the memory storage here
            UtxoEntry::new(
                Some(utxo.clone()),
                IsFresh::from(entry.is_fresh()),
                IsDirty::from(entry.is_dirty()),
            )
        });

        Ok(utxo.utxo_mut())
    }

    /// Removes the utxo from the cache if it's not modified
    pub fn uncache(&mut self, outpoint: &UtxoOutPoint) -> Result<(), Error> {
        let key = outpoint;
        if let Some(entry) = self.utxos.get(key) {
            // see bitcoin's Uncache.
            if !entry.is_fresh() && !entry.is_dirty() {
                //todo: decrement the memory usage
                self.utxos.remove(key);
                return Ok(());
            }
        }
        Err(Error::NoUtxoFound)
    }

    pub fn consume(self) -> ConsumedUtxoCache {
        ConsumedUtxoCache {
            container: self.utxos,
            best_block: self.current_block_hash,
        }
    }
}

impl<P> Debug for UtxosCache<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtxosCache")
            // we wouldn't want to display the parent's children; only to check whether it has a parent.
            .field("current_block_hash", &self.current_block_hash)
            .field("utxos", &self.utxos)
            .finish()
    }
}

impl<P: UtxosView> UtxosView for UtxosCache<P> {
    type Error = P::Error;

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        let key = outpoint;
        if let Some(res) = self.utxos.get(key) {
            return Ok(res.utxo().cloned());
        }

        // if utxo is not found in this view, use parent's `get_utxo`.
        self.parent.utxo(outpoint)
    }

    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Self::Error> {
        self.utxo(outpoint).map(|u| u.is_some())
    }

    fn best_block_hash(&self) -> Result<Id<GenBlock>, Self::Error> {
        Ok(self.current_block_hash)
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

impl<P> FlushableUtxoView for UtxosCache<P> {
    type Error = Error;

    fn batch_write(&mut self, utxo_entries: ConsumedUtxoCache) -> Result<(), Error> {
        for (key, entry) in utxo_entries.container {
            // Ignore non-dirty entries (optimization).
            if entry.is_dirty() {
                let parent_entry = self.utxos.get(&key);
                match parent_entry {
                    None => {
                        // The parent cache does not have an entry, while the child cache does.
                        // We can ignore it if it's both spent and FRESH in the child
                        if !(entry.is_fresh() && entry.is_spent()) {
                            // Create the utxo in the parent cache, move the data up
                            // and mark it as dirty.
                            let entry_copy = UtxoEntry::new(
                                entry.utxo().cloned(),
                                IsFresh::from(entry.is_fresh()),
                                IsDirty::Yes,
                            );

                            self.utxos.insert(key, entry_copy);
                            // TODO: increase the memory usage
                        }
                    }
                    // found entry in the parent cache
                    Some(parent_entry) => {
                        if entry.is_fresh() && !parent_entry.is_spent() {
                            // The utxo was marked FRESH in the child cache, but the utxo
                            // exists in the parent cache. If this ever happens, it means
                            // the FRESH flag was misapplied and there is a logic error in
                            // the calling code.
                            return Err(Error::FreshUtxoAlreadyExists);
                        }

                        if parent_entry.is_fresh() && entry.is_spent() {
                            // The grandparent cache does not have an entry, and the utxo
                            // has been spent. We can just delete it from the parent cache.
                            self.utxos.remove(&key);
                        } else {
                            // A normal modification.
                            let entry_copy = UtxoEntry::new(
                                entry.utxo().cloned(),
                                IsFresh::from(parent_entry.is_fresh()),
                                IsDirty::Yes,
                            );
                            self.utxos.insert(key, entry_copy);
                            // TODO: update the memory usage

                            // NOTE: It isn't safe to mark the utxo as FRESH in the parent
                            // cache. If it already existed and was spent in the parent
                            // cache then marking it FRESH would prevent that spentness
                            // from being flushed to the grandparent.
                        }
                    }
                }
            }
        }

        self.current_block_hash = utxo_entries.best_block;
        Ok(())
    }
}

/// Returns true if the given output type should be included in the utxo set
fn should_include_in_utxo_set(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::IssueNft(..)
        | TxOutput::Htlc(_, _) => true,
        TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..)
        | TxOutput::Burn(..)
        | TxOutput::IssueFungibleToken(..)
        | TxOutput::DataDeposit(..)
        | TxOutput::CreateOrder(..) => false,
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;
    use crate::tests::test_helper::{
        empty_test_utxos_view, insert_single_entry, Presence, UnwrapInfallible,
    };
    use common::primitives::H256;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn set_best_block(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let expected_best_block_id: Id<GenBlock> = H256::random_using(&mut rng).into();
        let test_view = empty_test_utxos_view(H256::zero().into());
        let mut cache = UtxosCache::new(&test_view).unwrap_infallible();
        cache.set_best_block(expected_best_block_id);
        assert_eq!(Ok(expected_best_block_id), cache.best_block_hash());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_absent(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let test_view = empty_test_utxos_view(H256::zero().into());
        let mut cache = UtxosCache::new(&test_view).unwrap_infallible();

        // when the outpoint does not exist.
        let (_, outp) = insert_single_entry(&mut rng, &mut cache, Presence::Absent, None, None);
        assert_eq!(Error::NoUtxoFound, cache.uncache(&outp).unwrap_err());
        assert!(!cache.has_utxo_in_cache(&outp));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_not_fresh_not_dirty(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let test_view = empty_test_utxos_view(H256::zero().into());
        let mut cache = UtxosCache::new(&test_view).unwrap_infallible();

        // when the entry is not dirty and not fresh
        let (_, outp) = insert_single_entry(
            &mut rng,
            &mut cache,
            Presence::Present,
            Some((IsFresh::No, IsDirty::No)),
            None,
        );
        assert!(cache.uncache(&outp).is_ok());
        assert!(!cache.has_utxo_in_cache(&outp));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_dirty_not_fresh(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let test_view = empty_test_utxos_view(H256::zero().into());
        let mut cache = UtxosCache::new(&test_view).unwrap_infallible();

        // when the entry is dirty, entry cannot be removed.
        let (_, outp) = insert_single_entry(
            &mut rng,
            &mut cache,
            Presence::Present,
            Some((IsFresh::No, IsDirty::Yes)),
            None,
        );
        assert_eq!(Error::NoUtxoFound, cache.uncache(&outp).unwrap_err());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_fresh_and_dirty(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let test_view = empty_test_utxos_view(H256::zero().into());
        let mut cache = UtxosCache::new(&test_view).unwrap_infallible();

        // when the entry is both fresh and dirty, entry cannot be removed.
        let (_, outp) = insert_single_entry(
            &mut rng,
            &mut cache,
            Presence::Present,
            Some((IsFresh::Yes, IsDirty::Yes)),
            None,
        );
        assert_eq!(Error::NoUtxoFound, cache.uncache(&outp).unwrap_err());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn fetch_an_entry(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let test_view = empty_test_utxos_view(H256::zero().into());
        let mut cache1 = UtxosCache::new(&test_view).unwrap_infallible();
        let (_, outpoint) = insert_single_entry(
            &mut rng,
            &mut cache1,
            Presence::Present,
            Some((IsFresh::Yes, IsDirty::Yes)),
            None,
        );

        let mut cache2 = UtxosCache::new(&cache1).unwrap_infallible();

        assert!(cache1.has_utxo_in_cache(&outpoint));
        assert!(!cache2.has_utxo_in_cache(&outpoint));

        cache2.fetch_utxo_entry(&outpoint).unwrap();

        assert!(cache1.has_utxo_in_cache(&outpoint));
        assert!(cache2.has_utxo_in_cache(&outpoint));
    }
}
