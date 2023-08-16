// Copyright (c) 2023 RBB S.r.l
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

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use common::{
    chain::{
        tokens::{token_id, TokenId},
        AccountNonce,
        AccountSpending::Delegation,
        DelegationId, Destination, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, Id},
};
use pos_accounting::make_delegation_id;
use utils::ensure;
use wallet_types::{
    utxo_types::{get_utxo_state, UtxoStates},
    wallet_tx::TxState,
    with_locked::WithLocked,
    AccountWalletTxId, BlockInfo, WalletTx,
};

use crate::{WalletError, WalletResult};

pub struct DelegationData {
    pub balance: Amount,
    pub destination: Destination,
    pub last_nonce: Option<AccountNonce>,
}
impl DelegationData {
    fn new(destination: Destination) -> DelegationData {
        DelegationData {
            balance: Amount::ZERO,
            destination,
            last_nonce: None,
        }
    }
}

pub struct PoolData {
    pub utxo_outpoint: UtxoOutPoint,
    pub creation_block: BlockInfo,
    pub decommission_key: Destination,
}

impl PoolData {
    fn new(
        utxo_outpoint: UtxoOutPoint,
        creation_block: BlockInfo,
        decommission_key: Destination,
    ) -> Self {
        PoolData {
            utxo_outpoint,
            creation_block,
            decommission_key,
        }
    }
}

/// A helper structure for the UTXO search.
///
/// All transactions and blocks from the DB are cached here. If a transaction
/// consumes a wallet input (send transaction) or produces a wallet output
/// (receive transaction), it's stored in the DB and cached here. To find all UTXOs,
/// all transaction/block outputs are collected. Then, from all these outputs,
/// we remove all outputs that are consumed by the same locally stored
/// transactions and blocks. Then we filter the outputs that are from our wallet
/// (can be signed) to get the final UTXO list that is ready to use.
/// In case of reorg, top blocks (and the transactions they contain) are simply removed from the DB/cache.
/// A similar approach is used by the Bitcoin Core wallet.
pub struct OutputCache {
    txs: BTreeMap<OutPointSourceId, WalletTx>,
    consumed: BTreeMap<UtxoOutPoint, TxState>,
    unconfirmed_descendants: BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
    pools: BTreeMap<PoolId, PoolData>,
    delegations: BTreeMap<DelegationId, DelegationData>,
}

impl OutputCache {
    pub fn empty() -> Self {
        Self {
            txs: BTreeMap::new(),
            consumed: BTreeMap::new(),
            unconfirmed_descendants: BTreeMap::new(),
            pools: BTreeMap::new(),
            delegations: BTreeMap::new(),
        }
    }

    pub fn new(mut txs: Vec<(AccountWalletTxId, WalletTx)>) -> WalletResult<Self> {
        let mut cache = Self::empty();

        txs.sort_by(|x, y| match (x.1.state(), y.1.state()) {
            (TxState::Confirmed(h1, _, idx1), TxState::Confirmed(h2, _, idx2)) => {
                (h1, idx1).cmp(&(h2, idx2))
            }
            (TxState::Confirmed(_, _, _), _) => std::cmp::Ordering::Less,
            (_, TxState::Confirmed(_, _, _)) => std::cmp::Ordering::Greater,
            (TxState::InMempool(idx1), TxState::InMempool(idx2)) => idx1.cmp(&idx2),
            (TxState::InMempool(idx1), TxState::Inactive(idx2)) => idx1.cmp(&idx2),
            (TxState::Inactive(idx1), TxState::Inactive(idx2)) => idx1.cmp(&idx2),
            (TxState::Inactive(idx1), TxState::InMempool(idx2)) => idx1.cmp(&idx2),
            (_, _) => std::cmp::Ordering::Equal,
        });
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id.into_item_id(), tx)?;
        }
        Ok(cache)
    }

    pub fn txs_with_unconfirmed(&self) -> &BTreeMap<OutPointSourceId, WalletTx> {
        &self.txs
    }

    pub fn has_confirmed_transactions(&self) -> bool {
        self.txs.values().any(|tx| match tx.state() {
            TxState::Inactive(_)
            | TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Abandoned => false,
            TxState::Confirmed(_, _, _) => true,
        })
    }

    pub fn get_txo(&self, outpoint: &UtxoOutPoint) -> Option<&TxOutput> {
        self.txs
            .get(&outpoint.source_id())
            .and_then(|tx| tx.outputs().get(outpoint.output_index() as usize))
    }

    pub fn pool_ids(&self) -> Vec<(PoolId, BlockInfo)> {
        self.pools
            .iter()
            .filter_map(|(pool_id, pool_data)| {
                (!self.consumed.contains_key(&pool_data.utxo_outpoint))
                    .then_some((*pool_id, pool_data.creation_block))
            })
            .collect()
    }

    pub fn pool_data(&self, pool_id: PoolId) -> WalletResult<&PoolData> {
        self.pools.get(&pool_id).ok_or(WalletError::UnknownPoolId(pool_id))
    }

    pub fn delegation_ids(&self) -> impl Iterator<Item = (&DelegationId, &DelegationData)> {
        self.delegations.iter()
    }

    pub fn delegation_data(&self, delegation_id: DelegationId) -> WalletResult<&DelegationData> {
        self.delegations
            .get(&delegation_id)
            .ok_or(WalletError::DelegationNotFound(delegation_id))
    }

    pub fn add_tx(&mut self, tx_id: OutPointSourceId, tx: WalletTx) -> WalletResult<()> {
        let already_present = self.txs.contains_key(&tx_id);
        let is_unconfirmed = match tx.state() {
            TxState::Inactive(_)
            | TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Abandoned => true,
            TxState::Confirmed(_, _, _) => false,
        };
        if is_unconfirmed && !already_present {
            self.unconfirmed_descendants.insert(tx_id.clone(), BTreeSet::new());
        }

        self.update_inputs(&tx, is_unconfirmed, &tx_id, already_present)?;

        if let Some(block_info) = get_block_info(&tx) {
            self.update_outputs(&tx, block_info)?;
        }
        self.txs.insert(tx_id, tx);
        Ok(())
    }

    /// Update the pool states for a newly confirmed transaction
    fn update_outputs(&mut self, tx: &WalletTx, block_info: BlockInfo) -> Result<(), WalletError> {
        for (idx, output) in tx.outputs().iter().enumerate() {
            match output {
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    if let Some(pool_data) = self.pools.get_mut(pool_id) {
                        pool_data.utxo_outpoint = UtxoOutPoint::new(tx.id(), idx as u32)
                    } else {
                        return Err(WalletError::InconsistentProduceBlockFromStake(*pool_id));
                    }
                }
                TxOutput::CreateStakePool(pool_id, data) => {
                    self.pools
                        .entry(*pool_id)
                        .and_modify(|entry| {
                            entry.utxo_outpoint = UtxoOutPoint::new(tx.id(), idx as u32)
                        })
                        .or_insert_with(|| {
                            PoolData::new(
                                UtxoOutPoint::new(tx.id(), idx as u32),
                                block_info,
                                data.decommission_key().clone(),
                            )
                        });
                }
                TxOutput::DelegateStaking(amount, delegation_id) => {
                    match self.delegations.entry(*delegation_id) {
                        Entry::Vacant(_) => {
                            return Err(WalletError::InconsistentDelegationAddition(
                                *delegation_id,
                            ));
                        }
                        Entry::Occupied(mut entry) => {
                            let pool_data = entry.get_mut();
                            pool_data.balance = (pool_data.balance + *amount)
                                .ok_or(WalletError::OutputAmountOverflow)?;
                        }
                    }
                }
                TxOutput::CreateDelegationId(destination, _) => {
                    let input0_outpoint = tx
                        .inputs()
                        .get(0)
                        .ok_or(WalletError::NoUtxos)?
                        .utxo_outpoint()
                        .ok_or(WalletError::NoUtxos)?;
                    let delegation_id = make_delegation_id(input0_outpoint);
                    self.delegations
                        .insert(delegation_id, DelegationData::new(destination.clone()));
                }
                | TxOutput::Burn(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _) => {}
            };
        }
        Ok(())
    }

    /// Update the inputs for a new transaction, mark them as consumed and update delegation account
    /// balances
    fn update_inputs(
        &mut self,
        tx: &WalletTx,
        is_unconfirmed: bool,
        tx_id: &OutPointSourceId,
        already_present: bool,
    ) -> Result<(), WalletError> {
        for input in tx.inputs() {
            match input {
                TxInput::Utxo(outpoint) => {
                    self.consumed.insert(outpoint.clone(), tx.state());
                    if is_unconfirmed {
                        self.unconfirmed_descendants
                            .get_mut(&outpoint.source_id())
                            .as_mut()
                            .map(|descendants| descendants.insert(tx_id.clone()));
                    } else {
                        self.unconfirmed_descendants.remove(tx_id);
                    }
                }
                TxInput::Account(outpoint) => {
                    if !already_present {
                        match outpoint.account() {
                            Delegation(delegation_id, amount) => {
                                match self.delegations.get_mut(delegation_id) {
                                    Some(data) => {
                                        data.balance = (data.balance - *amount).ok_or(
                                            WalletError::NegativeDelegationAmount(*delegation_id),
                                        )?;
                                        let next_nonce = data
                                            .last_nonce
                                            .map_or(Some(AccountNonce::new(0)), |nonce| {
                                                nonce.increment()
                                            })
                                            .ok_or(WalletError::DelegationNonceOverflow(
                                                *delegation_id,
                                            ))?;
                                        ensure!(
                                            outpoint.nonce() >= next_nonce,
                                            WalletError::InconsistentDelegationDuplicateNonce(
                                                *delegation_id,
                                                outpoint.nonce()
                                            )
                                        );
                                        data.last_nonce = Some(outpoint.nonce());
                                    }
                                    None => {
                                        return Err(WalletError::InconsistentDelegationRemoval(
                                            *delegation_id,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn remove_tx(&mut self, tx_id: &OutPointSourceId) -> WalletResult<()> {
        let tx_opt = self.txs.remove(tx_id);
        if let Some(tx) = tx_opt {
            for input in tx.inputs() {
                match input {
                    TxInput::Utxo(outpoint) => {
                        self.consumed.remove(outpoint);
                        self.unconfirmed_descendants.remove(tx_id);
                    }
                    TxInput::Account(outpoint) => match outpoint.account() {
                        Delegation(delegation_id, amount) => {
                            match self.delegations.get_mut(delegation_id) {
                                Some(data) => {
                                    data.balance = (data.balance - *amount).ok_or(
                                        WalletError::InconsistentDelegationRemoval(*delegation_id),
                                    )?;
                                    data.last_nonce = outpoint.nonce().decrement();
                                }
                                None => {
                                    return Err(WalletError::NoUtxos);
                                }
                            }
                        }
                    },
                }
            }
        }
        Ok(())
    }

    fn is_consumed(&self, utxo_states: UtxoStates, outpoint: &UtxoOutPoint) -> bool {
        self.consumed.get(outpoint).map_or(false, |consumed_state| {
            utxo_states.contains(get_utxo_state(consumed_state))
        })
    }

    pub fn utxos_with_token_ids(
        &self,
        current_block_info: BlockInfo,
        utxo_states: UtxoStates,
        locked_state: WithLocked,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        self.txs
            .values()
            .filter(|tx| is_in_state(tx, utxo_states))
            .flat_map(|tx| {
                let tx_block_info = get_block_info(tx);
                let token_id = match tx {
                    WalletTx::Tx(tx_data) => token_id(tx_data.get_transaction()),
                    WalletTx::Block(_) => None,
                };

                tx.outputs()
                    .iter()
                    .enumerate()
                    .map(|(idx, output)| (output, UtxoOutPoint::new(tx.id(), idx as u32)))
                    .filter(move |(output, outpoint)| {
                        !self.is_consumed(utxo_states, outpoint)
                            && is_specific_lock_state(
                                locked_state,
                                output,
                                current_block_info,
                                tx_block_info,
                                outpoint,
                            )
                    })
                    .map(move |(output, outpoint)| {
                        (
                            outpoint,
                            (
                                output,
                                if output.is_token_or_nft_issuance() {
                                    token_id
                                } else {
                                    None
                                },
                            ),
                        )
                    })
            })
            .collect()
    }

    pub fn pending_transactions(&self) -> Vec<&WithId<Transaction>> {
        self.txs
            .values()
            .filter_map(|tx| match tx {
                WalletTx::Block(_) => None,
                WalletTx::Tx(tx) => match tx.state() {
                    TxState::Inactive(_) => Some(tx.get_transaction_with_id()),
                    TxState::Confirmed(_, _, _)
                    | TxState::Conflicted(_)
                    | TxState::InMempool(_)
                    | TxState::Abandoned => None,
                },
            })
            .collect()
    }

    /// Mark a transaction and its descendants as abandoned
    /// Returns a Vec of the transaction Ids that have been abandoned
    pub fn abandon_transaction(
        &mut self,
        tx_id: Id<Transaction>,
    ) -> WalletResult<Vec<Id<Transaction>>> {
        let mut all_abandoned = Vec::new();
        let mut to_abandon = BTreeSet::from_iter([OutPointSourceId::from(tx_id)]);

        while let Some(outpoint_source_id) = to_abandon.pop_first() {
            all_abandoned.push(*outpoint_source_id.get_tx_id().expect("must be a transaction"));

            if let Some(descendants) = self.unconfirmed_descendants.remove(&outpoint_source_id) {
                to_abandon.extend(descendants.into_iter())
            }

            match self.txs.entry(outpoint_source_id) {
                Entry::Occupied(mut entry) => {
                    match entry.get_mut() {
                        WalletTx::Block(_) => Err(WalletError::CannotFindTransactionWithId(tx_id)),
                        WalletTx::Tx(tx) => match tx.state() {
                            TxState::Inactive(_) => {
                                tx.set_state(TxState::Abandoned);
                                for input in tx.get_transaction().inputs() {
                                    match input {
                                        TxInput::Utxo(outpoint) => {
                                            self.consumed.insert(outpoint.clone(), *tx.state());
                                        }
                                        TxInput::Account(outpoint) => {
                                            match outpoint.account() {
                                                Delegation(delegation_id, amount) => {
                                                    match self.delegations.get_mut(delegation_id) {
                                                        Some(data) => {
                                                            data.last_nonce =
                                                                outpoint.nonce().decrement();
                                                            data.balance = (data.balance + *amount)
                                .ok_or(WalletError::DelegationAmountOverflow(*delegation_id))?;
                                                        }
                                                        None => {
                                                            return Err(WalletError::InconsistentDelegationRemoval(*delegation_id));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(())
                            }
                            state => Err(WalletError::CannotAbandonTransaction(*state)),
                        },
                    }
                }
                Entry::Vacant(_) => Err(WalletError::CannotFindTransactionWithId(tx_id)),
            }?;
        }

        Ok(all_abandoned)
    }
}

/// Checks the output against the current block height and compares it with the locked_state parameter.
/// If they match, the function return true, if they don't, it returns false.
/// For example, if we would like to check that an output is locked,
/// we pass locked_state = WithLocked::Locked, and pass the output in question.
/// If the output is locked, the function returns true. Otherwise, it returns false
fn is_specific_lock_state(
    locked_state: WithLocked,
    output: &TxOutput,
    current_block_info: BlockInfo,
    tx_block_info: Option<BlockInfo>,
    outpoint: &UtxoOutPoint,
) -> bool {
    match locked_state {
        WithLocked::Any => true,
        WithLocked::Locked => {
            !valid_timelock(output, &current_block_info, &tx_block_info, outpoint)
        }
        WithLocked::Unlocked => {
            valid_timelock(output, &current_block_info, &tx_block_info, outpoint)
        }
    }
}

/// Get the block info (block height and timestamp) if the Tx is in confirmed state
fn get_block_info(tx: &WalletTx) -> Option<BlockInfo> {
    match tx.state() {
        TxState::Confirmed(height, timestamp, _) => Some(BlockInfo { height, timestamp }),
        TxState::InMempool(_)
        | TxState::Inactive(_)
        | TxState::Conflicted(_)
        | TxState::Abandoned => None,
    }
}

/// Check the TxOutput's timelock is unlocked
fn valid_timelock(
    output: &TxOutput,
    current_block_info: &BlockInfo,
    transaction_block_info: &Option<BlockInfo>,
    outpoint: &UtxoOutPoint,
) -> bool {
    output.timelock().map_or(true, |timelock| {
        transaction_block_info.as_ref().map_or(false, |transaction_block_info| {
            tx_verifier::timelock_check::check_timelock(
                &transaction_block_info.height,
                &transaction_block_info.timestamp,
                timelock,
                &current_block_info.height,
                &current_block_info.timestamp,
                outpoint,
            )
            .is_ok()
        })
    })
}

/// Check Tx is in the selected state Confirmed/Inactive/Abandoned...
fn is_in_state(tx: &WalletTx, utxo_states: UtxoStates) -> bool {
    utxo_states.contains(get_utxo_state(&tx.state()))
}

#[cfg(test)]
mod tests {
    use common::{
        chain::block::timestamp::BlockTimestamp,
        primitives::{BlockHeight, H256},
    };
    use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};
    use wallet_types::{wallet_tx::TxData, AccountId};

    use super::*;

    fn make_delegation_tx(output_index: u32) -> (Transaction, DelegationId) {
        let input0_outpoint = UtxoOutPoint::new(
            OutPointSourceId::Transaction(Id::<Transaction>::new(H256::zero())),
            output_index,
        );
        let delegation_id = make_delegation_id(&input0_outpoint);
        let tx = Transaction::new(
            0,
            vec![TxInput::from(input0_outpoint)],
            vec![TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                PoolId::new(H256::zero()),
            )],
        )
        .unwrap();

        (tx, delegation_id)
    }

    fn make_stake_delegation_tx(delegation_id: DelegationId) -> Transaction {
        Transaction::new(
            0,
            vec![],
            vec![TxOutput::DelegateStaking(Amount::ZERO, delegation_id)],
        )
        .unwrap()
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_wallet_transaction_sorting_on_load(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let account_id = AccountId::new_from_xpub(
            &ExtendedPrivateKey::new_from_entropy(ExtendedKeyKind::Secp256k1Schnorr).1,
        );

        let mut delegation_ids = BTreeMap::new();
        let txs = (0..100)
            .map(|idx| {
                let tx: WithId<Transaction> = if rng.gen::<bool>() || delegation_ids.is_empty() {
                    let (tx, delegation_id) = make_delegation_tx(delegation_ids.len() as u32);
                    delegation_ids.insert(delegation_id, Amount::ZERO);
                    tx.into()
                } else {
                    let delegation_id =
                        delegation_ids.keys().nth(rng.gen_range(0..delegation_ids.len())).unwrap();
                    make_stake_delegation_tx(*delegation_id).into()
                };

                let tx_id = WithId::id(&tx);

                let wtx = WalletTx::Tx(TxData::new(
                    tx,
                    TxState::Confirmed(
                        BlockHeight::new(0),
                        BlockTimestamp::from_int_seconds(0),
                        idx as u64,
                    ),
                ));

                (
                    AccountWalletTxId::new(account_id.clone(), OutPointSourceId::from(tx_id)),
                    wtx,
                )
            })
            .collect();

        let cache = OutputCache::new(txs).unwrap();

        let delegations: BTreeMap<&DelegationId, _> = cache.delegation_ids().collect();

        for (delegation_id, balance) in delegation_ids {
            let data = delegations.get(&delegation_id).unwrap();
            assert_eq!(data.balance, balance);
        }
    }
}
