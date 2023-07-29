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
    AccountWalletTxId, BlockInfo, WalletTx,
};

use crate::{WalletError, WalletResult};

pub struct DelegationData {
    pub balance: Amount,
    pub destination: Destination,
    pub latest_nonce: AccountNonce,
}
impl DelegationData {
    fn new(destination: Destination) -> DelegationData {
        DelegationData {
            balance: Amount::ZERO,
            destination,
            latest_nonce: AccountNonce::new(0),
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
            (TxState::Confirmed(h1, _), TxState::Confirmed(h2, _)) => h1.cmp(&h2),
            (TxState::Confirmed(_, _), _) => std::cmp::Ordering::Less,
            (_, TxState::Confirmed(_, _)) => std::cmp::Ordering::Greater,
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

    pub fn get_txo(&self, outpoint: &UtxoOutPoint) -> Option<&TxOutput> {
        self.txs
            .get(&outpoint.tx_id())
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
        let is_unconfirmed = match tx.state() {
            TxState::Inactive
            | TxState::InMempool
            | TxState::Conflicted(_)
            | TxState::Abandoned => true,
            TxState::Confirmed(_, _) => false,
        };
        if is_unconfirmed {
            self.unconfirmed_descendants.insert(tx_id.clone(), BTreeSet::new());
        }

        for input in tx.inputs() {
            match input {
                TxInput::Utxo(outpoint) => {
                    self.consumed.insert(outpoint.clone(), tx.state());
                    if is_unconfirmed {
                        self.unconfirmed_descendants
                            .get_mut(&outpoint.tx_id())
                            .as_mut()
                            .map(|descendants| descendants.insert(tx_id.clone()));
                    }
                }
                TxInput::Account(outpoint) => match outpoint.account() {
                    Delegation(delegation_id, amount) => {
                        match self.delegations.get_mut(delegation_id) {
                            Some(data) => {
                                data.balance = (data.balance - *amount)
                                    .ok_or(WalletError::NegativeDelegationAmount(*delegation_id))?;
                                let next_nonce = data
                                    .latest_nonce
                                    .increment()
                                    .ok_or(WalletError::DelegationNonceOverflow(*delegation_id))?;
                                ensure!(
                                    outpoint.nonce() >= next_nonce,
                                    WalletError::InconsistentDelegationDuplicateNonce(
                                        *delegation_id,
                                        outpoint.nonce()
                                    )
                                );
                                data.latest_nonce = outpoint.nonce();
                            }
                            None => {
                                return Err(WalletError::InconsistentDelegationRemoval(
                                    *delegation_id,
                                ));
                            }
                        }
                    }
                },
            }
        }

        let tx_block_info = match tx.state() {
            TxState::Confirmed(height, timestamp) => Some(BlockInfo { height, timestamp }),
            TxState::Inactive
            | TxState::Conflicted(_)
            | TxState::InMempool
            | TxState::Abandoned => None,
        };
        if let Some(block_info) = tx_block_info {
            for (idx, output) in tx.outputs().iter().enumerate() {
                match output {
                    TxOutput::ProduceBlockFromStake(_, pool_id) => {
                        if let Some(data) = self.pools.get_mut(pool_id) {
                            data.utxo_outpoint = UtxoOutPoint::new(tx.id(), idx as u32)
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
                                let data = entry.get_mut();
                                data.balance = (data.balance + *amount)
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
        }
        self.txs.insert(tx_id, tx);
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
                                    data.latest_nonce = outpoint.nonce().decrement().ok_or(
                                        WalletError::InconsistentDelegationRemovalNegativeNonce(
                                            *delegation_id,
                                        ),
                                    )?;
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

    fn valid_utxo(
        &self,
        outpoint: &UtxoOutPoint,
        output: &TxOutput,
        transaction_block_info: &Option<BlockInfo>,
        current_block_info: &BlockInfo,
        utxo_states: UtxoStates,
    ) -> bool {
        !self.is_consumed(utxo_states, outpoint)
            && valid_timelock(output, current_block_info, transaction_block_info, outpoint)
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
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        let mut utxos = BTreeMap::new();

        for tx in self.txs.values() {
            if !utxo_states.contains(get_utxo_state(&tx.state())) {
                continue;
            }

            let tx_block_info = match tx.state() {
                TxState::Confirmed(height, timestamp) => Some(BlockInfo { height, timestamp }),
                TxState::InMempool
                | TxState::Inactive
                | TxState::Conflicted(_)
                | TxState::Abandoned => None,
            };
            for (index, output) in tx.outputs().iter().enumerate() {
                let outpoint = UtxoOutPoint::new(tx.id(), index as u32);
                if self.valid_utxo(
                    &outpoint,
                    output,
                    &tx_block_info,
                    &current_block_info,
                    utxo_states,
                ) {
                    let token_id = if output.is_token_or_nft_issuance() {
                        match tx {
                            WalletTx::Tx(tx_data) => token_id(tx_data.get_transaction()),
                            WalletTx::Block(_) => None,
                        }
                    } else {
                        None
                    };
                    utxos.insert(outpoint, (output, token_id));
                }
            }
        }

        utxos
    }

    pub fn pending_transactions(&self) -> Vec<&WithId<Transaction>> {
        self.txs
            .values()
            .filter_map(|tx| match tx {
                WalletTx::Block(_) => None,
                WalletTx::Tx(tx) => match tx.state() {
                    TxState::Inactive => Some(tx.get_transaction_with_id()),
                    TxState::Confirmed(_, _)
                    | TxState::Conflicted(_)
                    | TxState::InMempool
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
                            TxState::Inactive => {
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
