// Copyright (c) 2026 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    chain::{
        make_order_id, make_token_id, output_value::OutputValue, tokens::TokenId, AccountCommand,
        AccountNonce, AccountSpending, ChainConfig, OrderAccountCommand, OrderId, OutPointSourceId,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, Id, Idable},
};

/// A type of dependency that a transaction can depend on
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone)]
enum Dependency {
    Utxo(UtxoOutPoint),
    TokenCreation(TokenId),
    TokenCommand(TokenId, AccountNonce),
    OrderCreation(OrderId),
    OrderFill(OrderId),
    OrderFreeze(OrderId),
}

type TxIndex = usize;

struct DependenciesMap {
    providers: BTreeMap<Dependency, Vec<TxIndex>>,
    dependents: BTreeMap<Dependency, Vec<TxIndex>>,
}

impl DependenciesMap {
    fn new() -> Self {
        Self {
            providers: BTreeMap::new(),
            dependents: BTreeMap::new(),
        }
    }
}

pub trait DependencyNode {
    type Id: Eq + PartialOrd + Ord + std::fmt::Debug;
    type Priority: Ord + Copy;

    fn id(&self) -> Self::Id;
    fn dependencies(&self) -> &[Self::Id];
    fn priority(&self) -> Self::Priority;
}

// Highest priority txs are first, then delegation stake, delegation withdrawal and last token freeze
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub enum TxPriorityOrder {
    Highest = 3,
    DelegationStake = 2,
    DelegationWithdrawal = 1,
    TokenFreeze = 0,
}

/// Represents an item that can be topologically sorted.
#[derive(Eq, PartialEq)]
pub struct TxDependencyNode {
    id: Id<Transaction>,
    dependencies: Vec<Id<Transaction>>,
    tx: SignedTransaction,
    priority: TxPriorityOrder,
}

impl TxDependencyNode {
    fn new(tx: SignedTransaction) -> Self {
        let id = tx.transaction().get_id();
        let priority = tx_priority_order(&tx);

        Self {
            id,
            dependencies: Vec::new(),
            tx,
            priority,
        }
    }

    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.tx
    }
}

impl DependencyNode for TxDependencyNode {
    type Id = Id<Transaction>;
    type Priority = TxPriorityOrder;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn priority(&self) -> Self::Priority {
        self.priority
    }

    fn dependencies(&self) -> &[Self::Id] {
        &self.dependencies
    }
}

// Build a dependency graph from the provided transactions
pub fn build_dependency_graph(
    transactions: Vec<SignedTransaction>,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> Vec<TxDependencyNode> {
    let mut dependencies = DependenciesMap::new();

    for (tx_index, tx) in transactions.iter().enumerate() {
        process_input_dependencies(tx_index, &mut dependencies, tx);
        process_output_dependencies(tx_index, chain_config, block_height, &mut dependencies, tx);
    }

    let mut dependency_nodes =
        transactions.into_iter().map(TxDependencyNode::new).collect::<Vec<_>>();

    for (dep, tx_indices) in dependencies.dependents.iter() {
        if let Some(providers) = dependencies.providers.get(dep) {
            let providers = providers
                .iter()
                .map(|provider_tx_index| dependency_nodes[*provider_tx_index].id)
                .collect::<Vec<_>>();

            for tx_index in tx_indices {
                dependency_nodes[*tx_index].dependencies.extend(providers.clone());
            }
        }
    }

    dependency_nodes
}

fn process_output_dependencies(
    tx_index: usize,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    dependencies: &mut DependenciesMap,
    tx: &SignedTransaction,
) {
    let inputs = tx.transaction().inputs();
    for (out_index, out) in tx.transaction().outputs().iter().enumerate() {
        match out {
            TxOutput::CreateOrder(order_data) => {
                let order_id = make_order_id(inputs).expect("Valid TX from mempool");
                dependencies
                    .providers
                    .entry(Dependency::OrderCreation(order_id))
                    .or_default()
                    .push(tx_index);

                match order_data.ask() {
                    OutputValue::TokenV1(token_id, _) => {
                        dependencies
                            .dependents
                            .entry(Dependency::TokenCreation(*token_id))
                            .or_default()
                            .push(tx_index);
                    }
                    OutputValue::Coin(_) | OutputValue::TokenV0(_) => {}
                }
                match order_data.give() {
                    OutputValue::TokenV1(token_id, _) => {
                        dependencies
                            .dependents
                            .entry(Dependency::TokenCreation(*token_id))
                            .or_default()
                            .push(tx_index);
                    }
                    OutputValue::Coin(_) | OutputValue::TokenV0(_) => {}
                }
            }
            TxOutput::IssueFungibleToken(_) => {
                let token_id = make_token_id(chain_config, block_height, inputs)
                    .expect("Valid TX from mempool");
                dependencies
                    .providers
                    .entry(Dependency::TokenCreation(token_id))
                    .or_default()
                    .push(tx_index);
            }
            TxOutput::IssueNft(token_id, _, _) => {
                dependencies
                    .providers
                    .entry(Dependency::TokenCreation(*token_id))
                    .or_default()
                    .push(tx_index);
            }
            _ => {
                let outpoint = UtxoOutPoint::new(
                    OutPointSourceId::Transaction(tx.transaction().get_id()),
                    out_index as u32,
                );
                dependencies
                    .providers
                    .entry(Dependency::Utxo(outpoint))
                    .or_default()
                    .push(tx_index);
            }
        }
    }
}

fn tx_priority_order(tx: &SignedTransaction) -> TxPriorityOrder {
    let mut priority = TxPriorityOrder::Highest;
    for inp in tx.transaction().inputs().iter() {
        match inp {
            TxInput::Utxo(_) => {}
            TxInput::Account(acc) => match acc.account() {
                AccountSpending::DelegationBalance(_, _) => {
                    priority = std::cmp::min(priority, TxPriorityOrder::DelegationWithdrawal);
                }
            },
            TxInput::AccountCommand(_, cmd) => match cmd {
                AccountCommand::FreezeToken(_, _) => {
                    priority = std::cmp::min(priority, TxPriorityOrder::TokenFreeze);
                }
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::LockTokenSupply(_)
                | AccountCommand::ChangeTokenMetadataUri(_, _)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ConcludeOrder(_)
                | AccountCommand::FillOrder(_, _, _) => {}
            },
            TxInput::OrderAccountCommand(_) => {}
        }
    }

    for out in tx.transaction().outputs() {
        if let TxOutput::DelegateStaking(_, _) = out {
            priority = std::cmp::min(priority, TxPriorityOrder::DelegationStake);
        }
    }

    priority
}

fn process_input_dependencies(
    tx_index: usize,
    dependencies: &mut DependenciesMap,
    tx: &SignedTransaction,
) {
    for inp in tx.transaction().inputs().iter() {
        match inp {
            TxInput::Utxo(utxo_outpoint) => {
                dependencies
                    .dependents
                    .entry(Dependency::Utxo(utxo_outpoint.clone()))
                    .or_default()
                    .push(tx_index);
            }
            TxInput::Account(_) => {}
            TxInput::AccountCommand(nonce, cmd) => match cmd {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    dependencies
                        .providers
                        .entry(Dependency::TokenCommand(*token_id, *nonce))
                        .or_default()
                        .push(tx_index);

                    dependencies
                        .dependents
                        .entry(Dependency::TokenCreation(*token_id))
                        .or_default()
                        .push(tx_index);
                    if let Some(previous_nonce) = nonce.decrement() {
                        dependencies
                            .dependents
                            .entry(Dependency::TokenCommand(*token_id, previous_nonce))
                            .or_default()
                            .push(tx_index);
                    }
                }
                AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {}
            },
            TxInput::OrderAccountCommand(cmd) => match cmd {
                OrderAccountCommand::FillOrder(order_id, _) => {
                    dependencies
                        .providers
                        .entry(Dependency::OrderFill(*order_id))
                        .or_default()
                        .push(tx_index);

                    dependencies
                        .dependents
                        .entry(Dependency::OrderCreation(*order_id))
                        .or_default()
                        .push(tx_index);
                }
                OrderAccountCommand::FreezeOrder(order_id) => {
                    dependencies
                        .providers
                        .entry(Dependency::OrderFreeze(*order_id))
                        .or_default()
                        .push(tx_index);

                    dependencies
                        .dependents
                        .entry(Dependency::OrderCreation(*order_id))
                        .or_default()
                        .push(tx_index);
                    dependencies
                        .dependents
                        .entry(Dependency::OrderFill(*order_id))
                        .or_default()
                        .push(tx_index);
                }
                OrderAccountCommand::ConcludeOrder(order_id) => {
                    dependencies
                        .dependents
                        .entry(Dependency::OrderCreation(*order_id))
                        .or_default()
                        .push(tx_index);
                    dependencies
                        .dependents
                        .entry(Dependency::OrderFill(*order_id))
                        .or_default()
                        .push(tx_index);
                    dependencies
                        .dependents
                        .entry(Dependency::OrderFreeze(*order_id))
                        .or_default()
                        .push(tx_index);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chainstate_test_framework::TransactionBuilder;
    use common::{
        chain::{
            config::create_regtest,
            output_value::OutputValue,
            signature::inputsig::InputWitness,
            tokens::{IsTokenUnfreezable, TokenIssuance},
            AccountCommandTag, Destination, OrderData, OutPointSourceId, TxInput, TxOutput,
            UtxoOutPoint,
        },
        primitives::{Amount, BlockHeight, Id, H256},
    };
    use randomness::seq::IteratorRandom;
    use test_utils::{
        random::{make_seedable_rng, Rng, Seed},
        token_utils::random_token_issuance_v1,
    };

    use rstest::rstest;
    use strum::IntoEnumIterator;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_utxo_dependency_chain(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = create_regtest();
        let block_height = BlockHeight::new(0);

        // simple A -> B UTXO chain
        let random_tx_id = Id::new(H256::random_using(&mut rng));
        let random_utxo_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 0);
        let txa = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txa_id = txa.transaction().get_id();

        let output_from_txa = UtxoOutPoint::new(OutPointSourceId::Transaction(txa_id), 0);
        let txb = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(output_from_txa),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txb_id = txb.transaction().get_id();

        let transactions = vec![txa, txb];
        let dependency_graph = build_dependency_graph(transactions, &chain_config, block_height);
        assert_eq!(dependency_graph.len(), 2);
        assert_eq!(dependency_graph[0].id, txa_id);
        assert_eq!(dependency_graph[1].id, txb_id);
        assert!(dependency_graph[0].dependencies.is_empty());
        assert_eq!(dependency_graph[1].dependencies, vec![txa_id]);
    }

    // test txs not dependednt on UTXO input/outputs but on token creation/command
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_token_creation_dependency_chain(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = create_regtest();
        let block_height = BlockHeight::new(0);

        // A creates a new token, B uses a comand on it
        let random_tx_id = Id::new(H256::random_using(&mut rng));
        let random_utxo_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 0);
        let token = TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
            random_token_issuance_v1(&chain_config, Destination::AnyoneCanSpend, &mut rng),
        )));
        let txa = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint),
                InputWitness::NoSignature(None),
            )
            .add_output(token)
            .build();
        let txa_id = txa.transaction().get_id();
        let token_id = make_token_id(
            &chain_config,
            BlockHeight::new(0),
            txa.transaction().inputs(),
        )
        .unwrap();

        let random_utxo_outpoint2 =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 1);
        let random_command1 = make_random_token_comand(token_id, &mut rng);
        let txb = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint2),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::AccountCommand(AccountNonce::new(0), random_command1),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txb_id = txb.transaction().get_id();

        let random_utxo_outpoint3 =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 2);
        let random_command2 = make_random_token_comand(token_id, &mut rng);
        let txc = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint3),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::AccountCommand(AccountNonce::new(1), random_command2),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txc_id = txc.transaction().get_id();

        let transactions = vec![txa, txb, txc];
        let dependency_graph = build_dependency_graph(transactions, &chain_config, block_height);
        assert_eq!(dependency_graph.len(), 3);
        assert_eq!(dependency_graph[0].id, txa_id);
        assert_eq!(dependency_graph[1].id, txb_id);
        assert_eq!(dependency_graph[2].id, txc_id);
        assert!(dependency_graph[0].dependencies.is_empty());
        assert_eq!(dependency_graph[1].dependencies, vec![txa_id]);
        assert_eq!(dependency_graph[2].dependencies, vec![txa_id, txb_id]);
    }

    // test new order depending on new token creation
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_order_depending_on_token_creation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = create_regtest();
        let block_height = BlockHeight::new(0);

        // A creates a new token, B creates an order using it
        let random_tx_id = Id::new(H256::random_using(&mut rng));
        let random_utxo_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 0);
        let token = TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
            random_token_issuance_v1(&chain_config, Destination::AnyoneCanSpend, &mut rng),
        )));
        let txa = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint),
                InputWitness::NoSignature(None),
            )
            .add_output(token)
            .build();
        let txa_id = txa.transaction().get_id();
        let token_id = make_token_id(
            &chain_config,
            BlockHeight::new(0),
            txa.transaction().inputs(),
        )
        .unwrap();

        let random_utxo_outpoint2 =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 1);

        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(Amount::from_atoms(10)),
            OutputValue::TokenV1(token_id, Amount::from_atoms(10)),
        );
        let order = TxOutput::CreateOrder(Box::new(order_data));
        let txb = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint2),
                InputWitness::NoSignature(None),
            )
            .add_output(order)
            .build();
        let txb_id = txb.transaction().get_id();

        let transactions = vec![txa, txb];
        let dependency_graph = build_dependency_graph(transactions, &chain_config, block_height);
        assert_eq!(dependency_graph.len(), 2);
        assert_eq!(dependency_graph[0].id, txa_id);
        assert_eq!(dependency_graph[1].id, txb_id);
        assert!(dependency_graph[0].dependencies.is_empty());
        assert_eq!(dependency_graph[1].dependencies, vec![txa_id]);
    }

    // test transactions dependent on orders creation fill freeze and conclude
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_order_creation_fill_freeze_conclude_dependency_chain(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = create_regtest();
        let block_height = BlockHeight::new(0);

        // A creates a new order, B fills it, C freezes it, D concludes it
        let random_tx_id = Id::new(H256::random_using(&mut rng));
        let random_utxo_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 0);

        let random_token_id = Id::new(H256::random_using(&mut rng));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(Amount::from_atoms(10)),
            OutputValue::TokenV1(random_token_id, Amount::from_atoms(10)),
        );
        let order = TxOutput::CreateOrder(Box::new(order_data));
        let txa = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint),
                InputWitness::NoSignature(None),
            )
            .add_output(order)
            .build();
        let txa_id = txa.transaction().get_id();
        let order_id = make_order_id(txa.transaction().inputs()).unwrap();

        let random_utxo_outpoint2 =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 1);
        let fill_order = OrderAccountCommand::FillOrder(order_id, Amount::from_atoms(1));
        let txb = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint2),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::OrderAccountCommand(fill_order),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txb_id = txb.transaction().get_id();

        let random_utxo_outpoint3 =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 2);
        let freeze_order = OrderAccountCommand::FreezeOrder(order_id);
        let txc = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint3),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::OrderAccountCommand(freeze_order),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txc_id = txc.transaction().get_id();

        let random_utxo_outpoint4 =
            UtxoOutPoint::new(OutPointSourceId::Transaction(random_tx_id), 3);
        let conclude_order = OrderAccountCommand::ConcludeOrder(order_id);
        let txd = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(random_utxo_outpoint4),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::OrderAccountCommand(conclude_order),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(100)
            .build();
        let txd_id = txd.transaction().get_id();

        let transactions = vec![txa, txb, txc, txd];
        let dependency_graph = build_dependency_graph(transactions, &chain_config, block_height);
        assert_eq!(dependency_graph.len(), 4);
        assert_eq!(dependency_graph[0].id, txa_id);
        assert_eq!(dependency_graph[1].id, txb_id);
        assert_eq!(dependency_graph[2].id, txc_id);
        assert_eq!(dependency_graph[3].id, txd_id);
        assert!(dependency_graph[0].dependencies.is_empty());
        assert_eq!(dependency_graph[1].dependencies, vec![txa_id]);
        assert_eq!(dependency_graph[2].dependencies, vec![txa_id, txb_id]);
        assert_eq!(
            dependency_graph[3].dependencies,
            vec![txa_id, txb_id, txc_id]
        );
    }

    fn make_random_token_comand(token_id: TokenId, rng: &mut impl Rng) -> AccountCommand {
        match AccountCommandTag::iter().choose(rng).unwrap() {
            AccountCommandTag::MintTokens => {
                AccountCommand::MintTokens(token_id, Amount::from_atoms(rng.gen_range(1..100)))
            }
            AccountCommandTag::UnmintTokens => AccountCommand::UnmintTokens(token_id),
            AccountCommandTag::FreezeToken => {
                AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes)
            }
            AccountCommandTag::UnfreezeToken => AccountCommand::UnfreezeToken(token_id),
            AccountCommandTag::LockTokenSupply => AccountCommand::LockTokenSupply(token_id),
            AccountCommandTag::ChangeTokenMetadataUri => {
                AccountCommand::ChangeTokenMetadataUri(token_id, "URI".into())
            }
            _ => AccountCommand::ChangeTokenAuthority(token_id, Destination::AnyoneCanSpend),
        }
    }
}
