// opensource@mintlayer.org
// Copyright (c) 2026 RBB S.r.l
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

use std::{collections::BTreeSet, sync::Arc};

use itertools::Itertools as _;
use randomness::CryptoRng;
use rstest::rstest;
use strum::IntoEnumIterator as _;

use chainstate_test_framework::{
    TransactionBuilder, create_stake_pool_data_with_all_reward_to_staker,
};
use common::{
    chain::{
        AccountCommand, AccountCommandTag, AccountNonce, AccountOutPoint, AccountSpending,
        ChainConfig, CoinUnit, Destination, OutPointSourceId, PoolId, SignedTransaction,
        Transaction, TxOutput, UtxoOutPoint, make_delegation_id, make_token_id,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::{IsTokenUnfreezable, TokenId, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
        transaction::TxInput,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use logging::log;
use mempool::{AncestorScore, FeeRate, MempoolConfig, tx_accumulator::PackingStrategy};
use serialization::Encode as _;
use test_utils::{
    BasicTestTimeGetter,
    random::{RngExt as _, Seed, make_seedable_rng},
    random_ascii_alphanumeric_string,
};
use utils::{once_destructor::OnceDestructor, shuffled::Shuffled as _, sorted::Sorted as _};

use crate::{
    detail::tests::produce_block::assert_job_count,
    tests::helpers::{
        BlockprodTestSetup, BlockprodTestSetupBuilder, PoSTestSetupBuilder,
        add_local_txs_to_mempool, make_genesis_timestamp,
    },
};

#[derive(Debug, Copy, Clone)]
enum FeesSelection {
    Increasing,
    Random,
}

#[rstest_reuse::template]
pub fn fees_selection_param(
    #[values(FeesSelection::Increasing, FeesSelection::Random)] fees_selection: FeesSelection,
) {
}

#[rstest_reuse::apply(fees_selection_param)]
#[rstest]
// The test is heavily randomized, so we run it a few times to increase the likelihood of catching a problem.
#[case(Seed::from_entropy())]
#[case(Seed::from_entropy())]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_account_deps(#[case] seed: Seed, fees_selection: FeesSelection) {
    use token_account_deps_test_details::*;

    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

    let tx_count = rng.random_range(10..=15);
    log::debug!("tx_count = {tx_count}");

    let extra_genesis_txos = (0..tx_count)
        .map(|_| {
            TxOutput::Transfer(
                OutputValue::Coin(GENESIS_EXTRA_TXO_AMOUNT),
                Destination::AnyoneCanSpend,
            )
        })
        .collect();

    let pos_setup = PoSTestSetupBuilder::new()
        .with_extra_genesis_txos(extra_genesis_txos)
        .build(make_genesis_timestamp(&time_getter, &mut rng), &mut rng);

    let chain_config = Arc::clone(&pos_setup.chain_config);
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .with_mempool_config(MempoolConfig {
            min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
            max_cluster_tx_count: Default::default(),
            max_cluster_size_bytes: Default::default(),
        })
        .with_time_getter(time_getter.clone())
        .build();

    let base_fee = rng.random_range(10..20);
    // Every next fee is much larger than the previous, to ensure that in the Increasing case
    // each tx's ancestor score is determined by its own fee and not by fees of its ancestors.
    let fees = (0..tx_count)
        .map(|i| Amount::from_atoms(base_fee * 10u128.pow(i)))
        .collect_vec();
    let fees = reorder_fees(fees, fees_selection, &mut rng);

    log::debug!("fees = {fees:?}");

    let mut token_state =
        TokenState::new(Arc::clone(&blockprod_setup.chain_config), fees[0], &mut rng);

    let txs = std::iter::once(token_state.issuance_tx().clone())
        .chain(fees[1..].iter().map(|fee| token_state.make_next_tx(*fee, &mut rng)))
        .collect_vec();
    let encoded_sizes = txs.iter().map(|tx| tx.encoded_size()).collect_vec();

    log::debug!("txs = {txs:?}");
    log::debug!("encoded_sizes = {encoded_sizes:?}");

    let expected_tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect_vec();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            assert_fees(&blockprod_setup, &time_getter, &txs, &fees).await;
            let block_production = blockprod_setup.make_blockprod_builder().build();

            add_local_txs_to_mempool(&blockprod_setup.mempool, txs).await;

            match fees_selection {
                FeesSelection::Increasing => {
                    // Sanity check: ancestor scores are ordered the same way as fees.
                    assert_ancestor_scores(&blockprod_setup, &expected_tx_ids, &fees).await;
                }
                FeesSelection::Random => {}
            }

            let input_data = pos_setup.make_first_pos_block_input_data();

            let (new_block, job_finished_receiver) = block_production
                .produce_block(
                    input_data,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await
                .unwrap();

            let block_tx_ids = new_block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id())
                .collect::<Vec<_>>();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
            assert_eq!(block_tx_ids, expected_tx_ids);
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

mod token_account_deps_test_details {
    use std::borrow::Cow;

    use common::chain::{
        CoinUnit, SignedTransaction, Transaction, UtxoOutPoint,
        signature::{
            inputsig::standard_signature::StandardInputSignature,
            sighash::input_commitments::SighashInputCommitment,
        },
        tokens::{IsTokenFreezable, TokenTotalSupplyTag},
    };
    use crypto::key::{KeyKind, PrivateKey};
    use randomness::{CryptoRng, seq::IteratorRandom as _};

    use super::*;

    pub const GENESIS_EXTRA_TXO_AMOUNT: Amount =
        Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
    // The 0th genesis txo is consumed when producing the 1st block, so "extra" ones start
    // from index 1.
    const GENESIS_EXTRA_TXO_START_IDX: u32 = 1;

    pub struct TokenState {
        chain_config: Arc<ChainConfig>,
        issuance: TokenIssuanceV1,
        issuance_tx: SignedTransaction,
        token_id: TokenId,
        authority_sk: PrivateKey,
        authority: Destination,
        is_frozen: bool,
        is_locked: bool,
        token_utxo_and_amount: Option<(UtxoOutPoint, TxOutput, Amount)>,
        // Index of the next tx in the test sequence, not counting the issuance tx.
        next_extra_tx_idx: u32,
    }

    fn random_metadata_uri(rng: &mut impl CryptoRng) -> Vec<u8> {
        // Use a small uri to prevent the corresponding tx from becoming too big, which would
        // affect its score.
        random_ascii_alphanumeric_string(rng, 5..=10).as_bytes().to_vec()
    }

    impl TokenState {
        pub fn new(
            chain_config: Arc<ChainConfig>,
            issuance_tx_fee: Amount,
            rng: &mut impl CryptoRng,
        ) -> Self {
            let (authority_sk, authority_pk) =
                PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
            let authority = Destination::PublicKey(authority_pk.clone());

            let issuance = {
                let max_dec_count = chain_config.token_max_dec_count();
                let supply = match TokenTotalSupplyTag::iter().choose(rng).unwrap() {
                    TokenTotalSupplyTag::Fixed => {
                        let supply = Amount::from_atoms(rng.random_range(1_000_000..=2_000_000));
                        TokenTotalSupply::Fixed(supply)
                    }
                    TokenTotalSupplyTag::Lockable => TokenTotalSupply::Lockable,
                    TokenTotalSupplyTag::Unlimited => TokenTotalSupply::Unlimited,
                };

                let is_freezable = if rng.random::<bool>() {
                    IsTokenFreezable::Yes
                } else {
                    IsTokenFreezable::No
                };

                TokenIssuanceV1 {
                    token_ticker: random_ascii_alphanumeric_string(rng, 3..=5).as_bytes().to_vec(),
                    number_of_decimals: rng.random_range(1..=max_dec_count),
                    metadata_uri: random_metadata_uri(rng),
                    total_supply: supply,
                    is_freezable,
                    authority: authority.clone(),
                }
            };

            let issuance_tx = make_issuance_tx(
                issuance.clone(),
                &chain_config,
                issuance_tx_fee,
                GENESIS_EXTRA_TXO_START_IDX,
            );
            // Note: the height in make_token_id doesn't matter because the issuance tx's first input is a utxo.
            let token_id = make_token_id(
                chain_config.as_ref(),
                BlockHeight::new(1),
                issuance_tx.transaction().inputs(),
            )
            .unwrap();

            Self {
                chain_config,
                issuance,
                issuance_tx,
                token_id,
                authority_sk,
                authority,
                is_frozen: false,
                is_locked: false,
                token_utxo_and_amount: None,
                next_extra_tx_idx: 0,
            }
        }

        pub fn issuance_tx(&self) -> &SignedTransaction {
            &self.issuance_tx
        }

        pub fn make_next_tx(&mut self, fee: Amount, rng: &mut impl CryptoRng) -> SignedTransaction {
            let genesis_txo_idx = GENESIS_EXTRA_TXO_START_IDX + self.next_extra_tx_idx + 1;
            let nonce = AccountNonce::new(self.next_extra_tx_idx as u64);

            let genesis_outpoint =
                UtxoOutPoint::new(self.chain_config.genesis_block_id().into(), genesis_txo_idx);
            let genesis_txo =
                self.chain_config.genesis_block().utxos()[genesis_txo_idx as usize].clone();
            let mut tx_inputs_and_commitments: Vec<(TxInput, _)> = vec![(
                genesis_outpoint.into(),
                SighashInputCommitment::Utxo(Cow::Owned(genesis_txo)),
            )];
            let mut tx_outputs: Vec<TxOutput> = vec![];

            let cmd_tag = *self.possible_commands().iter().choose(rng).unwrap();

            let mut new_token_output_idx_and_amount: Option<(u32, Amount)> = None;
            let mut new_authority_sk_and_destination: Option<(PrivateKey, Destination)> = None;
            let extra_fee;

            let command = match cmd_tag {
                AccountCommandTag::MintTokens => {
                    let amount = Amount::from_atoms(rng.random_range(100..=1000));

                    new_token_output_idx_and_amount = Some((tx_outputs.len() as u32, amount));

                    tx_outputs.push(TxOutput::Transfer(
                        OutputValue::TokenV1(self.token_id, amount),
                        Destination::AnyoneCanSpend,
                    ));

                    extra_fee = self.chain_config.token_supply_change_fee(BlockHeight::new(1));

                    AccountCommand::MintTokens(self.token_id, amount)
                }
                AccountCommandTag::UnmintTokens => {
                    let (token_outpoint, token_utxo, token_amount) =
                        self.token_utxo_and_amount.as_ref().unwrap();

                    assert!(*token_amount > Amount::ZERO);
                    let amount_to_unmint =
                        Amount::from_atoms(rng.random_range(1..=token_amount.into_atoms()));
                    let change = (*token_amount - amount_to_unmint).unwrap();

                    tx_inputs_and_commitments.push((
                        token_outpoint.clone().into(),
                        SighashInputCommitment::Utxo(Cow::Owned(token_utxo.clone())),
                    ));
                    tx_outputs.push(TxOutput::Burn(OutputValue::TokenV1(
                        self.token_id,
                        amount_to_unmint,
                    )));

                    if change > Amount::ZERO {
                        new_token_output_idx_and_amount = Some((tx_outputs.len() as u32, change));

                        tx_outputs.push(TxOutput::Transfer(
                            OutputValue::TokenV1(self.token_id, change),
                            Destination::AnyoneCanSpend,
                        ));
                    } else {
                        self.token_utxo_and_amount = None;
                    }

                    extra_fee = self.chain_config.token_supply_change_fee(BlockHeight::new(1));

                    AccountCommand::UnmintTokens(self.token_id)
                }
                AccountCommandTag::LockTokenSupply => {
                    self.is_locked = true;

                    extra_fee = self.chain_config.token_supply_change_fee(BlockHeight::new(1));

                    AccountCommand::LockTokenSupply(self.token_id)
                }
                AccountCommandTag::FreezeToken => {
                    self.is_frozen = true;

                    extra_fee = self.chain_config.token_freeze_fee(BlockHeight::new(1));

                    AccountCommand::FreezeToken(self.token_id, IsTokenUnfreezable::Yes)
                }
                AccountCommandTag::UnfreezeToken => {
                    self.is_frozen = false;

                    extra_fee = self.chain_config.token_freeze_fee(BlockHeight::new(1));

                    AccountCommand::UnfreezeToken(self.token_id)
                }
                AccountCommandTag::ChangeTokenAuthority => {
                    let (new_authority_sk, new_authority_pk) =
                        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
                    let new_authority = Destination::PublicKey(new_authority_pk.clone());

                    new_authority_sk_and_destination =
                        Some((new_authority_sk, new_authority.clone()));

                    extra_fee = self.chain_config.token_change_authority_fee(BlockHeight::new(1));

                    AccountCommand::ChangeTokenAuthority(self.token_id, new_authority)
                }
                AccountCommandTag::ChangeTokenMetadataUri => {
                    extra_fee = self.chain_config.token_change_metadata_uri_fee();

                    AccountCommand::ChangeTokenMetadataUri(self.token_id, random_metadata_uri(rng))
                }

                AccountCommandTag::ConcludeOrder | AccountCommandTag::FillOrder => {
                    panic!("Unexpected non-token command");
                }
            };

            let total_fee = (fee + extra_fee).unwrap();
            let change = (GENESIS_EXTRA_TXO_AMOUNT - total_fee).unwrap();
            assert!(change > Amount::ZERO);
            tx_outputs.push(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ));

            tx_inputs_and_commitments.push((
                TxInput::AccountCommand(nonce, command),
                SighashInputCommitment::None,
            ));

            let (tx_inputs, tx_input_commitments): (Vec<_>, Vec<_>) =
                tx_inputs_and_commitments.into_iter().unzip();

            let inputs_count = tx_inputs.len();
            let tx = Transaction::new(0, tx_inputs, tx_outputs).unwrap();

            let account_cmd_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &self.authority_sk,
                Default::default(),
                self.authority.clone(),
                &tx,
                &tx_input_commitments,
                0,
                rng,
            )
            .unwrap();

            self.next_extra_tx_idx += 1;

            if let Some((idx, amount)) = new_token_output_idx_and_amount {
                if amount != Amount::ZERO {
                    let txo = tx.outputs()[idx as usize].clone();
                    self.token_utxo_and_amount =
                        Some((UtxoOutPoint::new(tx.get_id().into(), idx), txo, amount))
                } else {
                    self.token_utxo_and_amount = None;
                }
            }

            if let Some((new_authority_sk, new_authority)) = new_authority_sk_and_destination {
                self.authority_sk = new_authority_sk;
                self.authority = new_authority;
            }

            SignedTransaction::new(
                tx,
                std::iter::repeat_n(InputWitness::NoSignature(None), inputs_count - 1)
                    .chain([InputWitness::Standard(account_cmd_sig)])
                    .collect(),
            )
            .unwrap()
        }

        fn possible_commands(&self) -> BTreeSet<AccountCommandTag> {
            if self.is_frozen {
                // The only things we can do with a frozen token is unfreeze.
                return BTreeSet::from([AccountCommandTag::UnfreezeToken]);
            }

            let mut result = BTreeSet::new();

            for tag in AccountCommandTag::iter() {
                let can_add = match tag {
                    AccountCommandTag::MintTokens => {
                        // We assume that mint amounts and the number of mints will always be less than the total supply.
                        !self.is_locked
                    }
                    AccountCommandTag::UnmintTokens => {
                        !self.is_locked
                            && self
                                .token_utxo_and_amount
                                .as_ref()
                                .is_some_and(|(_, _, amount)| *amount > Amount::ZERO)
                    }
                    AccountCommandTag::LockTokenSupply => match self.issuance.total_supply {
                        TokenTotalSupply::Fixed(_) | TokenTotalSupply::Unlimited => false,
                        TokenTotalSupply::Lockable => !self.is_locked,
                    },

                    AccountCommandTag::ChangeTokenAuthority
                    | AccountCommandTag::ChangeTokenMetadataUri => true,

                    AccountCommandTag::FreezeToken => self.issuance.is_freezable.as_bool(),
                    AccountCommandTag::UnfreezeToken => false,

                    // These are not token commands.
                    AccountCommandTag::ConcludeOrder | AccountCommandTag::FillOrder => false,
                };

                if can_add {
                    result.insert(tag);
                }
            }

            result
        }
    }

    fn make_issuance_tx(
        issuance: TokenIssuanceV1,
        chain_config: &ChainConfig,
        fee: Amount,
        genesis_txo_idx: u32,
    ) -> SignedTransaction {
        let total_fee = (chain_config.fungible_token_issuance_fee() + fee).unwrap();
        let change = (GENESIS_EXTRA_TXO_AMOUNT - total_fee).unwrap();
        assert!(change > Amount::ZERO);

        TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    genesis_txo_idx,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                issuance,
            ))))
            .build()
    }
}

// Note: this test creates only 2 txs, so Random case doesn't make much sense, so we only check
// the Increasing case here.
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_creation_and_decommissioning(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

    let genesis_extra_txo_amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
    let extra_genesis_txo = TxOutput::Transfer(
        OutputValue::Coin(genesis_extra_txo_amount),
        Destination::AnyoneCanSpend,
    );
    let pos_setup = PoSTestSetupBuilder::new()
        .with_extra_genesis_txos(vec![extra_genesis_txo.clone(), extra_genesis_txo])
        .build(make_genesis_timestamp(&time_getter, &mut rng), &mut rng);

    let chain_config = Arc::clone(&pos_setup.chain_config);
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .with_mempool_config(MempoolConfig {
            min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
            max_cluster_tx_count: Default::default(),
            max_cluster_size_bytes: Default::default(),
        })
        .with_time_getter(time_getter.clone())
        .build();

    let base_fee = rng.random_range(10..20);
    // The fees are progressively increasing, making the second (decommissioning) tx more lucrative.
    let fees = vec![Amount::from_atoms(base_fee), Amount::from_atoms(base_fee * 10)];

    let min_pledge = chain_config.min_stake_pool_pledge().into_atoms();
    let pool_size = Amount::from_atoms(rng.random_range(min_pledge..min_pledge * 2));

    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, pool_size, vrf_pk);

    let genesis_outpoint1 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 1);
    let genesis_outpoint2 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 2);
    let pool_id = PoolId::from_utxo(&genesis_outpoint1);
    let create_pool_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint1.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(((genesis_extra_txo_amount - pool_size).unwrap() - fees[0]).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let create_pool_tx_id = create_pool_tx.transaction().get_id();
    let create_pool_outpoint = UtxoOutPoint::new(create_pool_tx_id.into(), 0);

    let pool_maturity_block_count =
        chain_config.staking_pool_spend_maturity_block_count(BlockHeight::one());
    let decommission_pool_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint2.into(), InputWitness::NoSignature(None))
        .add_input(create_pool_outpoint.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(pool_size),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(pool_maturity_block_count.to_int()),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((genesis_extra_txo_amount - fees[1]).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let txs = vec![create_pool_tx, decommission_pool_tx];
    let expected_tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect_vec();

    log::debug!("fees = {fees:?}");
    log::debug!("expected_tx_ids = {expected_tx_ids:?}");

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            assert_fees(&blockprod_setup, &time_getter, &txs, &fees).await;

            let block_production = blockprod_setup.make_blockprod_builder().build();

            add_local_txs_to_mempool(&blockprod_setup.mempool, txs).await;

            assert_ancestor_scores(&blockprod_setup, &expected_tx_ids, &fees).await;

            let input_data = pos_setup.make_first_pos_block_input_data();

            let (new_block, job_finished_receiver) = block_production
                .produce_block(
                    input_data,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await
                .unwrap();

            let block_tx_ids = new_block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id())
                .collect::<Vec<_>>();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
            assert_eq!(block_tx_ids, expected_tx_ids);
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[rstest_reuse::apply(fees_selection_param)]
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_creation_and_delegation(#[case] seed: Seed, fees_selection: FeesSelection) {
    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

    let genesis_extra_txo_amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
    let extra_genesis_txo = TxOutput::Transfer(
        OutputValue::Coin(genesis_extra_txo_amount),
        Destination::AnyoneCanSpend,
    );
    let pos_setup = PoSTestSetupBuilder::new()
        .with_extra_genesis_txos(vec![
            extra_genesis_txo.clone(),
            extra_genesis_txo.clone(),
            extra_genesis_txo,
        ])
        .build(make_genesis_timestamp(&time_getter, &mut rng), &mut rng);

    let chain_config = Arc::clone(&pos_setup.chain_config);
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .with_mempool_config(MempoolConfig {
            min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
            max_cluster_tx_count: Default::default(),
            max_cluster_size_bytes: Default::default(),
        })
        .with_time_getter(time_getter.clone())
        .build();

    let base_fee = rng.random_range(10..20);
    // The fees are progressively increasing, making the dependent txs more lucrative.
    let fees = vec![
        Amount::from_atoms(base_fee),
        Amount::from_atoms(base_fee * 10),
        Amount::from_atoms(base_fee * 100),
    ];
    let fees = reorder_fees(fees, fees_selection, &mut rng);

    let min_pledge = chain_config.min_stake_pool_pledge().into_atoms();
    let pool_size = Amount::from_atoms(rng.random_range(min_pledge..min_pledge * 2));

    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, pool_size, vrf_pk);

    let genesis_outpoint1 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 1);
    let genesis_outpoint2 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 2);
    let genesis_outpoint3 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 3);

    let pool_id = PoolId::from_utxo(&genesis_outpoint1);
    let create_pool_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint1.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(((genesis_extra_txo_amount - pool_size).unwrap() - fees[0]).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let create_delegation_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint2.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            pool_id,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((genesis_extra_txo_amount - fees[1]).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let delegation_id = make_delegation_id(create_delegation_tx.inputs()).unwrap();

    let delegation_amount = Amount::from_atoms(rng.random_range(min_pledge..min_pledge * 2));
    let delegate_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint3.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::DelegateStaking(delegation_amount, delegation_id))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(
                ((genesis_extra_txo_amount - delegation_amount).unwrap() - fees[2]).unwrap(),
            ),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let txs = vec![create_pool_tx, create_delegation_tx, delegate_tx];
    let expected_tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect_vec();

    log::debug!("fees = {fees:?}");
    log::debug!("expected_tx_ids = {expected_tx_ids:?}");

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            assert_fees(&blockprod_setup, &time_getter, &txs, &fees).await;

            let block_production = blockprod_setup.make_blockprod_builder().build();

            add_local_txs_to_mempool(&blockprod_setup.mempool, txs).await;

            match fees_selection {
                FeesSelection::Increasing => {
                    // Sanity check: ancestor scores are ordered the same way as fees.
                    assert_ancestor_scores(&blockprod_setup, &expected_tx_ids, &fees).await;
                }
                FeesSelection::Random => {}
            }

            let input_data = pos_setup.make_first_pos_block_input_data();

            let (new_block, job_finished_receiver) = block_production
                .produce_block(
                    input_data,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await
                .unwrap();

            let block_tx_ids = new_block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id())
                .collect::<Vec<_>>();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
            assert_eq!(block_tx_ids, expected_tx_ids);
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

// Node: delegations and delegation withdrawals are not ordered with respect to each other,
// this is why we only test zero withdrawals here.
#[rstest_reuse::apply(fees_selection_param)]
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_creation_and_delegation_withdrawals(
    #[case] seed: Seed,
    fees_selection: FeesSelection,
) {
    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

    let withdrawal_tx_count = rng.random_range(2..=5);
    let genesis_extra_txo_amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
    let extra_genesis_txos = (0..2 + withdrawal_tx_count)
        .map(|_| {
            TxOutput::Transfer(
                OutputValue::Coin(genesis_extra_txo_amount),
                Destination::AnyoneCanSpend,
            )
        })
        .collect();
    let pos_setup = PoSTestSetupBuilder::new()
        .with_extra_genesis_txos(extra_genesis_txos)
        .build(make_genesis_timestamp(&time_getter, &mut rng), &mut rng);

    let chain_config = Arc::clone(&pos_setup.chain_config);
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .with_mempool_config(MempoolConfig {
            min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
            max_cluster_tx_count: Default::default(),
            max_cluster_size_bytes: Default::default(),
        })
        .with_time_getter(time_getter.clone())
        .build();

    let base_fee = rng.random_range(10..20);
    let fees = (0..2 + withdrawal_tx_count)
        .map(|i| Amount::from_atoms(base_fee * 10u128.pow(i)))
        .collect_vec();
    let fees = reorder_fees(fees, fees_selection, &mut rng);

    let min_pledge = chain_config.min_stake_pool_pledge().into_atoms();
    let pool_size = Amount::from_atoms(rng.random_range(min_pledge..min_pledge * 2));

    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, pool_size, vrf_pk);

    let genesis_outpoint1 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 1);
    let genesis_outpoint2 = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 2);

    let pool_id = PoolId::from_utxo(&genesis_outpoint1);
    let create_pool_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint1.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(((genesis_extra_txo_amount - pool_size).unwrap() - fees[0]).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let create_delegation_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint2.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            pool_id,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((genesis_extra_txo_amount - fees[1]).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let delegation_id = make_delegation_id(create_delegation_tx.inputs()).unwrap();

    let withdrawal_txs_iter = (0..withdrawal_tx_count).map(|i| {
        let genesis_outpoint = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 3 + i);

        TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(i as u64),
                    AccountSpending::DelegationBalance(delegation_id, Amount::ZERO),
                )),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((genesis_extra_txo_amount - fees[2 + i as usize]).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build()
    });

    let txs = [create_pool_tx, create_delegation_tx]
        .into_iter()
        .chain(withdrawal_txs_iter)
        .collect_vec();
    let expected_tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect_vec();

    log::debug!("fees = {fees:?}");
    log::debug!("expected_tx_ids = {expected_tx_ids:?}");

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            assert_fees(&blockprod_setup, &time_getter, &txs, &fees).await;

            let block_production = blockprod_setup.make_blockprod_builder().build();

            add_local_txs_to_mempool(&blockprod_setup.mempool, txs).await;

            match fees_selection {
                FeesSelection::Increasing => {
                    // Sanity check: ancestor scores are ordered the same way as fees.
                    assert_ancestor_scores(&blockprod_setup, &expected_tx_ids, &fees).await;
                }
                FeesSelection::Random => {}
            }

            let input_data = pos_setup.make_first_pos_block_input_data();

            let (new_block, job_finished_receiver) = block_production
                .produce_block(
                    input_data,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await
                .unwrap();

            let block_tx_ids = new_block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id())
                .collect::<Vec<_>>();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
            assert_eq!(block_tx_ids, expected_tx_ids);
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

fn reorder_fees(
    fees: Vec<Amount>,
    fees_selection: FeesSelection,
    rng: &mut impl CryptoRng,
) -> Vec<Amount> {
    match fees_selection {
        FeesSelection::Increasing => {
            assert_eq!(fees.clone().sorted(), fees);
            fees
        }
        FeesSelection::Random => fees.shuffled(rng),
    }
}

async fn assert_fees(
    blockprod_setup: &BlockprodTestSetup,
    time_getter: &TimeGetter,
    txs: &[SignedTransaction],
    fees: &[Amount],
) {
    let mut tx_verifier = mempool::tx_verifier::create(
        Arc::clone(&blockprod_setup.chain_config),
        blockprod_setup.chainstate.clone(),
    );

    let best_block_index = blockprod_setup
        .chainstate
        .call(|cs| {
            let tip = cs.get_best_block_id().unwrap();
            let tip_index = cs.get_gen_block_index_for_persisted_block(&tip).unwrap().unwrap();
            tip_index
        })
        .await
        .unwrap();

    for (tx, fee) in txs.iter().zip_eq(fees.iter()) {
        use chainstate::tx_verifier::transaction_verifier::TransactionSourceForConnect;
        use common::chain::block::timestamp::BlockTimestamp;

        let actual_fee = tx_verifier
            .connect_transaction(
                &TransactionSourceForConnect::for_mempool_with_height(
                    &best_block_index,
                    BlockHeight::new(1),
                ),
                &tx,
                &BlockTimestamp::from_time(time_getter.get_time()),
            )
            .unwrap()
            .map_into_block_fees(&blockprod_setup.chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(actual_fee.0, *fee);
    }
}

// Assert that ancestor scores of the specified mempool txs have the same order as their fees.
async fn assert_ancestor_scores(
    blockprod_setup: &BlockprodTestSetup,
    tx_ids: &[Id<Transaction>],
    fees: &[Amount],
) {
    let tx_ids = tx_ids.to_vec();
    let scores = blockprod_setup
        .mempool
        .call(move |mp| {
            tx_ids
                .iter()
                .map(|tx_id| mp.get_tx_score(tx_id).unwrap().unwrap())
                .collect_vec()
        })
        .await
        .unwrap();

    log::debug!("scores = {scores:?}");

    let fees_with_index = fees.iter().enumerate().collect_vec();
    let sorted_fees = fees_with_index
        .sorted_by(|(_, fee1): &(_, &Amount), (_, fee2): &(_, &Amount)| fee1.cmp(fee2));
    let fees_sort_indices = sorted_fees.iter().map(|(idx, _)| idx).collect_vec();

    let scores_with_index = scores.iter().enumerate().collect_vec();
    let sorted_scores = scores_with_index.sorted_by(
        |(_, score1): &(_, &AncestorScore), (_, score2): &(_, &AncestorScore)| score1.cmp(score2),
    );
    let score_sort_indices = sorted_scores.iter().map(|(idx, _)| idx).collect_vec();

    assert_eq!(fees_sort_indices, score_sort_indices);
}
