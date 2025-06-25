// Copyright (c) 2025 RBB S.r.l
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

use std::{
    num::NonZeroU8,
    ops::{Add, Div},
    sync::Arc,
};

use itertools::{izip, Itertools as _};

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        config::create_regtest,
        htlc::{HashedTimelockContract, HtlcSecret},
        output_value::OutputValue,
        signature::{inputsig::arbitrary_message::produce_message_challenge, DestinationSigError},
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0, TokenId, TokenIssuance,
            TokenIssuanceV1,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, ChainConfig, DelegationId,
        Destination, GenBlock, OrderAccountCommand, OrderData, OrderId, OutPointSourceId, PoolId,
        SignedTransactionIntent, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, Idable, H256},
};
use crypto::{
    key::{hdkd::u31::U31, KeyKind, PrivateKey},
    vrf::VRFPrivateKey,
};
use logging::log;
use randomness::{CryptoRng, Rng};
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{random::gen_random_bytes, random_ascii_alphanumeric_string};
use tx_verifier::error::{InputCheckErrorPayload, ScriptError};
use wallet_storage::{DefaultBackend, Store, TransactionRwUnlocked, Transactional};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    partially_signed_transaction::{
        OrderAdditionalInfo, PoolAdditionalInfo, TokenAdditionalInfo, TxAdditionalInfo,
    },
    BlockInfo, Currency, KeyPurpose,
};

use crate::{
    account::PoolData,
    key_chain::AccountKeyChains,
    signer::{tests::account_from_mnemonic, Signer, SignerError},
    Account, SendRequest,
};

pub fn test_sign_message_generic<MkS1, MkS2, S1, S2>(
    rng: &mut (impl Rng + CryptoRng),
    make_signer: MkS1,
    make_another_signer: Option<MkS2>,
) where
    MkS1: Fn(Arc<ChainConfig>, U31) -> S1,
    MkS2: Fn(Arc<ChainConfig>, U31) -> S2,
    S1: Signer,
    S2: Signer,
{
    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);

    let pkh_destination = account
        .get_new_address(&mut db_tx, KeyPurpose::ReceiveFunds)
        .unwrap()
        .1
        .into_object();
    let pkh = match pkh_destination {
        Destination::PublicKeyHash(pkh) => pkh,
        _ => panic!("not a public key hash destination"),
    };
    let pk = account.find_corresponding_pub_key(&pkh).unwrap();
    let pk_destination = Destination::PublicKey(pk);

    let (standalone_private_key, standalone_pk) =
        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    account
        .add_standalone_private_key(&mut db_tx, standalone_private_key, None)
        .unwrap();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk);

    for destination in [pkh_destination, pk_destination, standalone_pk_destination] {
        let message = vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
        let message_challenge = produce_message_challenge(&message);

        let mut signer = make_signer(chain_config.clone(), account.account_index());
        let res = signer
            .sign_challenge(&message, &destination, account.key_chain(), &db_tx)
            .unwrap();
        res.verify_signature(&chain_config, &destination, &message_challenge).unwrap();

        if let Some(make_another_signer) = &make_another_signer {
            let mut another_signer =
                make_another_signer(chain_config.clone(), account.account_index());

            let another_res = another_signer
                .sign_challenge(&message, &destination, account.key_chain(), &db_tx)
                .unwrap();
            another_res
                .verify_signature(&chain_config, &destination, &message_challenge)
                .unwrap();

            assert_eq!(res, another_res);
        }
    }

    // Check we cannot sign if we don't know the destination
    let (_, random_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let random_pk_destination = Destination::PublicKey(random_pk);

    let mut signer = make_signer(chain_config.clone(), account.account_index());

    let message = vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
    let err = signer
        .sign_challenge(
            &message,
            &random_pk_destination,
            account.key_chain(),
            &db_tx,
        )
        .unwrap_err();

    assert_eq!(err, SignerError::DestinationNotFromThisWallet);
}

pub fn test_sign_transaction_intent_generic<MkS1, MkS2, S1, S2>(
    rng: &mut (impl Rng + CryptoRng),
    make_signer: MkS1,
    make_another_signer: Option<MkS2>,
) where
    MkS1: Fn(Arc<ChainConfig>, U31) -> S1,
    MkS2: Fn(Arc<ChainConfig>, U31) -> S2,
    S1: Signer,
    S2: Signer,
{
    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);

    let (standalone_private_key, standalone_pk) =
        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    account
        .add_standalone_private_key(&mut db_tx, standalone_private_key, None)
        .unwrap();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk);

    let inputs: Vec<TxInput> = (0..rng.gen_range(3..6))
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();
    let num_inputs = inputs.len();
    let mut input_destinations: Vec<_> = (1..num_inputs)
        .map(|_| {
            let pkh_destination = account
                .get_new_address(&mut db_tx, KeyPurpose::ReceiveFunds)
                .unwrap()
                .1
                .into_object();
            if rng.gen::<bool>() {
                pkh_destination
            } else {
                let pkh = match pkh_destination {
                    Destination::PublicKeyHash(pkh) => pkh,
                    _ => panic!("not a public key hash destination"),
                };
                let pk = account.find_corresponding_pub_key(&pkh).unwrap();
                Destination::PublicKey(pk)
            }
        })
        .chain([standalone_pk_destination])
        .collect();

    let tx = Transaction::new(
        0,
        inputs,
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            account.get_new_address(&mut db_tx, KeyPurpose::Change).unwrap().1.into_object(),
        )],
    )
    .unwrap();

    let intent: String = [rng.gen::<char>(), rng.gen::<char>(), rng.gen::<char>()].iter().collect();
    log::debug!("Generated intent: `{intent}`");
    let expected_signed_message =
        SignedTransactionIntent::get_message_to_sign(&intent, &tx.get_id());

    let mut signer = make_signer(chain_config.clone(), account.account_index());
    let res = signer
        .sign_transaction_intent(
            &tx,
            &input_destinations,
            &intent,
            account.key_chain(),
            &db_tx,
        )
        .unwrap();
    res.verify(&chain_config, &input_destinations, &expected_signed_message)
        .unwrap();

    if let Some(make_another_signer) = &make_another_signer {
        let mut another_signer = make_another_signer(chain_config.clone(), account.account_index());
        let another_res = another_signer
            .sign_transaction_intent(
                &tx,
                &input_destinations,
                &intent,
                account.key_chain(),
                &db_tx,
            )
            .unwrap();
        another_res
            .verify(&chain_config, &input_destinations, &expected_signed_message)
            .unwrap();

        assert_eq!(res, another_res);
    }

    // cannot sign when there is a random destination
    let (_, random_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let random_pk_destination = Destination::PublicKey(random_pk);
    input_destinations[rng.gen_range(0..num_inputs)] = random_pk_destination;

    let err = signer
        .sign_transaction_intent(
            &tx,
            &input_destinations,
            &intent,
            account.key_chain(),
            &db_tx,
        )
        .unwrap_err();

    assert_eq!(err, SignerError::DestinationNotFromThisWallet);
}

pub fn test_sign_transaction_generic<MkS1, MkS2, S1, S2>(
    rng: &mut (impl Rng + CryptoRng),
    make_signer: MkS1,
    make_another_signer: Option<MkS2>,
) where
    MkS1: Fn(Arc<ChainConfig>, U31) -> S1,
    MkS2: Fn(Arc<ChainConfig>, U31) -> S2,
    S1: Signer,
    S2: Signer,
{
    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);
    let mut account2 = account_from_mnemonic(&chain_config, &mut db_tx, U31::ONE);

    let (standalone_private_key, standalone_pk) =
        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    account
        .add_standalone_private_key(&mut db_tx, standalone_private_key, None)
        .unwrap();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk.clone());

    let coin_input_amounts: Vec<Amount> = (0..rng.gen_range(2..7))
        .map(|_| Amount::from_atoms(rng.gen_range(100..1000)))
        .collect();

    let total_coin_input_amount =
        coin_input_amounts.iter().fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());

    let decommissioned_pool_id = PoolId::new(H256::random_using(rng));
    let decommissioned_pool_balance = Amount::from_atoms(rng.gen_range(100..200));
    let decommissioned_pool_data = PoolData {
        utxo_outpoint: UtxoOutPoint::new(Id::<Transaction>::random_using(rng).into(), 1),
        creation_block: BlockInfo {
            height: BlockHeight::new(rng.gen()),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        },
        decommission_key: destination_from_account(&mut account, &mut db_tx, rng),
        stake_destination: random_destination(rng),
        vrf_public_key: VRFPrivateKey::new_from_rng(rng, crypto::vrf::VRFKeyKind::Schnorrkel).1,
        margin_ratio_per_thousand: PerThousand::new_from_rng(rng),
        cost_per_block: Amount::from_atoms(rng.gen_range(100..200)),
    };

    let produce_block_from_stake_utxo =
        TxOutput::ProduceBlockFromStake(random_destination(rng), decommissioned_pool_id);
    let utxos: Vec<TxOutput> = coin_input_amounts
        .iter()
        .skip(1)
        .map(|a| {
            let dest = destination_from_account(&mut account, &mut db_tx, rng);

            TxOutput::Transfer(OutputValue::Coin(*a), dest)
        })
        .chain([TxOutput::Transfer(
            OutputValue::Coin(coin_input_amounts[0]),
            standalone_pk_destination.clone(),
        )])
        .chain([produce_block_from_stake_utxo])
        .collect();

    let inputs: Vec<TxInput> = (0..utxos.len())
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();

    let (_, pub_key1) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let pub_key2 = if let Destination::PublicKeyHash(pkh) =
        account.get_new_address(&mut db_tx, KeyPurpose::Change).unwrap().1.into_object()
    {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };
    let pub_key3 = if let Destination::PublicKeyHash(pkh) = account2
        .get_new_address(&mut db_tx, KeyPurpose::Change)
        .unwrap()
        .1
        .into_object()
    {
        account2.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };

    let min_required_signatures = 3;
    // The first account can sign the pub_key2 and the standalone key,
    // but it will not be fully signed, so we will need to sign it with the account2 which
    // can complete the signing with the pub_key3.
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![pub_key1.clone(), pub_key2.clone(), standalone_pk, pub_key3.clone()],
    )
    .unwrap();
    account.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();
    let multisig_hash = account2.add_standalone_multisig(&mut db_tx, challenge, None).unwrap();

    let multisig_dest = Destination::ClassicMultisig(multisig_hash);

    let source_id: OutPointSourceId = if rng.gen_bool(0.5) {
        Id::<Transaction>::new(H256::random_using(rng)).into()
    } else {
        Id::<GenBlock>::new(H256::random_using(rng)).into()
    };
    let multisig_input = TxInput::from_utxo(source_id.clone(), rng.next_u32());
    let multisig_utxo = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..200))),
        multisig_dest.clone(),
    );

    let secret = HtlcSecret::new_from_rng(rng);
    let hash_lock = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: Destination::PublicKey(pub_key2.clone()),
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(rng.gen_range(100..200))),
        refund_key: Destination::PublicKey(pub_key1),
    };

    let htlc_input = TxInput::from_utxo(source_id, rng.next_u32());
    let htlc_utxo = TxOutput::Htlc(
        OutputValue::Coin(Amount::from_atoms(rng.gen::<u32>() as u128)),
        Box::new(hash_lock.clone()),
    );

    let token_id = TokenId::new(H256::random_using(rng));
    let token_mint_amount = Amount::from_atoms(rng.gen_range(100..200));

    let coin_transfer_amount = total_coin_input_amount.div(rng.gen_range(10..20)).unwrap();
    let coin_lock_then_transfer_amount =
        total_coin_input_amount.div(rng.gen_range(10..20)).unwrap();
    let coin_burn_amount = total_coin_input_amount.div(rng.gen_range(10..20)).unwrap();
    let delegate_staking_amount = total_coin_input_amount.div(rng.gen_range(10..20)).unwrap();
    let htlc_transfer_amount = total_coin_input_amount.div(rng.gen_range(10..20)).unwrap();

    let filled_order1_id = OrderId::new(H256::random_using(rng));
    let filled_order2_id = OrderId::new(H256::random_using(rng));
    let concluded_order1_id = OrderId::new(H256::random_using(rng));
    let concluded_order2_id = OrderId::new(H256::random_using(rng));
    let frozen_order_id = OrderId::new(H256::random_using(rng));

    let filled_order1_info = random_order_info(
        &Currency::Coin,
        &Currency::Token(token_id),
        100,
        200,
        10,
        rng,
    );

    let filled_order2_info = random_order_info(
        &Currency::Token(token_id),
        &Currency::Coin,
        100,
        200,
        10,
        rng,
    );

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(rng.gen_range(0..100)),
            AccountSpending::DelegationBalance(
                DelegationId::new(H256::random_using(rng)),
                Amount::from_atoms(rng.gen_range(100..200)),
            ),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::MintTokens(token_id, token_mint_amount),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnmintTokens(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::LockTokenSupply(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnfreezeToken(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ChangeTokenAuthority(
                TokenId::new(H256::random_using(rng)),
                Destination::AnyoneCanSpend,
            ),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ConcludeOrder(concluded_order1_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::FillOrder(
                filled_order1_id,
                Amount::from_atoms(
                    rng.gen_range(1..filled_order1_info.initially_asked.amount().into_atoms()),
                ),
                Destination::AnyoneCanSpend,
            ),
        ),
        TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(concluded_order2_id)),
        TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(frozen_order_id)),
        TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
            filled_order2_id,
            Amount::from_atoms(
                rng.gen_range(1..filled_order2_info.initially_asked.amount().into_atoms()),
            ),
            Destination::AnyoneCanSpend,
        )),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ChangeTokenMetadataUri(
                TokenId::new(H256::random_using(rng)),
                random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
            ),
        ),
    ];
    let acc_dests: Vec<Destination> = acc_inputs
        .iter()
        .map(|_| destination_from_account(&mut account, &mut db_tx, rng))
        .collect();

    let (_dest_prv, dest_pub) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let (_, vrf_public_key) = VRFPrivateKey::new_from_rng(rng, crypto::vrf::VRFKeyKind::Schnorrkel);

    let created_pool_id = PoolId::new(H256::random_using(rng));
    let delegation_id = DelegationId::new(H256::random_using(rng));
    let pool_data = StakePoolData::new(
        Amount::from_atoms(rng.gen_range(100..200)),
        Destination::PublicKey(dest_pub.clone()),
        vrf_public_key,
        Destination::PublicKey(dest_pub.clone()),
        PerThousand::new_from_rng(rng),
        Amount::from_atoms(rng.gen_range(10..100)),
    );
    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: random_ascii_alphanumeric_string(rng, 2..10).into_bytes(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: Destination::PublicKey(dest_pub.clone()),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    });

    let nft_issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
            description: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
            ticker: random_ascii_alphanumeric_string(rng, 2..10).into_bytes(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(None),
            media_hash: gen_random_bytes(rng, 4, 20),
        },
    });
    let nft_id = TokenId::new(H256::random_using(rng));

    let created_order_data = OrderData::new(
        Destination::PublicKey(dest_pub.clone()),
        OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..200))),
        OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen_range(100..200))),
    );

    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::TokenV1(
                token_id,
                Amount::from_atoms(rng.gen_range(1..=token_mint_amount.into_atoms())),
            ),
            Destination::PublicKey(dest_pub.clone()),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(coin_transfer_amount),
            Destination::PublicKey(dest_pub),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(coin_lock_then_transfer_amount),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(rng.next_u64()),
        ),
        TxOutput::Burn(OutputValue::Coin(coin_burn_amount)),
        TxOutput::CreateStakePool(created_pool_id, Box::new(pool_data)),
        TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            PoolId::new(H256::random_using(rng)),
        ),
        TxOutput::DelegateStaking(delegate_staking_amount, delegation_id),
        TxOutput::IssueFungibleToken(Box::new(token_issuance)),
        TxOutput::IssueNft(
            nft_id,
            Box::new(nft_issuance.clone()),
            Destination::AnyoneCanSpend,
        ),
        TxOutput::DataDeposit(gen_random_bytes(rng, 10, 20)),
        TxOutput::Htlc(OutputValue::Coin(htlc_transfer_amount), Box::new(hash_lock)),
        TxOutput::CreateOrder(Box::new(created_order_data)),
    ];

    let req = SendRequest::new()
        .with_inputs(
            izip!(inputs.clone(), utxos.clone(), vec![None; inputs.len()]),
            &|pool_id| {
                assert_eq!(*pool_id, decommissioned_pool_id);
                Some(&decommissioned_pool_data)
            },
        )
        .unwrap()
        .with_inputs(
            [(htlc_input.clone(), htlc_utxo.clone(), Some(secret))],
            &|_| None,
        )
        .unwrap()
        .with_inputs(
            [(multisig_input.clone(), multisig_utxo.clone(), None)],
            &|_| None,
        )
        .unwrap()
        .with_inputs_and_destinations(acc_inputs.into_iter().zip(acc_dests.clone()))
        .with_outputs(outputs);
    let destinations = req.destinations().to_vec();

    let additional_info = TxAdditionalInfo::new()
        .with_token_info(
            token_id,
            TokenAdditionalInfo {
                num_decimals: rng.gen_range(5..10),
                ticker: random_ascii_alphanumeric_string(rng, 5..10).into_bytes(),
            },
        )
        .with_order_info(filled_order1_id, filled_order1_info)
        .with_order_info(filled_order2_id, filled_order2_info)
        .with_order_info(
            concluded_order1_id,
            random_order_info(
                &Currency::Coin,
                &Currency::Token(token_id),
                100,
                200,
                10,
                rng,
            ),
        )
        .with_order_info(
            concluded_order2_id,
            random_order_info(
                &Currency::Token(token_id),
                &Currency::Coin,
                100,
                200,
                10,
                rng,
            ),
        )
        .with_order_info(
            frozen_order_id,
            random_order_info(
                &Currency::Coin,
                &Currency::Token(token_id),
                100,
                200,
                10,
                rng,
            ),
        )
        .with_pool_info(
            decommissioned_pool_id,
            PoolAdditionalInfo {
                staker_balance: decommissioned_pool_balance,
            },
        );
    let orig_ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let mut signer = make_signer(chain_config.clone(), account.account_index());
    let (ptx, _, _) = signer.sign_tx(orig_ptx.clone(), account.key_chain(), &db_tx).unwrap();
    assert!(ptx.all_signatures_available());

    if let Some(make_another_signer) = &make_another_signer {
        let mut another_signer = make_another_signer(chain_config.clone(), account.account_index());
        let (another_ptx, _, _) =
            another_signer.sign_tx(orig_ptx, account.key_chain(), &db_tx).unwrap();
        assert!(another_ptx.all_signatures_available());

        assert_eq!(ptx, another_ptx);
    }

    let input_commitments = ptx
        .make_sighash_input_commitments()
        .unwrap()
        .into_iter()
        .map(|comm| comm.deep_clone())
        .collect_vec();

    let all_utxos = utxos
        .iter()
        .map(Some)
        .chain([Some(&htlc_utxo), Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

    for (i, dest) in destinations.iter().enumerate() {
        // the multisig will not be fully signed
        if dest == &multisig_dest {
            let err = tx_verifier::input_check::signature_only_check::verify_tx_signature(
                &chain_config,
                dest,
                &ptx,
                &input_commitments,
                i,
                all_utxos[i].cloned(),
            )
            .unwrap_err();
            assert_eq!(
                err.error(),
                &InputCheckErrorPayload::Verification(ScriptError::Signature(
                    DestinationSigError::IncompleteClassicalMultisigSignature(
                        min_required_signatures,
                        min_required_signatures - 1
                    )
                )),
            )
        } else {
            tx_verifier::input_check::signature_only_check::verify_tx_signature(
                &chain_config,
                dest,
                &ptx,
                &input_commitments,
                i,
                all_utxos[i].cloned(),
            )
            .unwrap();
        }
    }

    let orig_ptx = ptx;
    // fully sign the remaining key in the multisig address
    let mut signer = make_signer(chain_config.clone(), account2.account_index());
    let (ptx, _, _) = signer.sign_tx(orig_ptx.clone(), account2.key_chain(), &db_tx).unwrap();
    assert!(ptx.all_signatures_available());

    if let Some(make_another_signer) = &make_another_signer {
        let mut another_signer =
            make_another_signer(chain_config.clone(), account2.account_index());
        let (another_ptx, _, _) =
            another_signer.sign_tx(orig_ptx, account2.key_chain(), &db_tx).unwrap();
        assert!(another_ptx.all_signatures_available());

        assert_eq!(ptx, another_ptx);
    }

    for (i, dest) in destinations.iter().enumerate() {
        tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &chain_config,
            dest,
            &ptx,
            &input_commitments,
            i,
            all_utxos[i].cloned(),
        )
        .unwrap();
    }
}

fn random_order_info(
    ask_currency: &Currency,
    give_currency: &Currency,
    min_initial_value: u128,
    max_initial_value: u128,
    min_balance: u128,
    rng: &mut impl Rng,
) -> OrderAdditionalInfo {
    let initially_asked = rng.gen_range(min_initial_value..=max_initial_value);
    let initially_given = rng.gen_range(min_initial_value..=max_initial_value);
    let ask_balance = rng.gen_range(min_balance..=initially_asked);
    let give_balance = rng.gen_range(min_balance..=initially_given);

    OrderAdditionalInfo {
        initially_asked: ask_currency.into_output_value(Amount::from_atoms(initially_asked)),
        initially_given: give_currency.into_output_value(Amount::from_atoms(initially_given)),
        ask_balance: Amount::from_atoms(ask_balance),
        give_balance: Amount::from_atoms(give_balance),
    }
}

fn random_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    let (_sk, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    Destination::PublicKey(pk)
}

fn destination_from_account<K: AccountKeyChains>(
    account: &mut Account<K>,
    db_tx: &mut impl TransactionRwUnlocked,
    rng: &mut impl Rng,
) -> Destination {
    let purpose = if rng.gen_bool(0.5) {
        KeyPurpose::ReceiveFunds
    } else {
        KeyPurpose::Change
    };

    account.get_new_address(db_tx, purpose).unwrap().1.into_object()
}
