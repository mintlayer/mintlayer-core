// Copyright (c) 2024 RBB S.r.l
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

use std::ops::{Add, Div, Mul, Sub};

use super::*;
use crate::key_chain::{MasterKeyChain, LOOKAHEAD_SIZE};
use crate::{Account, SendRequest};
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::config::create_regtest;
use common::chain::htlc::HashedTimelockContract;
use common::chain::output_value::OutputValue;
use common::chain::signature::inputsig::arbitrary_message::produce_message_challenge;
use common::chain::signature::inputsig::authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend;
use common::chain::stakelock::StakePoolData;
use common::chain::timelock::OutputTimeLock;
use common::chain::tokens::{NftIssuance, NftIssuanceV0, TokenId, TokenIssuance};
use common::chain::{
    AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, DelegationId, GenBlock,
    OrderData, OutPointSourceId, PoolId, TxInput,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::{Amount, BlockHeight, Id, H256};
use crypto::key::secp256k1::Secp256k1PublicKey;
use crypto::key::{KeyKind, PublicKey, Signature};
use itertools::izip;
use randomness::{Rng, RngCore};
use rstest::rstest;
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};
use wallet_storage::{DefaultBackend, Store, Transactional};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::partially_signed_transaction::TxAdditionalInfo;
use wallet_types::seed_phrase::StoreSeedPhrase;
use wallet_types::KeyPurpose::{Change, ReceiveFunds};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_message(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(config.clone(), &mut db_tx, key_chain, None).unwrap();

    let destination = account.get_new_address(&mut db_tx, ReceiveFunds).unwrap().1.into_object();
    let mut signer = SoftwareSigner::new(config.clone(), DEFAULT_ACCOUNT_INDEX);
    let message = vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
    let res = signer
        .sign_challenge(&message, &destination, account.key_chain(), &db_tx)
        .unwrap();

    let message_challenge = produce_message_challenge(&message);
    res.verify_signature(&config, &destination, &message_challenge).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_transaction_intent(#[case] seed: Seed) {
    use common::primitives::Idable;

    let mut rng = make_seedable_rng(seed);

    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(config.clone(), &mut db_tx, key_chain, None).unwrap();

    let mut signer = SoftwareSigner::new(config.clone(), DEFAULT_ACCOUNT_INDEX);

    let inputs: Vec<TxInput> = (0..rng.gen_range(1..5))
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(&mut rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(&mut rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();
    let input_destinations: Vec<_> = (0..inputs.len())
        .map(|_| account.get_new_address(&mut db_tx, ReceiveFunds).unwrap().1.into_object())
        .collect();

    let tx = Transaction::new(
        0,
        inputs,
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            account.get_new_address(&mut db_tx, Change).unwrap().1.into_object(),
        )],
    )
    .unwrap();

    let intent: String = [rng.gen::<char>(), rng.gen::<char>(), rng.gen::<char>()].iter().collect();
    let res = signer
        .sign_transaction_intent(
            &tx,
            &input_destinations,
            &intent,
            account.key_chain(),
            &db_tx,
        )
        .unwrap();

    let expected_signed_message =
        SignedTransactionIntent::get_message_to_sign(&intent, &tx.get_id());
    res.verify(&config, &input_destinations, &expected_signed_message).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_transaction(#[case] seed: Seed) {
    use std::num::NonZeroU8;

    use common::{
        chain::{
            classic_multisig::ClassicMultisigChallenge,
            htlc::HashedTimelockContract,
            stakelock::StakePoolData,
            tokens::{
                IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0, TokenId, TokenIssuance,
                TokenIssuanceV1,
            },
            AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, DelegationId,
            OrderData, OrderId, PoolId,
        },
        primitives::amount::UnsignedIntType,
    };
    use crypto::vrf::VRFPrivateKey;
    use itertools::izip;
    use serialization::extras::non_empty_vec::DataOrNoVec;

    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(chain_config.clone(), &mut db_tx, key_chain, None).unwrap();

    let amounts: Vec<Amount> = (0..(2 + rng.next_u32() % 5))
        .map(|_| Amount::from_atoms(rng.gen_range(1..10) as UnsignedIntType))
        .collect();

    let total_amount = amounts.iter().fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());

    let utxos: Vec<TxOutput> = amounts
        .iter()
        .map(|a| {
            let purpose = if rng.gen_bool(0.5) {
                ReceiveFunds
            } else {
                Change
            };

            TxOutput::Transfer(
                OutputValue::Coin(*a),
                account.get_new_address(&mut db_tx, purpose).unwrap().1.into_object(),
            )
        })
        .collect();

    let inputs: Vec<TxInput> = (0..utxos.len())
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(&mut rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(&mut rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();

    let (_dest_prv, pub_key1) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let pub_key2 = if let Destination::PublicKeyHash(pkh) =
        account.get_new_address(&mut db_tx, Change).unwrap().1.into_object()
    {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };
    let pub_key3 = if let Destination::PublicKeyHash(pkh) =
        account.get_new_address(&mut db_tx, Change).unwrap().1.into_object()
    {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };
    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![pub_key1.clone(), pub_key2.clone(), pub_key3],
    )
    .unwrap();
    let multisig_hash = account.add_standalone_multisig(&mut db_tx, challenge, None).unwrap();

    let multisig_dest = Destination::ClassicMultisig(multisig_hash);

    let source_id: OutPointSourceId = if rng.gen_bool(0.5) {
        Id::<Transaction>::new(H256::random_using(&mut rng)).into()
    } else {
        Id::<GenBlock>::new(H256::random_using(&mut rng)).into()
    };
    let multisig_input = TxInput::from_utxo(source_id.clone(), rng.next_u32());
    let multisig_utxo = TxOutput::Transfer(OutputValue::Coin(Amount::from_atoms(1)), multisig_dest);

    let secret = HtlcSecret::new_from_rng(&mut rng);
    let hash_lock = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: Destination::PublicKey(pub_key2.clone()),
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(0)),
        refund_key: Destination::PublicKey(pub_key1),
    };

    let htlc_input = TxInput::from_utxo(source_id, rng.next_u32());
    let htlc_utxo = TxOutput::Htlc(
        OutputValue::Coin(Amount::from_atoms(rng.gen::<u32>() as u128)),
        Box::new(hash_lock.clone()),
    );

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(
                DelegationId::new(H256::random_using(&mut rng)),
                Amount::from_atoms(rng.next_u32() as u128),
            ),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::MintTokens(
                TokenId::new(H256::random_using(&mut rng)),
                Amount::from_atoms(100),
            ),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnmintTokens(TokenId::new(H256::random_using(&mut rng))),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::LockTokenSupply(TokenId::new(H256::random_using(&mut rng))),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::FreezeToken(
                TokenId::new(H256::random_using(&mut rng)),
                IsTokenUnfreezable::Yes,
            ),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnfreezeToken(TokenId::new(H256::random_using(&mut rng))),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ChangeTokenAuthority(
                TokenId::new(H256::random_using(&mut rng)),
                Destination::AnyoneCanSpend,
            ),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ConcludeOrder(OrderId::new(H256::random_using(&mut rng))),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::FillOrder(
                OrderId::new(H256::random_using(&mut rng)),
                Amount::from_atoms(123),
                Destination::AnyoneCanSpend,
            ),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ChangeTokenMetadataUri(
                TokenId::new(H256::random_using(&mut rng)),
                "http://uri".as_bytes().to_vec(),
            ),
        ),
    ];
    let acc_dests: Vec<Destination> = acc_inputs
        .iter()
        .map(|_| {
            let purpose = if rng.gen_bool(0.5) {
                ReceiveFunds
            } else {
                Change
            };

            account.get_new_address(&mut db_tx, purpose).unwrap().1.into_object()
        })
        .collect();

    let dest_amount = total_amount.div(10).unwrap().mul(5).unwrap();
    let lock_amount = total_amount.div(10).unwrap().mul(1).unwrap();
    let burn_amount = total_amount.div(10).unwrap().mul(1).unwrap();
    let change_amount = total_amount.div(10).unwrap().mul(2).unwrap();
    let outputs_amounts_sum = [dest_amount, lock_amount, burn_amount, change_amount]
        .iter()
        .fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());
    let _fee_amount = total_amount.sub(outputs_amounts_sum).unwrap();

    let (_dest_prv, dest_pub) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (_, vrf_public_key) = VRFPrivateKey::new_from_entropy(crypto::vrf::VRFKeyKind::Schnorrkel);

    let pool_id = PoolId::new(H256::random());
    let delegation_id = DelegationId::new(H256::random());
    let pool_data = StakePoolData::new(
        Amount::from_atoms(5000000),
        Destination::PublicKey(dest_pub.clone()),
        vrf_public_key,
        Destination::PublicKey(dest_pub.clone()),
        PerThousand::new_from_rng(&mut rng),
        Amount::from_atoms(100),
    );
    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: "http://uri".as_bytes().to_vec(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: Destination::PublicKey(dest_pub.clone()),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    });

    let nft_issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: "Name".as_bytes().to_vec(),
            description: "SomeNFT".as_bytes().to_vec(),
            ticker: "NFTX".as_bytes().to_vec(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(None),
            media_hash: "123456".as_bytes().to_vec(),
        },
    });
    let nft_id = TokenId::new(H256::random());

    let order_data = OrderData::new(
        Destination::PublicKey(dest_pub.clone()),
        OutputValue::Coin(Amount::from_atoms(100)),
        OutputValue::Coin(total_amount),
    );

    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::Coin(dest_amount),
            Destination::PublicKey(dest_pub),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(lock_amount),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(rng.next_u64()),
        ),
        TxOutput::Burn(OutputValue::Coin(burn_amount)),
        TxOutput::CreateStakePool(pool_id, Box::new(pool_data)),
        TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            PoolId::new(H256::random_using(&mut rng)),
        ),
        TxOutput::DelegateStaking(burn_amount, delegation_id),
        TxOutput::IssueFungibleToken(Box::new(token_issuance)),
        TxOutput::IssueNft(
            nft_id,
            Box::new(nft_issuance.clone()),
            Destination::AnyoneCanSpend,
        ),
        TxOutput::DataDeposit(vec![1, 2, 3]),
        TxOutput::Htlc(OutputValue::Coin(burn_amount), Box::new(hash_lock)),
        TxOutput::CreateOrder(Box::new(order_data)),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100_000_000_000)),
            account.get_new_address(&mut db_tx, Change).unwrap().1.into_object(),
        ),
    ];

    let req = SendRequest::new()
        .with_inputs(
            izip!(inputs.clone(), utxos.clone(), vec![None; inputs.len()]),
            &|_| None,
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
    let additional_info = TxAdditionalInfo::new();
    let ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let mut signer = SoftwareSigner::new(chain_config.clone(), DEFAULT_ACCOUNT_INDEX);
    let (ptx, _, _) = signer.sign_tx(ptx, account.key_chain(), &db_tx).unwrap();

    eprintln!("num inputs in tx: {} {:?}", inputs.len(), ptx.witnesses());
    for (i, w) in ptx.witnesses().iter().enumerate() {
        eprintln!("W: {i} {w:?}");
    }
    assert!(ptx.all_signatures_available());

    let utxos_ref = utxos
        .iter()
        .map(Some)
        .chain([Some(&htlc_utxo), Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

    for (i, dest) in destinations.iter().enumerate() {
        tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &chain_config,
            dest,
            &ptx,
            &utxos_ref,
            i,
        )
        .unwrap();
    }
}

#[test]
fn fixed_signatures() {
    use std::num::NonZeroU8;

    use common::chain::{
        classic_multisig::ClassicMultisigChallenge,
        tokens::{IsTokenUnfreezable, Metadata, TokenIssuanceV1},
        OrderId,
    };
    use crypto::vrf::VRFPrivateKey;
    use serialization::extras::non_empty_vec::DataOrNoVec;

    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(chain_config.clone(), &mut db_tx, key_chain, None).unwrap();

    let amount_1 = Amount::from_atoms(1);
    let random_pk = PublicKey::from(
        Secp256k1PublicKey::from_bytes(&[
            2, 2, 11, 98, 44, 24, 95, 8, 36, 172, 134, 193, 94, 60, 66, 115, 65, 190, 73, 45, 12,
            228, 65, 185, 175, 158, 4, 233, 125, 192, 84, 52, 242,
        ])
        .unwrap(),
    );

    eprintln!("getting first address");
    let (num, addr) = account.get_new_address(&mut db_tx, ReceiveFunds).unwrap();
    eprintln!("num: {num:?}");

    let wallet_pk0 = if let Destination::PublicKeyHash(pkh) = addr.into_object() {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };

    let wallet_pk1 = if let Destination::PublicKeyHash(pkh) =
        account.get_new_address(&mut db_tx, ReceiveFunds).unwrap().1.into_object()
    {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };
    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![wallet_pk0.clone(), random_pk, wallet_pk1],
    )
    .unwrap();
    let multisig_hash =
        account.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();

    let multisig_dest = Destination::ClassicMultisig(multisig_hash);

    let multisig_input = TxInput::from_utxo(Id::<Transaction>::new(H256::zero()).into(), 2);
    let multisig_utxo = TxOutput::Transfer(OutputValue::Coin(amount_1), multisig_dest);

    let delegation_id = DelegationId::new(H256::zero());
    let token_id = TokenId::new(H256::zero());
    let order_id = OrderId::new(H256::zero());
    let pool_id = PoolId::new(H256::zero());

    let uri = "http://uri.com".as_bytes().to_vec();

    let wallet_dest0 = Destination::PublicKeyHash((&wallet_pk0).into());

    let utxos = [TxOutput::Transfer(OutputValue::Coin(amount_1), wallet_dest0.clone())];

    let inputs = [TxInput::from_utxo(
        OutPointSourceId::Transaction(Id::<Transaction>::new(H256::zero())),
        1,
    )];

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(delegation_id, amount_1),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::MintTokens(token_id, amount_1),
        ),
        TxInput::AccountCommand(AccountNonce::new(0), AccountCommand::UnmintTokens(token_id)),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::LockTokenSupply(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::UnfreezeToken(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenAuthority(token_id, Destination::AnyoneCanSpend),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ConcludeOrder(order_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::FillOrder(order_id, amount_1, Destination::AnyoneCanSpend),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenMetadataUri(token_id, uri.clone()),
        ),
    ];
    let acc_dests: Vec<Destination> = vec![wallet_dest0.clone(); acc_inputs.len()];

    let (_, vrf_public_key) =
        VRFPrivateKey::new_using_random_bytes(&[0; 32], crypto::vrf::VRFKeyKind::Schnorrkel)
            .unwrap();

    let pool_data = StakePoolData::new(
        amount_1,
        Destination::AnyoneCanSpend,
        vrf_public_key,
        Destination::AnyoneCanSpend,
        PerThousand::new(1).unwrap(),
        amount_1,
    );
    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: 2,
        metadata_uri: uri.clone(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: Destination::AnyoneCanSpend,
        is_freezable: common::chain::tokens::IsTokenFreezable::Yes,
    });

    let nft_issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: "Name".as_bytes().to_vec(),
            description: "SomeNFT".as_bytes().to_vec(),
            ticker: "NFTX".as_bytes().to_vec(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: Some(uri).into(),
            media_hash: "123456".as_bytes().to_vec(),
        },
    });
    let hash_lock = HashedTimelockContract {
        secret_hash: common::chain::htlc::HtlcSecretHash([1; 20]),
        spend_key: Destination::AnyoneCanSpend,
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(10)),
        refund_key: Destination::AnyoneCanSpend,
    };

    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::Coin(amount_1),
        OutputValue::Coin(amount_1),
    );

    let outputs = vec![
        TxOutput::Transfer(OutputValue::Coin(amount_1), Destination::AnyoneCanSpend),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::UntilHeight(BlockHeight::new(10)),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(10)),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(10),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(10),
        ),
        TxOutput::Burn(OutputValue::Coin(amount_1)),
        TxOutput::CreateStakePool(pool_id, Box::new(pool_data)),
        TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, pool_id),
        TxOutput::DelegateStaking(amount_1, delegation_id),
        TxOutput::IssueFungibleToken(Box::new(token_issuance)),
        TxOutput::IssueNft(
            token_id,
            Box::new(nft_issuance.clone()),
            Destination::AnyoneCanSpend,
        ),
        TxOutput::DataDeposit(vec![1, 2, 3]),
        TxOutput::Htlc(OutputValue::Coin(amount_1), Box::new(hash_lock)),
        TxOutput::CreateOrder(Box::new(order_data)),
    ];

    let req = SendRequest::new()
        .with_inputs(
            izip!(inputs.clone(), utxos.clone(), vec![None; inputs.len()]),
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
    let additional_info = TxAdditionalInfo::new();
    let ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let utxos_ref = utxos
        .iter()
        .map(Some)
        .chain([Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

    let multisig_signatures = [
        (0, "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59"),
        (2, "0a0a17d71bc98fa5c24ea611c856d0d08c6a765ea3c4c8f068668e0bdff710b82b0d2eead83d059386cd3cbdf4308418d4b81e6f52c001a9141ec477a8d24845"),
    ];

    let mut current_signatures = AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());

    for (idx, sig) in multisig_signatures {
        let mut signature = hex::decode(sig).unwrap();
        signature.insert(0, 0);
        let sig = Signature::from_data(signature).unwrap();
        current_signatures.add_signature(idx as u8, sig);
    }

    let sighash_type: SigHashType = SigHashType::ALL.try_into().unwrap();
    let multisig_sig = StandardInputSignature::new(sighash_type, current_signatures.encode());

    let sig = "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59";
    let mut bytes = hex::decode(sig).unwrap();
    bytes.insert(0, 0);

    let sig = Signature::from_data(bytes).unwrap();
    let sig = AuthorizedPublicKeyHashSpend::new(wallet_pk0.clone(), sig);
    let sig = StandardInputSignature::new(SigHashType::ALL.try_into().unwrap(), sig.encode());

    let mut sigs = vec![Some(InputWitness::Standard(sig)); ptx.count_inputs()];
    sigs[1] = Some(InputWitness::Standard(multisig_sig));
    let ptx = ptx.with_witnesses(sigs);

    assert!(ptx.all_signatures_available());

    for (i, dest) in destinations.iter().enumerate() {
        tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &chain_config,
            dest,
            &ptx,
            &utxos_ref,
            i,
        )
        .unwrap();
    }
}
