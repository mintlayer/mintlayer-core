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

use std::{num::NonZeroU8, sync::Arc};

use itertools::{izip, Itertools as _};

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        config::create_regtest,
        htlc::{HashedTimelockContract, HtlcSecret},
        output_value::OutputValue,
        signature::{
            inputsig::{
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
                authorize_pubkey_spend::AuthorizedPublicKeySpend,
                authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
                classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::sighashtype::SigHashType,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0, TokenId, TokenIssuance,
            TokenIssuanceV1,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, ChainConfig, DelegationId,
        Destination, OrderAccountCommand, OrderData, OrderId, OutPointSourceId, PoolId,
        Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::hash_encoded, per_thousand::PerThousand, Amount, BlockHeight, Id, H256},
};
use crypto::{
    key::{
        hdkd::u31::U31,
        secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
        signature::SignatureKind,
        PrivateKey, PublicKey, Signature,
    },
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use logging::log;
use randomness::{CryptoRng, Rng};
use serialization::{extras::non_empty_vec::DataOrNoVec, Encode as _};
use test_utils::{assert_matches_return_val, random_ascii_alphanumeric_string};
use wallet_storage::{DefaultBackend, Store, TransactionRwUnlocked, Transactional};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    partially_signed_transaction::{
        OrderAdditionalInfo, PoolAdditionalInfo, TokenAdditionalInfo, TxAdditionalInfo,
    },
    seed_phrase::StoreSeedPhrase,
    BlockInfo, KeyPurpose,
};

use crate::{
    account::PoolData,
    key_chain::{AccountKeyChains, MasterKeyChain, LOOKAHEAD_SIZE},
    signer::{
        tests::{account_from_mnemonic, MNEMONIC},
        Signer,
    },
    Account, SendRequest,
};

lazy_static::lazy_static! {
    // Some hardcoded public keys for the cases when the private ones are not needed.
    pub static ref SOME_PUB_KEY_1: PublicKey = {
        PublicKey::from(
            Secp256k1PublicKey::from_bytes(
                &hex::decode("02020b622c185f0824ac86c15e3c427341be492d0ce441b9af9e04e97dc05434f2").unwrap()
            ).unwrap()
        )
    };
    pub static ref SOME_PUB_KEY_2: PublicKey = {
        PublicKey::from(
            Secp256k1PublicKey::from_bytes(
                &hex::decode("036662bff6d4d1195f544a385e71ee3b31639c0ecba679f3ce43d9411f7ede13d0").unwrap()
            ).unwrap()
        )
    };
    pub static ref SOME_PUB_KEY_3: PublicKey = {
        PublicKey::from(
            Secp256k1PublicKey::from_bytes(
                &hex::decode("02635e0c3edb17551189fad3ee139b9255fe64353dfb0aa359ca83d57b4b41146c").unwrap()
            ).unwrap()
        )
    };

    // A pair of keys
    pub static ref PUB_KEY_A: PublicKey = {
        PublicKey::from(
            Secp256k1PublicKey::from_bytes(
                &hex::decode("036662bff6d4d1195f544a385e71ee3b31639c0ecba679f3ce43d9411f7ede13d0").unwrap()
            ).unwrap()
        )
    };
    pub static ref PRV_KEY_A: PrivateKey = {
        PrivateKey::from(
            Secp256k1PrivateKey::from_bytes(
                &hex::decode("c00f8401696a5bdc34f5a6d2ff3f922f58a28c18576b71e5e61c32867855a03c").unwrap()
            ).unwrap()
        )
    };
}

pub fn test_fixed_signatures_generic<MkS, S>(rng: &mut (impl Rng + CryptoRng), make_signer: MkS)
where
    MkS: Fn(Arc<ChainConfig>, U31) -> S,
    S: Signer,
{
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

    let wallet_pk0 = new_pub_key_from_account(&mut account, &mut db_tx, KeyPurpose::ReceiveFunds);
    let wallet_pk1 = new_pub_key_from_account(&mut account, &mut db_tx, KeyPurpose::ReceiveFunds);

    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![wallet_pk0.clone(), SOME_PUB_KEY_1.clone(), wallet_pk1],
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
    let additional_info = TxAdditionalInfo::new()
        .with_token_info(
            token_id,
            // Note: this info doesn't influence the signature and can be random.
            TokenAdditionalInfo {
                num_decimals: rng.gen_range(1..10),
                ticker: random_ascii_alphanumeric_string(rng, 5..10).into_bytes(),
            },
        )
        .with_order_info(
            order_id,
            OrderAdditionalInfo {
                ask_balance: Amount::from_atoms(10),
                give_balance: Amount::from_atoms(100),
                initially_asked: OutputValue::Coin(Amount::from_atoms(20)),
                // Note: initially_given's amount isn't used by the signers in orders v0, only its
                // currency matters.
                initially_given: OutputValue::TokenV1(
                    token_id,
                    Amount::from_atoms(rng.gen_range(100..200)),
                ),
            },
        );
    let orig_ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let mut signer = make_signer(chain_config.clone(), account.account_index());
    let (ptx, _, _) = signer.sign_tx(orig_ptx, account.key_chain(), &db_tx).unwrap();
    assert!(ptx.all_signatures_available());

    let input_commitments = ptx.make_sighash_input_commitments().unwrap();
    let all_utxos = utxos
        .iter()
        .map(Some)
        .chain([Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

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

    let expected_sigs = {
        let multisig = {
            let sigs_hex = [
                (0, "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59"),
                (2, "0a0a17d71bc98fa5c24ea611c856d0d08c6a765ea3c4c8f068668e0bdff710b82b0d2eead83d059386cd3cbdf4308418d4b81e6f52c001a9141ec477a8d24845"),
            ];
            make_multisig_spend_sig(challenge, sigs_hex)
        };

        let sig = "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59";
        let sig = make_pub_key_hash_spend_sig(wallet_pk0.clone(), sig);

        let mut sigs = vec![Some(InputWitness::Standard(sig)); ptx.count_inputs()];
        sigs[1] = Some(InputWitness::Standard(multisig));
        sigs
    };

    assert_eq!(ptx.witnesses(), &expected_sigs);
}

/// Another fixed signature test. The main difference from test_fixed_signatures_generic is that
/// we also test:
/// 1) ProduceBlockFromState input;
/// 2) v1 order inputs;
/// 3) htlc inputs.
pub fn test_fixed_signatures_generic2<MkS, S>(rng: &mut (impl Rng + CryptoRng), make_signer: MkS)
where
    MkS: Fn(Arc<ChainConfig>, U31) -> S,
    S: Signer,
{
    let chain_config = Arc::new(create_regtest());

    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account1 = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);
    let mut account2 = account_from_mnemonic(&chain_config, &mut db_tx, U31::ONE);

    account1
        .add_standalone_private_key(&mut db_tx, PRV_KEY_A.clone(), None)
        .unwrap();
    let standalone_pk = PUB_KEY_A.clone();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk.clone());

    let decommissioned_pool_id = PoolId::new(hash_encoded(&"some pool 1"));
    let created_pool_id = PoolId::new(hash_encoded(&"some pool 2"));
    let another_pool_id = PoolId::new(hash_encoded(&"some pool 3"));

    let nft_id = TokenId::new(hash_encoded(&"some nft"));
    let token_id = TokenId::new(hash_encoded(&"some token 1"));
    let another_token_id_1 = TokenId::new(hash_encoded(&"some token 2"));
    let another_token_id_2 = TokenId::new(hash_encoded(&"some token 3"));

    let decommissioned_pool_balance = Amount::from_atoms(100);
    let decommission_dest =
        new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::ReceiveFunds);
    let decommissioned_pool_data = PoolData {
        utxo_outpoint: UtxoOutPoint::new(
            Id::<Transaction>::new(hash_encoded(&"some tx")).into(),
            1,
        ),
        creation_block: BlockInfo {
            height: BlockHeight::new(123),
            timestamp: BlockTimestamp::from_int_seconds(234),
        },
        decommission_key: decommission_dest.clone(),
        stake_destination: bogus_destination("bogus destination 1"),
        vrf_public_key: bogus_vrf_pub_key("bogus vrf key 1"),
        margin_ratio_per_thousand: PerThousand::new(11).unwrap(),
        cost_per_block: Amount::from_atoms(111),
    };

    let account1_dest1 = new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::Change);
    let account1_pk1 = find_pub_key_for_pkh_dest(&account1_dest1, &account1).clone();
    let account1_dest2 = new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::Change);
    let account1_pk2 = find_pub_key_for_pkh_dest(&account1_dest2, &account1).clone();
    let account1_dest3 = new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::Change);
    let account1_pk3 = find_pub_key_for_pkh_dest(&account1_dest3, &account1).clone();
    let account1_dest4 = new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::Change);

    let account2_dest1 = new_dest_from_account(&mut account2, &mut db_tx, KeyPurpose::Change);
    let account2_pk1 = find_pub_key_for_pkh_dest(&account2_dest1, &account2).clone();
    let account2_dest2 = new_dest_from_account(&mut account2, &mut db_tx, KeyPurpose::Change);
    let account2_pk2 = find_pub_key_for_pkh_dest(&account2_dest2, &account2).clone();

    let utxos = vec![
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000)),
            account1_dest4.clone(),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(2000)),
            standalone_pk_destination.clone(),
        ),
        TxOutput::ProduceBlockFromStake(
            bogus_destination("bogus destination 2"),
            decommissioned_pool_id,
        ),
    ];

    let inputs: Vec<TxInput> = (0..utxos.len())
        .map(|i| {
            let source_id = Id::<Transaction>::new(hash_encoded(&format!("input tx {i}"))).into();
            TxInput::from_utxo(source_id, i as u32)
        })
        .collect();

    let (multisig_dest, multisig_challenge) = {
        let challenge = ClassicMultisigChallenge::new(
            &chain_config,
            NonZeroU8::new(3).unwrap(),
            vec![SOME_PUB_KEY_1.clone(), account1_pk1, standalone_pk, account2_pk1],
        )
        .unwrap();
        let multisig_hash1 =
            account1.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();
        let multisig_hash2 =
            account2.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();
        assert_eq!(multisig_hash1, multisig_hash2);

        (Destination::ClassicMultisig(multisig_hash1), challenge)
    };

    let source_id: OutPointSourceId =
        Id::<Transaction>::new(hash_encoded(&"another input tx")).into();
    let multisig_input = TxInput::from_utxo(source_id.clone(), 1);
    let multisig_utxo = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(150)),
        multisig_dest.clone(),
    );

    let htlc_secret = HtlcSecret::new(hash_encoded(&"secret").to_fixed_bytes());
    let (htlc_multisig_dest, htlc_multisig_challenge) = {
        let challenge = ClassicMultisigChallenge::new(
            &chain_config,
            NonZeroU8::new(2).unwrap(),
            vec![account1_pk2, account2_pk2],
        )
        .unwrap();
        let multisig_hash2 =
            account1.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();
        let multisig_hash1 =
            account2.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();
        assert_eq!(multisig_hash1, multisig_hash2);

        (Destination::ClassicMultisig(multisig_hash1), challenge)
    };
    let htlc1 = HashedTimelockContract {
        secret_hash: htlc_secret.hash(),
        spend_key: Destination::PublicKey(account1_pk3),
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(111)),
        refund_key: Destination::PublicKey(SOME_PUB_KEY_2.clone()),
    };
    let htlc2 = HashedTimelockContract {
        secret_hash: htlc_secret.hash(),
        spend_key: Destination::PublicKey(SOME_PUB_KEY_2.clone()),
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(222)),
        refund_key: htlc_multisig_dest.clone(),
    };
    let htlc_in_output = HashedTimelockContract {
        secret_hash: htlc_secret.hash(),
        spend_key: Destination::PublicKey(SOME_PUB_KEY_1.clone()),
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(333)),
        refund_key: Destination::PublicKey(SOME_PUB_KEY_2.clone()),
    };
    let htlc1_input = TxInput::from_utxo(source_id.clone(), 2);
    let htlc2_input = TxInput::from_utxo(source_id, 3);
    let htlc1_utxo = TxOutput::Htlc(
        OutputValue::Coin(Amount::from_atoms(300)),
        Box::new(htlc1.clone()),
    );
    let htlc2_utxo = TxOutput::Htlc(
        OutputValue::Coin(Amount::from_atoms(400)),
        Box::new(htlc2.clone()),
    );

    let token_mint_amount = Amount::from_atoms(1000);

    let coin_transfer_amount = Amount::from_atoms(100);
    let coin_lock_then_transfer_amount = Amount::from_atoms(110);
    let coin_burn_amount = Amount::from_atoms(120);
    let delegate_staking_amount = Amount::from_atoms(130);
    let htlc_transfer_amount = Amount::from_atoms(140);

    let filled_order_v0_id = OrderId::new(hash_encoded(&"some order 1"));
    let filled_order_v1_id = OrderId::new(hash_encoded(&"some order 2"));
    let concluded_order_v0_id = OrderId::new(hash_encoded(&"some order 3"));
    let concluded_order_v1_id = OrderId::new(hash_encoded(&"some order 4"));
    let frozen_order_id = OrderId::new(hash_encoded(&"some order 5"));

    let filled_order_v0_info = OrderAdditionalInfo {
        // Note: the amounts in initially_asked and initially_given aren't used by the signers when handling
        // v0 FillOrder, only the currencies matter.
        initially_asked: OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..200))),
        initially_given: OutputValue::TokenV1(
            token_id,
            Amount::from_atoms(rng.gen_range(100..200)),
        ),
        ask_balance: Amount::from_atoms(50),
        give_balance: Amount::from_atoms(100),
    };
    let filled_order_v1_info = OrderAdditionalInfo {
        initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(300)),
        initially_given: OutputValue::Coin(Amount::from_atoms(150)),
        // Note: ask_balance/give_balance aren't used by the signers when handling v1 FillOrder.
        ask_balance: Amount::from_atoms(rng.gen_range(100..200)),
        give_balance: Amount::from_atoms(rng.gen_range(100..200)),
    };
    let concluded_order_v0_info = OrderAdditionalInfo {
        initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(110)),
        // Note: the amount in initially_given isn't used by the signers when handling ConcludeOrder
        // (both v0 and v1), only the currency matters.
        initially_given: OutputValue::TokenV1(
            token_id,
            Amount::from_atoms(rng.gen_range(100..200)),
        ),
        ask_balance: Amount::from_atoms(55),
        give_balance: Amount::from_atoms(110),
    };
    let concluded_order_v1_info = OrderAdditionalInfo {
        initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(330)),
        // Note: the amount in initially_given isn't used by the signers when handling ConcludeOrder
        // (both v0 and v1), only the currency matters.
        initially_given: OutputValue::TokenV1(
            token_id,
            Amount::from_atoms(rng.gen_range(100..200)),
        ),
        ask_balance: Amount::from_atoms(110),
        give_balance: Amount::from_atoms(55),
    };
    let frozen_order_info = OrderAdditionalInfo {
        // Note: the amounts aren't used by the signers when handling FreezeOrder.
        initially_asked: OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..200))),
        initially_given: OutputValue::TokenV1(
            token_id,
            Amount::from_atoms(rng.gen_range(100..200)),
        ),
        ask_balance: Amount::from_atoms(rng.gen_range(100..200)),
        give_balance: Amount::from_atoms(rng.gen_range(100..200)),
    };

    let delegation_id1 = DelegationId::new(hash_encoded(&"some delegation 1"));
    let delegation_id2 = DelegationId::new(hash_encoded(&"some delegation 2"));

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(delegation_id1, Amount::from_atoms(100)),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(1),
            AccountCommand::MintTokens(token_id, token_mint_amount),
        ),
        TxInput::AccountCommand(AccountNonce::new(2), AccountCommand::UnmintTokens(token_id)),
        TxInput::AccountCommand(
            AccountNonce::new(3),
            AccountCommand::LockTokenSupply(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(4),
            AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(5),
            AccountCommand::UnfreezeToken(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(6),
            AccountCommand::ChangeTokenAuthority(another_token_id_1, Destination::AnyoneCanSpend),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(9),
            AccountCommand::ChangeTokenMetadataUri(another_token_id_2, "111".as_bytes().to_owned()),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(7),
            AccountCommand::ConcludeOrder(concluded_order_v0_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(8),
            AccountCommand::FillOrder(
                filled_order_v0_id,
                Amount::from_atoms(50),
                Destination::AnyoneCanSpend,
            ),
        ),
        TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(concluded_order_v1_id)),
        TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(frozen_order_id)),
        TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
            filled_order_v1_id,
            Amount::from_atoms(100),
            Destination::AnyoneCanSpend,
        )),
    ];
    let acc_dests: Vec<Destination> = acc_inputs
        .iter()
        .map(|_| new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::ReceiveFunds))
        .collect();

    let pool_data = StakePoolData::new(
        Amount::from_atoms(1000),
        bogus_destination("bogus destination 3"),
        bogus_vrf_pub_key("bogus vrf key 2"),
        bogus_destination("bogus destination 4"),
        PerThousand::new(22).unwrap(),
        Amount::from_atoms(10),
    );
    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: "222".as_bytes().to_owned(),
        number_of_decimals: 5,
        metadata_uri: "333".as_bytes().to_owned(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: bogus_destination("bogus destination 5"),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    });

    let nft_issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: "abc".as_bytes().to_owned(),
            description: "asd".as_bytes().to_owned(),
            ticker: "qwe".as_bytes().to_owned(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(None),
            media_hash: "1234".as_bytes().to_owned(),
        },
    });

    let created_order_data = OrderData::new(
        bogus_destination("bogus destination 6"),
        OutputValue::Coin(Amount::from_atoms(123)),
        OutputValue::TokenV1(token_id, Amount::from_atoms(234)),
    );

    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(100)),
            bogus_destination("bogus destination 7"),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(coin_transfer_amount),
            bogus_destination("bogus destination 8"),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(coin_lock_then_transfer_amount),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(111),
        ),
        TxOutput::Burn(OutputValue::Coin(coin_burn_amount)),
        TxOutput::CreateStakePool(created_pool_id, Box::new(pool_data)),
        TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, another_pool_id),
        TxOutput::DelegateStaking(delegate_staking_amount, delegation_id2),
        TxOutput::IssueFungibleToken(Box::new(token_issuance)),
        TxOutput::IssueNft(
            nft_id,
            Box::new(nft_issuance.clone()),
            Destination::AnyoneCanSpend,
        ),
        TxOutput::DataDeposit(vec![1, 2, 3]),
        TxOutput::Htlc(
            OutputValue::Coin(htlc_transfer_amount),
            Box::new(htlc_in_output),
        ),
        TxOutput::CreateOrder(Box::new(created_order_data)),
    ];

    let req = SendRequest::new()
        .with_inputs(
            izip!(
                inputs.iter().cloned(),
                utxos.iter().cloned(),
                std::iter::repeat(None)
            ),
            &|pool_id| {
                assert_eq!(*pool_id, decommissioned_pool_id);
                Some(&decommissioned_pool_data)
            },
        )
        .unwrap()
        .with_inputs(
            [
                (
                    htlc1_input.clone(),
                    htlc1_utxo.clone(),
                    Some(htlc_secret.clone()),
                ),
                (htlc2_input.clone(), htlc2_utxo.clone(), None),
                (multisig_input.clone(), multisig_utxo.clone(), None),
            ],
            &|_| None,
        )
        .unwrap()
        .with_inputs_and_destinations(acc_inputs.into_iter().zip(acc_dests.clone()))
        .with_outputs(outputs);
    let destinations = req.destinations().to_vec();
    let all_utxos = utxos
        .iter()
        .map(Some)
        .chain([Some(&htlc1_utxo), Some(&htlc2_utxo), Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

    let additional_info = TxAdditionalInfo::new()
        .with_token_info(
            token_id,
            // Note: token info doesn't influence the signature and can be random.
            TokenAdditionalInfo {
                num_decimals: rng.gen_range(1..10),
                ticker: random_ascii_alphanumeric_string(rng, 5..10).into_bytes(),
            },
        )
        .with_order_info(filled_order_v0_id, filled_order_v0_info)
        .with_order_info(filled_order_v1_id, filled_order_v1_info)
        .with_order_info(concluded_order_v0_id, concluded_order_v0_info)
        .with_order_info(concluded_order_v1_id, concluded_order_v1_info)
        .with_order_info(frozen_order_id, frozen_order_info)
        .with_pool_info(
            decommissioned_pool_id,
            PoolAdditionalInfo {
                staker_balance: decommissioned_pool_balance,
            },
        );
    let ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let input_commitments = ptx
        .make_sighash_input_commitments()
        .unwrap()
        .into_iter()
        .map(|comm| comm.deep_clone())
        .collect_vec();

    let mut signer = make_signer(chain_config.clone(), account1.account_index());
    let (ptx, _, _) = signer.sign_tx(ptx, account1.key_chain(), &db_tx).unwrap();
    assert!(ptx.all_signatures_available());

    // Fully sign multisig inputs.
    let mut signer = make_signer(chain_config.clone(), account2.account_index());
    let (ptx, _, _) = signer.sign_tx(ptx, account2.key_chain(), &db_tx).unwrap();
    assert!(ptx.all_signatures_available());

    for (i, dest) in destinations.iter().enumerate() {
        let raw_sig = assert_matches_return_val!(
            ptx.witnesses()[i].as_ref().unwrap(),
            InputWitness::Standard(sig),
            sig.raw_signature()
        );

        log_signature(i, raw_sig);

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

    let expected_sigs = {
        let htlc_multisig = {
            let sigs_hex = [
                (0, "32eaee75673ebe681c3d8a44e9ae7310f93f99c5021cb5746f64d26d12e22b59a8517943f828c9bff06521bd0a421552f320aae1bd04bbc731629c350289d5eb"),
                (1, "43786e4d3def2f1f1dd5e1afa9489f6e79c7eb4b0dbc09456c9e75f6dac7f2313c18663895ecc3b76141cc58b3e3eab3e927cf43b56c75d6313ca5c8ff6626c2"),
            ];
            make_htlc_multisig_spend_sig(htlc_multisig_challenge, sigs_hex)
        };
        let multisig = {
            let sigs_hex = [
                (1, "8f15883ae42988b3e1e4d68183a92f9a7102e2f2abf4b17474881eb2630f87dfc5f050dea079440a14be325211195cf58dc3681e7c5665892d433daa9ea935ff"),
                (2, "bc8e6694b066f64003ad92f894ee560de9f51aa8253a8e336188db7fd36fa992923bf948490144c7b74533d56efa699db547fd5605aaf8eeb8a5cbda02d5c8c8"),
                (3, "3945b0d96a08b0bb6994d3d722d8359f34761a4407fc6f2dd03734a8065a3ba246deea95fa78411ef23c2d05f0efcefb1984f9e2c38c9e11b6dff410cb72eb80")
            ];
            make_multisig_spend_sig(multisig_challenge, sigs_hex)
        };

        vec![
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&account1_dest4, &account1),
                "aa01ee31f91af118a2ceebb3995dbf5d8755f557b11fa5a68af9aa7da3998a1ee4ed41ea4f67c3658d51fbcbe7b24b65b8a99648d1dc20a3035541cd45e66a59",
            ))),
            Some(InputWitness::Standard(make_pub_key_spend_sig(
                "bc8e6694b066f64003ad92f894ee560de9f51aa8253a8e336188db7fd36fa992923bf948490144c7b74533d56efa699db547fd5605aaf8eeb8a5cbda02d5c8c8",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&decommission_dest, &account1),
                "ee4b5a0febe45ebe8ce4ece0387111f7d53bb8acf7ce1635fcc13c41f6ff6b632ea434e8031781e53731839c782f33e87e06599a9e37d0f3aed63964635c1018",
            ))),
            Some(InputWitness::Standard(make_htlc_secret_spend_sig(
                htlc_secret,
                "0094a8bde764e97d9534d08c22cf8aa762e44338830ea058604d89b76c33c9b6dc8fd7f1f2e2d818841c10d47e8d504b9fc251a1d2ddb13eaeb7c045ea03727d8f",
            ))),
            Some(InputWitness::Standard(htlc_multisig)),
            Some(InputWitness::Standard(multisig)),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[0], &account1),
                "5537743c018289f74aad5cc3672d14a502c31641fb8244f41e8412eac10128e8f5261c43b4f3615d20e97a99ab69f99625fa6adf3e9eeec890f4721044dbeb8b",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[1], &account1),
                "1b5f79c97ae5ab0717fa5460331271a328b8773735fd146082d6aab86023e94fd51613fcd6c76ab3e64a05548ae71a45920ba317cba8b04917f2b6ef38a1f72a",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[2], &account1),
                "315d46daa4fb008207d7888c406c65aaca86fe708db505227cd13e4cea968034ce961432c8747f51a5f47139571f8b72c0905ac0b9834c030019ad29b9c77995",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[3], &account1),
                "b283bf358bfd9ea494f46c1b50485a2bd76aba5db918fea738b5f86ee950e95359dcbce5c1db7eab483e15788abb8f921c0bf9d83e3f0ea40bc4a0b5b2003378",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[4], &account1),
                "46ccf257425b3fce609d99062152166bb41f1dca503e46aa989146fbfccdb92c83fe90c5d232f934429fb4aa2c9c529412b7c1a678a736fe9c8b183de6e9dd59",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[5], &account1),
                "66cb7bc3b42f40a08e15dd4539201da316b0ccd12594b0ef62cd5a0480f410a4791a5e928685ca764a9ed728bf960ad1b3ccce15cdd4e9369abe24853b6f395c",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[6], &account1),
                "ec29fa50efd02cf9bcceb9c43e01fea0ea16df2770aeced93cc1594fa8b6aeaca6e42cdb223a3dbd5daf978c4f716437ebe51bd079b5ea681c9587ec1ac1fa93",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[7], &account1),
                "a7fbcc42b4d2af00cc2a1636aa89ba66a8d89008dcf0e0f830ccd6aa0340d638b930b07e0babcf93da0d1b7302445998779b5af11125f2e15ffe1a4f43dc901d",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[8], &account1),
                "0bd5c0fb6d8c5d0ad7d7883bdc9b9f03b147b9d6c540c949ac544ee326e8137532ca7eb1e2256952d200b5228c630d10b60a4d2b1d37a0d1408865a3188deb65",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[9], &account1),
                "47c5dfc79c953a672d7b4f74a2b60cf56c7d74253803e4629dfe80458cb0758b54172823a97486d63611f1d26fcb672e13d25c3fc42834b040d1d41460fd6f78",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[10], &account1),
                "9ba0d5070c0ba2f35cd89d344b30b681eb5a69d5668216865189e84a15b8fc50fa49ace13a1702761d3a4632c04b5ef00088b0052250ff2f0e4fb51db56e295e",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[11], &account1),
                "1eddbbfdf09404546c5a4a15e89b7811a658559cdde1960bcebc3aefe0ae86dd1c05a8418b208c75f3ad011d839e045ffa522135cb2cabc5c08f34b2060b5431",
            ))),
            Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                find_pub_key_for_pkh_dest(&acc_dests[12], &account1),
                "180a0f411eb920d7dd2b71cdf0a8f71a20ca82563c6cb6aa48fe20b7000ef05c1257968b3d6a7b369c8b131b83d421feae951c06ec27f5223e540a8eafb9842b",
            ))),
        ]
    };

    assert_eq!(ptx.witnesses().len(), expected_sigs.len());
    for (idx, (actual_sig, expected_sig)) in
        ptx.witnesses().iter().zip(expected_sigs.iter()).enumerate()
    {
        assert_eq!(actual_sig, expected_sig, "checking sig #{idx}");
    }
}

fn log_signature(index: usize, raw_sig: &[u8]) {
    if let Ok(spend) = AuthorizedPublicKeyHashSpend::from_data(raw_sig) {
        let sig =
            assert_matches_return_val!(spend.signature(), Signature::Secp256k1Schnorr(sig), sig);
        log::debug!("sig #{index} is AuthorizedPublicKeyHashSpend, sig = {sig:x}");
    } else if let Ok(spend) = AuthorizedPublicKeySpend::from_data(raw_sig) {
        let sig =
            assert_matches_return_val!(spend.signature(), Signature::Secp256k1Schnorr(sig), sig);
        log::debug!("sig #{index} is AuthorizedPublicKeySpend, sig = {sig:x}");
    } else if let Ok(spend) = AuthorizedClassicalMultisigSpend::from_data(raw_sig) {
        log::debug!("sig #{index} is AuthorizedClassicalMultisigSpend");

        for (i, sig) in spend.signatures() {
            let sig = assert_matches_return_val!(sig, Signature::Secp256k1Schnorr(sig), sig);
            log::debug!("   sig #{i} = {sig:x}");
        }
    } else if let Ok(spend) = AuthorizedHashedTimelockContractSpend::from_data(raw_sig) {
        match spend {
            AuthorizedHashedTimelockContractSpend::Secret(_, sig) => {
                let sig = hex::encode(&sig);
                log::debug!(
                    "sig #{index} is AuthorizedHashedTimelockContractSpend::Secret, sig = {sig}"
                );
            }
            AuthorizedHashedTimelockContractSpend::Multisig(inner_raw_sig) => {
                let inner_spend =
                    AuthorizedClassicalMultisigSpend::from_data(&inner_raw_sig).unwrap();
                log::debug!("sig #{index} is AuthorizedHashedTimelockContractSpend::Multisig");

                for (i, sig) in inner_spend.signatures() {
                    let sig =
                        assert_matches_return_val!(sig, Signature::Secp256k1Schnorr(sig), sig);
                    log::debug!("   sig #{i} = {sig:x}");
                }
            }
        }
    } else {
        panic!("Cannot decode sig #{index}");
    }
}

fn make_pub_key_spend_sig(sig_hex: &str) -> StandardInputSignature {
    let sig_bytes = hex::decode(sig_hex).unwrap();
    let sig = Signature::from_raw_data(&sig_bytes, SignatureKind::Secp256k1Schnorr).unwrap();
    let spend = AuthorizedPublicKeySpend::new(sig);
    StandardInputSignature::new(SigHashType::ALL.try_into().unwrap(), spend.encode())
}

fn make_pub_key_hash_spend_sig(pub_key: PublicKey, sig_hex: &str) -> StandardInputSignature {
    let sig_bytes = hex::decode(sig_hex).unwrap();
    let sig = Signature::from_raw_data(&sig_bytes, SignatureKind::Secp256k1Schnorr).unwrap();
    let spend = AuthorizedPublicKeyHashSpend::new(pub_key, sig);
    StandardInputSignature::new(SigHashType::ALL.try_into().unwrap(), spend.encode())
}

fn make_multisig_spend_sig<'a>(
    challenge: ClassicMultisigChallenge,
    sigs_hex: impl IntoIterator<Item = (u32, &'a str)>,
) -> StandardInputSignature {
    let mut spend = AuthorizedClassicalMultisigSpend::new_empty(challenge);

    for (idx, sig) in sigs_hex {
        let sig_bytes = hex::decode(sig).unwrap();
        let sig = Signature::from_raw_data(sig_bytes, SignatureKind::Secp256k1Schnorr).unwrap();
        spend.add_signature(idx as u8, sig);
    }

    let sighash_type: SigHashType = SigHashType::ALL.try_into().unwrap();
    StandardInputSignature::new(sighash_type, spend.encode())
}

fn make_htlc_secret_spend_sig(secret: HtlcSecret, sig_hex: &str) -> StandardInputSignature {
    let sig_bytes = hex::decode(sig_hex).unwrap();
    let spend = AuthorizedHashedTimelockContractSpend::Secret(secret, sig_bytes);
    StandardInputSignature::new(SigHashType::ALL.try_into().unwrap(), spend.encode())
}

fn make_htlc_multisig_spend_sig<'a>(
    challenge: ClassicMultisigChallenge,
    sigs_hex: impl IntoIterator<Item = (u32, &'a str)>,
) -> StandardInputSignature {
    let mut multisig_spend = AuthorizedClassicalMultisigSpend::new_empty(challenge);

    for (idx, sig) in sigs_hex {
        let sig_bytes = hex::decode(sig).unwrap();
        let sig = Signature::from_raw_data(sig_bytes, SignatureKind::Secp256k1Schnorr).unwrap();
        multisig_spend.add_signature(idx as u8, sig);
    }

    let spend = AuthorizedHashedTimelockContractSpend::Multisig(multisig_spend.encode());
    let sighash_type: SigHashType = SigHashType::ALL.try_into().unwrap();
    StandardInputSignature::new(sighash_type, spend.encode())
}

fn new_dest_from_account<K: AccountKeyChains>(
    account: &mut Account<K>,
    db_tx: &mut impl TransactionRwUnlocked,
    purpose: KeyPurpose,
) -> Destination {
    account.get_new_address(db_tx, purpose).unwrap().1.into_object()
}

fn new_pub_key_from_account<K: AccountKeyChains>(
    account: &mut Account<K>,
    db_tx: &mut impl TransactionRwUnlocked,
    purpose: KeyPurpose,
) -> PublicKey {
    let dest = new_dest_from_account(account, db_tx, purpose);
    find_pub_key_for_pkh_dest(&dest, &*account)
}

fn find_pub_key_for_pkh_dest<K: AccountKeyChains>(
    dest: &Destination,
    account: &Account<K>,
) -> PublicKey {
    let pkh = assert_matches_return_val!(dest, Destination::PublicKeyHash(pkh), pkh);
    account.find_corresponding_pub_key(pkh).unwrap()
}

fn bogus_destination(str_to_hash: &str) -> Destination {
    let sk = PrivateKey::from(
        Secp256k1PrivateKey::from_bytes(hash_encoded(&str_to_hash).as_bytes()).unwrap(),
    );
    Destination::PublicKey(PublicKey::from_private_key(&sk))
}

fn bogus_vrf_pub_key(str_to_hash: &str) -> VRFPublicKey {
    VRFPrivateKey::new_using_random_bytes(
        hash_encoded(&str_to_hash).as_bytes(),
        crypto::vrf::VRFKeyKind::Schnorrkel,
    )
    .unwrap()
    .1
}
