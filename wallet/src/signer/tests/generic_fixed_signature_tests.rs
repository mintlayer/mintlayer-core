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
        self,
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        config::ChainType,
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
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, ChainConfig,
        ChainstateUpgradeBuilder, DelegationId, Destination, NetUpgrades, OrderAccountCommand,
        OrderData, OrderId, OutPointSourceId, PoolId, SighashInputCommitmentVersion, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
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
    let sighash_input_commitment_version_fork_height = BlockHeight::new(rng.gen_range(1..100_000));
    // The height shouldn't matter as long as it's below the fork
    let tx_block_height =
        BlockHeight::new(rng.gen_range(0..sighash_input_commitment_version_fork_height.into_int()));

    let chain_config = Arc::new(
        chain::config::Builder::new(ChainType::Regtest)
            .chainstate_upgrades(
                NetUpgrades::initialize(vec![
                    (
                        BlockHeight::zero(),
                        ChainstateUpgradeBuilder::latest()
                            .sighash_input_commitment_version(SighashInputCommitmentVersion::V0)
                            .build(),
                    ),
                    (
                        sighash_input_commitment_version_fork_height,
                        ChainstateUpgradeBuilder::latest()
                            .sighash_input_commitment_version(SighashInputCommitmentVersion::V1)
                            .build(),
                    ),
                ])
                .unwrap(),
            )
            .build(),
    );

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
    let (ptx, _, _) =
        signer.sign_tx(orig_ptx, account.key_chain(), &db_tx, tx_block_height).unwrap();
    assert!(ptx.all_signatures_available());

    let input_commitments = ptx
        .make_sighash_input_commitments_at_height(&chain_config, tx_block_height)
        .unwrap();
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
/// 3) htlc inputs;
/// 4) v1 input commitments.
pub fn test_fixed_signatures_generic2<MkS, S>(
    rng: &mut (impl Rng + CryptoRng),
    input_commitments_version: SighashInputCommitmentVersion,
    make_signer: MkS,
) where
    MkS: Fn(Arc<ChainConfig>, U31) -> S,
    S: Signer,
{
    // The actual heights don't matter as long as tx block height is at the correct side of the fork.
    let (sighash_input_commitment_version_fork_height, tx_block_height) = {
        let fork_height = rng.gen_range(1000..2000);
        let tx_block_height = match input_commitments_version {
            SighashInputCommitmentVersion::V0 => rng.gen_range(1..fork_height),
            SighashInputCommitmentVersion::V1 => rng.gen_range(fork_height..fork_height * 2),
        };
        (
            BlockHeight::new(fork_height),
            BlockHeight::new(tx_block_height),
        )
    };

    let chain_config = Arc::new(
        chain::config::Builder::new(ChainType::Regtest)
            .chainstate_upgrades(
                NetUpgrades::initialize(vec![
                    (
                        BlockHeight::zero(),
                        ChainstateUpgradeBuilder::latest()
                            .sighash_input_commitment_version(SighashInputCommitmentVersion::V0)
                            .build(),
                    ),
                    (
                        sighash_input_commitment_version_fork_height,
                        ChainstateUpgradeBuilder::latest()
                            .sighash_input_commitment_version(SighashInputCommitmentVersion::V1)
                            .build(),
                    ),
                ])
                .unwrap(),
            )
            .build(),
    );

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

    let filled_order_v0_info = match input_commitments_version {
        SighashInputCommitmentVersion::V0 => {
            OrderAdditionalInfo {
                // Note: the amounts in initially_asked and initially_given aren't used by the signers when handling
                // v0 FillOrder, only the currencies matter.
                initially_asked: OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..200))),
                initially_given: OutputValue::TokenV1(
                    token_id,
                    Amount::from_atoms(rng.gen_range(100..200)),
                ),
                ask_balance: Amount::from_atoms(50),
                give_balance: Amount::from_atoms(100),
            }
        }
        SighashInputCommitmentVersion::V1 => {
            OrderAdditionalInfo {
                // Note: in commitments v1, we commit to initially_asked/initially_given values for FillOrder,
                // so the values can't be random.
                initially_asked: OutputValue::Coin(Amount::from_atoms(100)),
                initially_given: OutputValue::TokenV1(token_id, Amount::from_atoms(200)),
                ask_balance: Amount::from_atoms(50),
                give_balance: Amount::from_atoms(100),
            }
        }
    };
    let filled_order_v1_info = OrderAdditionalInfo {
        initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(300)),
        initially_given: OutputValue::Coin(Amount::from_atoms(150)),
        // Note: ask_balance/give_balance aren't used by the signers when handling v1 FillOrder.
        ask_balance: Amount::from_atoms(rng.gen_range(100..200)),
        give_balance: Amount::from_atoms(rng.gen_range(100..200)),
    };
    let concluded_order_v0_info = match input_commitments_version {
        SighashInputCommitmentVersion::V0 => {
            OrderAdditionalInfo {
                initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(110)),
                // Note: the amount in initially_given isn't used by the signers when handling ConcludeOrder
                // (both v0 and v1), only the currency matters.
                initially_given: OutputValue::TokenV1(
                    token_id,
                    Amount::from_atoms(rng.gen_range(100..200)),
                ),
                ask_balance: Amount::from_atoms(55),
                give_balance: Amount::from_atoms(110),
            }
        }
        SighashInputCommitmentVersion::V1 => OrderAdditionalInfo {
            // Note: in commitments v1, we commit to all values for ConcludeOrder,
            // so none of them can be random.
            initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(110)),
            initially_given: OutputValue::TokenV1(token_id, Amount::from_atoms(220)),
            ask_balance: Amount::from_atoms(55),
            give_balance: Amount::from_atoms(110),
        },
    };
    let concluded_order_v1_info = match input_commitments_version {
        SighashInputCommitmentVersion::V0 => {
            OrderAdditionalInfo {
                initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(330)),
                // Note: the amount in initially_given isn't used by the signers when handling ConcludeOrder
                // (both v0 and v1), only the currency matters.
                initially_given: OutputValue::TokenV1(
                    token_id,
                    Amount::from_atoms(rng.gen_range(100..200)),
                ),
                ask_balance: Amount::from_atoms(110),
                give_balance: Amount::from_atoms(55),
            }
        }
        SighashInputCommitmentVersion::V1 => {
            OrderAdditionalInfo {
                // Note: in commitments v1, we commit to all values for ConcludeOrder,
                // so none of them can be random.
                initially_asked: OutputValue::TokenV1(token_id, Amount::from_atoms(330)),
                initially_given: OutputValue::TokenV1(token_id, Amount::from_atoms(165)),
                ask_balance: Amount::from_atoms(110),
                give_balance: Amount::from_atoms(55),
            }
        }
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
        )),
    ];
    // Note: the last input is v1 FillOrder, which must not be signed.
    let acc_dests = (0..acc_inputs.len() - 1)
        .map(|_| new_dest_from_account(&mut account1, &mut db_tx, KeyPurpose::ReceiveFunds))
        .chain(std::iter::once(Destination::AnyoneCanSpend))
        .collect_vec();

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
        .make_sighash_input_commitments_at_height(&chain_config, tx_block_height)
        .unwrap()
        .into_iter()
        .map(|comm| comm.deep_clone())
        .collect_vec();

    let mut signer = make_signer(chain_config.clone(), account1.account_index());
    let (ptx, _, _) = signer.sign_tx(ptx, account1.key_chain(), &db_tx, tx_block_height).unwrap();
    assert!(ptx.all_signatures_available());

    // Fully sign multisig inputs.
    let mut signer = make_signer(chain_config.clone(), account2.account_index());
    let (ptx, _, _) = signer.sign_tx(ptx, account2.key_chain(), &db_tx, tx_block_height).unwrap();
    assert!(ptx.all_signatures_available());

    for (i, dest) in destinations.iter().enumerate() {
        log_witness(i, ptx.witnesses()[i].as_ref().unwrap());

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

    let expected_sigs = match input_commitments_version {
        SighashInputCommitmentVersion::V0 => {
            let htlc_multisig = {
                let sigs_hex = [
                (0, "0ff63e871249f4b6d8de07216617054c71a4b341e11afd405712cc108cb8e315f4b577444a29a81126aab9b7ad426594c2b39e5bc2e11169b1c64e62524620fe"),
                (1, "cd190e9a746aefb9ccec04a178017db55154f6370993139819ab270e988ff2c510b5bbcd95da31dff124f22b323bc3547ec15045e92552f7a951433c064d07f0"),
            ];
                make_htlc_multisig_spend_sig(htlc_multisig_challenge, sigs_hex)
            };
            let multisig = {
                let sigs_hex = [
                (1, "e94989eddcbb19eb87a02935a6b9e09e0cb0537d5aadf2d8bb37872949176820970c6d69320712be192805ad4609020237e46e461c0aeb42712f5feaceee5fd8"),
                (2, "90da875f04bc2db203e5a4c322514bb17d01870a34f40bba5922439580db156c4d9b455ce2b2ceb8e070541fb7a503752dfbc670ac32c858c462044e1ac8e421"),
                (3, "1ae75282887fcdca2f9cccbca269db14d368fd29658b92e32af98c9488ab6745cfd54dacafc91fcf63dbce69d196716345fd0d9cbcff25ef251286ab1bea025e")
            ];
                make_multisig_spend_sig(multisig_challenge, sigs_hex)
            };

            vec![
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&account1_dest4, &account1),
                    "dcc2f6ee68a13910e01a087946bc8200ac2fc0e229c756fced7e35f398b48c9c6e50987ea5990db911a812b90684597f640055cfc3407e130253216fe12c1d39",
                ))),
                Some(InputWitness::Standard(make_pub_key_spend_sig(
                    "90da875f04bc2db203e5a4c322514bb17d01870a34f40bba5922439580db156c4d9b455ce2b2ceb8e070541fb7a503752dfbc670ac32c858c462044e1ac8e421",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&decommission_dest, &account1),
                    "60ded17d5efd92ae32a8020bd0fe74aab43e095cb429a86e8b36e91fffa3fc04624e6c57663ab343da3ba6cc3853c4c8e26c0cf36b2b3fd96ba8b9afd6330260",
                ))),
                Some(InputWitness::Standard(make_htlc_secret_spend_sig(
                    htlc_secret,
                    "00765a0a326c9b0e7a4a7f890f6548df021163d25b034d568dbc5354eb11c40b567d0fa9bee9111eb6895d45fe4dec9e96f7bc8da5388a747ed1354b7425780abf",
                ))),
                Some(InputWitness::Standard(htlc_multisig)),
                Some(InputWitness::Standard(multisig)),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[0], &account1),
                    "89fc1b6acfc26c2abd019734fbc714c1a3f93157f0799fbc019eb64075130b5fa9ce675ba1b5fa6c80a3eef4d4cc01d2460e60ea996ab2acf158d3df9dc4c1b7",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[1], &account1),
                    "5628b5eb690254a711fd93824f177663d540365d26acf32f566cabddadbd4bd1fd1c48a4215448c22ff853f4e960fd46742ab82c50c68dd1a41a1e93ab03dd95",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[2], &account1),
                    "5f9c58fa90d14982fbe1e69ff91a21f60f7b8a7f069733baae744502d84e0d82e983558bcfaf9c8e77576a696784c1e71e87329cb132fde67316694c8cca84d7",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[3], &account1),
                    "bf61b338c7a59764b1ffbdf5751a6e017d1600eb70d89ab46114dd5ba130188847b7a3b0d67278ec33c5499ad5958c89245a2d76a6d580f343505bf03da2f10a",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[4], &account1),
                    "04c102210c9bc1467c97aac2930946c0ece292a7ee040dfe3fad1212c7d139ecef437b09f0f97cee908981dfd6898a375d735e77fef4bc32692e861a2e16825a",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[5], &account1),
                    "26ef8f25151bb1f7d098a9319bb18f1e54c64b7b8f80dc0eb6401ff924d5e6a9f4d343e808d56f6eead674b6a953a901f03615f592b2b11ee084d126ce533eea",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[6], &account1),
                    "4647a7ffb7fd7dd7bac96a49ba7595b2ebf6c39484a70f56b5acc9cd7eb70e845bbf8ab5c11844d3188d6ad8320c793eeeb7125b71a5fa82580c538e5b379596",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[7], &account1),
                    "d835087b24f194ec8aa45b2174ee625f5c5e5be52370d828f8f01024ec25226f268682bedca4dee966ab99b4d790c694ba15ca26dac91733735fd9efc5c0ac39",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[8], &account1),
                    "f412f8620df1ef92ca245df21ec0690a4f231c6ee11853cb67579f67a6782b03ebe6b9563a47c7552417fad354f5f9965cd522dd38fee36da61bf12d30a15484",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[9], &account1),
                    "a0273f3af5cdfce947908ada352d8a57228bcaa9d167868190ad6c034d86cb43d7d29e2db14eb786243db1fe6573f4d0c88cf0e1fe88a974c8981bd05928d6d3",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[10], &account1),
                    "3ae6e814d6d3b7072575b1a1e69ec32612ede6a79a712a575eed8b76e3c16fbf410563d7cfc22df9b2f09417bbd3e3f73d141039530e2fbbc57c87b93ca6c87b",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[11], &account1),
                    "2638c6936859e41083f6254e7ee1eaa9f06c2e3c39f635224828d06befa0b78699776df9160b08a94d55c18fa7d7369f87d9842add12727874c60e12894349c9",
                ))),
                Some(InputWitness::NoSignature(None)),
            ]
        }
        SighashInputCommitmentVersion::V1 => {
            let htlc_multisig = {
                let sigs_hex = [
                (0, "dbc526968f2506a1682cff368c2bb805f426dffbf85bcfc175b67f97444c0cb7285d1d80f582ae8192f7c329d895182a454735ffa9debbfbdf8517f9f3b5ddfc"),
                (1, "2a9dabb9953ba0b7fb66b0cad67a569f8df8947b07e41a46b640a0addc19b0131b6b2f46d3d784a5ba66d991b3e3af9ac7d6720c7d80cc6040892226a7b41669"),
            ];
                make_htlc_multisig_spend_sig(htlc_multisig_challenge, sigs_hex)
            };
            let multisig = {
                let sigs_hex = [
                (1, "8aacc97858a80bb779b000f18bf82c984977ca2a4d8560ae72421c9cd9cb7b513d35a62123553e0d24c0249eb2e04d2f99fe38eb41505a1081cd2d684a8a45d2"),
                (2, "c13c5bb22e719b5c7966aa9b58c2ae8e6bf3f848e62df19d38c4d41c7acd9d48eda1e13f18a25c9524904c4866143a95fd963606b5a77979a6dfc04cdebc979d"),
                (3, "93b5538c13a981dc8d6978361f13627603464de82d45f966de78b829a87eab642087b5bbc5b3aed5a888b8387491fe7fcd27f3e69bf7a70e5d12f004691da173")
            ];
                make_multisig_spend_sig(multisig_challenge, sigs_hex)
            };

            vec![
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&account1_dest4, &account1),
                    "79f8b16b721e0a92109f9deb15f67a7b5baf39196ba02240ad1038faa1ec55eead0bf3a328ffeee32cb751df208dbec2125345b853d276e11357b66657e222c0",
                ))),
                Some(InputWitness::Standard(make_pub_key_spend_sig(
                    "c13c5bb22e719b5c7966aa9b58c2ae8e6bf3f848e62df19d38c4d41c7acd9d48eda1e13f18a25c9524904c4866143a95fd963606b5a77979a6dfc04cdebc979d",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&decommission_dest, &account1),
                    "fb6ca8eb23d55a76284878e59f51c937bcccdbfc17074c248c4b4a39fac50084e072c6b643c297a38c2eb497c6a6b45f455be62cc7ff5d72dcfd75bc6d3f3643",
                ))),
                Some(InputWitness::Standard(make_htlc_secret_spend_sig(
                    htlc_secret,
                    "004f3a9f36d2e54da540e6a5d5500649ef38abd9d89bcecb8a5558fe5316fcdd5efa867f26dd99595004453dd92647b11f487769478eb8b62b2826d17b29a24dde",
                ))),
                Some(InputWitness::Standard(htlc_multisig)),
                Some(InputWitness::Standard(multisig)),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[0], &account1),
                    "f43511b1a2d22df92abbb40c6a6d5e553f3eb0701c3144eb8b37712bec8ee50f07011ec8921614f484d4cdd74a779657b3ece5a3f4edb57eb4c8a5813e247aeb",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[1], &account1),
                    "8e2d4d375590368f975ae4e74bdc4a7ce4e17bee0028428a4597b2f4bfbfe2fb501f25933a56c0a2d47a58f04f99a5742bd44113b28ef0d673f7490f3e1760d9",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[2], &account1),
                    "c3a49a0e3d43e9a016d865f1eab887de11d4cbc1bf67782ccc43b348ef4b25f65d668c23114e0606469f8ab4025be28ae3877e73ca14ea37a47ef68bba4e1065",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[3], &account1),
                    "bb24a759259b6053b8c129dbebde37d4b3602b15f4c2a1c9b53736052993eec48da5ba6ed88caf976285ced1711d5fa2023fd18d41ac45c0841c0794e05a5239",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[4], &account1),
                    "2b4dc6a7c85ea4f5c819472ea8b6ac1f4bc960113f462ab1a961b0b161e3097151f94343dea7f0a3201c43d39ab1e43c6ca074adbfac0d2d5e3a1e7855463aeb",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[5], &account1),
                    "d778efa779f75cb8ac2a9ecc01e5276705a2ea3a0a1abb28be9edfd62f6463d1b771598981f281cea8c4e94c2bda0849b89b8b3f58c40d0903b2ef2f9fb57645",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[6], &account1),
                    "9262a4e454d03493671feb406fa47db9b7c77c58cb52afff11f1ce448cf6437aad2b0e8aa252e282e91837251890a80a902d153aa4d4a8e9e85896588851c366",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[7], &account1),
                    "dce047ec8b1abc1cc6cc0191c2b05ffe56250fa3c6edf5923f900948a9024ea3fbfd0c9663b8de5ff6eadd7a7d5a7e49d40d0296ef9e9ecb3bec9567a65ed41e",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[8], &account1),
                    "4dd98d658178198e0bc944d4cb9b5483c156059f2a683a93c6f11f6357ad39a97a1f933f616203395e8daf4702b319cbe4069ea72bc577aaf2ccee1a85558917",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[9], &account1),
                    "d5e78f191f1966a7d9f78992514c76357fd837a3051c1cbf7b899099d74150389a843f960b24c650a619066efda0c149604c996989baee8bc9a37a42e633b2c7",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[10], &account1),
                    "f189b993fdc3d09e51b6fc8c962c9364d841641dfb074ab2cebfe13bf8ecc33ec2475fd26bc24a3a98bfec913e6eff5ad3d815bf8596f13b1752823febcc8955",
                ))),
                Some(InputWitness::Standard(make_pub_key_hash_spend_sig(
                    find_pub_key_for_pkh_dest(&acc_dests[11], &account1),
                    "7f86429630aeec7d0c140c097cc4f5071fa1a991359ec9c4c96a0bc7612a3acf4f949b57e4b00a450b79a93768363e5370671380e02365eae3c072b353ab3e7c",
                ))),
                Some(InputWitness::NoSignature(None)),
            ]
        }
    };

    assert_eq!(ptx.witnesses().len(), expected_sigs.len());
    for (idx, (actual_sig, expected_sig)) in
        ptx.witnesses().iter().zip(expected_sigs.iter()).enumerate()
    {
        assert_eq!(actual_sig, expected_sig, "checking sig #{idx}");
    }
}

fn log_witness(index: usize, witness: &InputWitness) {
    match witness {
        InputWitness::NoSignature(_) => {
            log::debug!("sig #{index} is NoSignature");
        }
        InputWitness::Standard(sig) => {
            let raw_sig = sig.raw_signature();

            if let Ok(spend) = AuthorizedPublicKeyHashSpend::from_data(raw_sig) {
                let sig = assert_matches_return_val!(
                    spend.signature(),
                    Signature::Secp256k1Schnorr(sig),
                    sig
                );
                log::debug!("sig #{index} is AuthorizedPublicKeyHashSpend, sig = {sig:x}");
            } else if let Ok(spend) = AuthorizedPublicKeySpend::from_data(raw_sig) {
                let sig = assert_matches_return_val!(
                    spend.signature(),
                    Signature::Secp256k1Schnorr(sig),
                    sig
                );
                log::debug!("sig #{index} is AuthorizedPublicKeySpend, sig = {sig:x}");
            } else if let Ok(spend) = AuthorizedClassicalMultisigSpend::from_data(raw_sig) {
                log::debug!("sig #{index} is AuthorizedClassicalMultisigSpend");

                for (i, sig) in spend.signatures() {
                    let sig =
                        assert_matches_return_val!(sig, Signature::Secp256k1Schnorr(sig), sig);
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
                        log::debug!(
                            "sig #{index} is AuthorizedHashedTimelockContractSpend::Multisig"
                        );

                        for (i, sig) in inner_spend.signatures() {
                            let sig = assert_matches_return_val!(
                                sig,
                                Signature::Secp256k1Schnorr(sig),
                                sig
                            );
                            log::debug!("   sig #{i} = {sig:x}");
                        }
                    }
                }
            } else {
                panic!("Cannot decode sig #{index}");
            }
        }
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
