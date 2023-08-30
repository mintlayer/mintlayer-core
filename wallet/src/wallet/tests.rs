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

use crate::{
    key_chain::{make_account_path, LOOKAHEAD_SIZE},
    send_request::{make_address_output, make_create_delegation_output},
    wallet_events::WalletEventsNoOp,
    DefaultWallet,
};
use serialization::Encode;
use std::collections::BTreeSet;

use super::*;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_mainnet, create_regtest, Builder, ChainType},
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::{TokenData, TokenTransfer},
        Destination, Genesis, OutPointSourceId, TxInput,
    },
    primitives::{per_thousand::PerThousand, Idable, H256},
};
use crypto::{
    key::hdkd::{child_number::ChildNumber, derivable::Derivable, derivation_path::DerivationPath},
    random::{CryptoRng, Rng, SliceRandom},
};
use itertools::Itertools;
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use storage::raw::DbMapId;
use test_utils::random::{make_seedable_rng, Seed};
use wallet_storage::{schema, WalletStorageEncryptionRead};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    utxo_types::{UtxoState, UtxoType},
};
use wallet_types::{seed_phrase::SeedPhraseLanguage, AccountWalletTxId};

// TODO: Many of these tests require randomization...

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const NETWORK_FEE: u128 = 10000;

fn get_best_block(wallet: &DefaultWallet) -> (Id<GenBlock>, BlockHeight) {
    *wallet.get_best_block().first_key_value().unwrap().1
}

#[track_caller]
fn scan_wallet(wallet: &mut DefaultWallet, height: BlockHeight, blocks: Vec<Block>) {
    for account in wallet.get_best_block().keys() {
        wallet
            .scan_new_blocks(*account, height, blocks.clone(), &WalletEventsNoOp)
            .unwrap();
    }

    wallet
        .scan_new_blocks_unused_account(height, blocks, &WalletEventsNoOp)
        .unwrap();
}

fn gen_random_password(rng: &mut (impl Rng + CryptoRng)) -> String {
    (0..rng.gen_range(1..100)).map(|_| rng.gen::<char>()).collect()
}

fn gen_random_transfer(rng: &mut (impl Rng + CryptoRng), amount: Amount) -> TxOutput {
    let destination = Destination::PublicKey(
        crypto::key::PrivateKey::new_from_rng(rng, crypto::key::KeyKind::Secp256k1Schnorr).1,
    );
    match rng.gen::<bool>() {
        true => TxOutput::Transfer(OutputValue::Coin(amount), destination),
        false => {
            let lock_for_blocks = rng.gen_range(0..1000);
            let current_block_height = BlockHeight::new(rng.gen_range(0..1000));
            let seconds_between_blocks = rng.gen_range(1..1000);
            let current_timestamp = BlockTimestamp::from_int_seconds(rng.gen_range(0..1000));
            gen_random_lock_then_transfer(
                rng,
                amount,
                destination,
                lock_for_blocks,
                current_block_height,
                seconds_between_blocks,
                current_timestamp,
            )
        }
    }
}

fn gen_random_lock_then_transfer(
    rng: &mut (impl Rng + CryptoRng),
    amount: Amount,
    destination: Destination,
    lock_for_blocks: u64,
    current_block_height: BlockHeight,
    seconds_between_blocks: u64,
    current_timestamp: BlockTimestamp,
) -> TxOutput {
    match rng.gen_range(0..4) {
        0 => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            destination,
            OutputTimeLock::ForBlockCount(lock_for_blocks),
        ),
        1 => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            destination,
            OutputTimeLock::UntilHeight(current_block_height.checked_add(lock_for_blocks).unwrap()),
        ),
        2 => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            destination,
            OutputTimeLock::ForSeconds(seconds_between_blocks * lock_for_blocks),
        ),
        _ => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            destination,
            OutputTimeLock::UntilTime(
                current_timestamp
                    .add_int_seconds(seconds_between_blocks * lock_for_blocks)
                    .unwrap(),
            ),
        ),
    }
}

fn get_address(
    chain_config: &ChainConfig,
    mnemonic: &str,
    account_index: U31,
    purpose: KeyPurpose,
    address_index: U31,
) -> Address<Destination> {
    let (root_key, _root_vrf_key, _) =
        MasterKeyChain::mnemonic_to_root_key(mnemonic, None).unwrap();
    let mut address_path = make_account_path(chain_config, account_index).into_vec();
    address_path.push(purpose.get_deterministic_index());
    address_path.push(ChildNumber::from_normal(address_index));
    let address_priv_key = root_key
        .derive_absolute_path(&DerivationPath::try_from(address_path).unwrap())
        .unwrap();
    Address::new(
        chain_config,
        &Destination::PublicKey(address_priv_key.to_public_key().into_public_key()),
    )
    .unwrap()
}

#[track_caller]
fn verify_wallet_balance(
    chain_config: &Arc<ChainConfig>,
    wallet: &DefaultWallet,
    expected_balance: Amount,
) {
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, expected_balance);

    // Loading a copy of the wallet from the same DB should be safe because loading is an R/O operation
    let db_copy = wallet.db.clone();
    let wallet = Wallet::load_wallet(Arc::clone(chain_config), db_copy, None).unwrap();
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    // Check that the loaded wallet has the same balance
    assert_eq!(coin_balance, expected_balance);
}

fn create_wallet(chain_config: Arc<ChainConfig>) -> Wallet<DefaultBackend> {
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    Wallet::create_new_wallet(
        chain_config,
        db,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
        BlockHeight::new(0),
        genesis_block_id,
    )
    .unwrap()
}

#[track_caller]
fn test_balance_from_genesis(
    chain_type: ChainType,
    utxos: Vec<TxOutput>,
    expected_balance: Amount,
) {
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        utxos,
    );
    let chain_config = Arc::new(Builder::new(chain_type).genesis_custom(genesis).build());

    let wallet = create_wallet(chain_config.clone());

    verify_wallet_balance(&chain_config, &wallet, expected_balance);
}

#[test]
fn wallet_creation_in_memory() {
    let chain_config = Arc::new(create_regtest());
    let empty_db = create_wallet_in_memory().unwrap();

    // fail to load an empty wallet
    match Wallet::load_wallet(Arc::clone(&chain_config), empty_db, None) {
        Ok(_) => panic!("Wallet loading should fail"),
        Err(err) => assert_eq!(err, WalletError::WalletNotInitialized),
    }

    // initialize a new wallet with mnemonic
    let wallet = create_wallet(chain_config.clone());
    let initialized_db = wallet.db;

    // successfully load a wallet from initialized db
    let _wallet = Wallet::load_wallet(chain_config, initialized_db, None).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_migration_to_v2(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    let mut wallet = Wallet::create_new_wallet(
        Arc::clone(&chain_config),
        db,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
        BlockHeight::new(0),
        genesis_block_id,
    )
    .unwrap();
    let password = Some("password".into());
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet().unwrap();
    let default_acc_id = wallet.accounts.get(&DEFAULT_ACCOUNT_INDEX).unwrap().get_account_id();
    let db = wallet.db;

    // set version back to v1
    let mut db_tx = db.transaction_rw(None).unwrap();
    db_tx.set_storage_version(WALLET_VERSION_V1).unwrap();

    // delete the last unused acc
    let wallet_accounts = db_tx.get_accounts_info().unwrap();
    assert_eq!(wallet_accounts.len(), 2);
    let last_acc = wallet_accounts.iter().max_by_key(|acc| acc.1.account_index()).unwrap();
    db_tx.del_account(last_acc.0).unwrap();

    db_tx.commit().unwrap();

    let mut raw_db = db.dump_raw().unwrap();
    // remove the counters
    raw_db.remove(&DbMapId::new::<schema::DBUnconfirmedTxCounters, _>());
    // remove config
    let values = raw_db.get_mut(&DbMapId::new::<schema::DBValue, _>()).unwrap();
    values.remove(stringify!(StoreChainInfo).as_bytes());
    // insert some old txs that can't be deserialized to the new tx structure
    let txs = raw_db.get_mut(&DbMapId::new::<schema::DBTxs, _>()).unwrap();
    for idx in 0..10 {
        let id = AccountWalletTxId::new(
            default_acc_id.clone(),
            OutPointSourceId::Transaction(Id::<Transaction>::new(H256::from_low_u64_ne(idx))),
        );
        txs.insert(
            id.encode(),
            (0..rng.gen_range(1..10)).map(|_| rng.gen::<u8>()).collect(),
        );
    }

    let new_db = Store::new_from_dump(DefaultBackend::new_in_memory(), raw_db).unwrap();

    let wallet = Wallet::load_wallet(Arc::clone(&chain_config), new_db, password).unwrap();

    // Migration has been done and new version is v2
    assert_eq!(wallet.db.get_storage_version().unwrap(), WALLET_VERSION_V2);

    // accounts have been reset back to genesis to rescan the blockchain
    assert_eq!(
        wallet.get_best_block_for_account(DEFAULT_ACCOUNT_INDEX).unwrap(),
        (chain_config.genesis_block_id(), BlockHeight::new(0))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_seed_phrase_retrieval(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    // create wallet without saving the seed phrase
    {
        let wallet = create_wallet(chain_config.clone());
        let seed_phrase = wallet.seed_phrase().unwrap();
        assert!(seed_phrase.is_none());
    }

    // create wallet with saving the seed phrase
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    let mut wallet = Wallet::create_new_wallet(
        Arc::clone(&chain_config),
        db,
        MNEMONIC,
        None,
        StoreSeedPhrase::Store,
        BlockHeight::new(0),
        genesis_block_id,
    )
    .unwrap();

    {
        let seed_phrase = wallet.seed_phrase().unwrap().unwrap();
        let (seed_phrase_language, seed_phrase) = match seed_phrase {
            SerializableSeedPhrase::V0(language, seed_phrase) => (language, seed_phrase),
        };
        assert_eq!(seed_phrase.mnemonic().join(" "), MNEMONIC);
        assert_eq!(seed_phrase_language, SeedPhraseLanguage::English);
    }

    let password = gen_random_password(&mut rng);
    wallet.encrypt_wallet(&Some(password.clone())).unwrap();
    wallet.lock_wallet().unwrap();

    let err = wallet.seed_phrase().unwrap_err();
    assert_eq!(
        err,
        WalletError::DatabaseError(wallet_storage::Error::WalletLocked)
    );

    wallet.unlock_wallet(&password).unwrap();
    {
        let seed_phrase = wallet.seed_phrase().unwrap().unwrap();
        let (seed_phrase_language, seed_phrase) = match seed_phrase {
            SerializableSeedPhrase::V0(language, seed_phrase) => (language, seed_phrase),
        };
        assert_eq!(seed_phrase.mnemonic().join(" "), MNEMONIC);
        assert_eq!(seed_phrase_language, SeedPhraseLanguage::English);
    }

    {
        // Deleting the seed phrase will return it
        let seed_phrase = wallet.delete_seed_phrase().unwrap().unwrap();
        let (seed_phrase_language, seed_phrase) = match seed_phrase {
            SerializableSeedPhrase::V0(language, seed_phrase) => (language, seed_phrase),
        };
        assert_eq!(seed_phrase.mnemonic().join(" "), MNEMONIC);
        assert_eq!(seed_phrase_language, SeedPhraseLanguage::English);
    }

    // Now the seed phrase doesn't exist in the wallet anymore
    let seed_phrase = wallet.seed_phrase().unwrap();
    assert!(seed_phrase.is_none());
}

#[test]
fn wallet_balance_genesis() {
    let chain_type = ChainType::Mainnet;

    let genesis_amount = Amount::from_atoms(12345);
    let chain_config = Arc::new(Builder::new(chain_type).build());
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let genesis_output = TxOutput::Transfer(
        OutputValue::Coin(genesis_amount),
        address.decode_object(chain_config.as_ref()).unwrap(),
    );

    test_balance_from_genesis(chain_type, vec![genesis_output.clone()], genesis_amount);

    let genesis_amount_2 = Amount::from_atoms(54321);
    let genesis_output_2 = TxOutput::LockThenTransfer(
        OutputValue::Coin(genesis_amount_2),
        address.decode_object(chain_config.as_ref()).unwrap(),
        OutputTimeLock::UntilHeight(BlockHeight::zero()),
    );

    test_balance_from_genesis(
        chain_type,
        vec![genesis_output, genesis_output_2],
        (genesis_amount + genesis_amount_2).unwrap(),
    );

    let address_indexes = [0, LOOKAHEAD_SIZE - 1, LOOKAHEAD_SIZE];
    for purpose in KeyPurpose::ALL {
        for address_index in address_indexes {
            let address_index: U31 = address_index.try_into().unwrap();
            let address = get_address(
                &chain_config,
                MNEMONIC,
                DEFAULT_ACCOUNT_INDEX,
                purpose,
                address_index,
            );

            let genesis_amount = Amount::from_atoms(23456);
            let genesis_output =
                make_address_output(chain_config.as_ref(), address, genesis_amount).unwrap();

            if address_index.into_u32() == LOOKAHEAD_SIZE {
                test_balance_from_genesis(chain_type, vec![genesis_output], Amount::ZERO);
            } else {
                test_balance_from_genesis(chain_type, vec![genesis_output], genesis_amount);
            }
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_balance_works(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_type = ChainType::Mainnet;
    let genesis_amount = Amount::from_atoms(rng.gen_range(1..10000));
    let chain_config = Arc::new(create_mainnet());
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let genesis_output = TxOutput::Transfer(
        OutputValue::Coin(genesis_amount),
        address.decode_object(chain_config.as_ref()).unwrap(),
    );
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        vec![genesis_output],
    );
    let chain_config = Arc::new(Builder::new(chain_type).genesis_custom(genesis).build());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, genesis_amount);

    let password = gen_random_password(&mut rng);
    wallet.encrypt_wallet(&Some(password)).unwrap();
    wallet.lock_wallet().unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, genesis_amount);
}

#[test]
fn wallet_balance_block_reward() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);

    assert_eq!(coin_balance, Amount::ZERO);
    let (best_block_id, best_block_height) = get_best_block(&wallet);
    assert_eq!(best_block_id, chain_config.genesis_block_id());
    assert_eq!(best_block_height, BlockHeight::new(0));

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(10000);
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();
    let block1_id = block1.header().block_id();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    // Verify that the first block reward has been received
    let (best_block_id, best_block_height) = get_best_block(&wallet);
    assert_eq!(best_block_id, block1_id);
    assert_eq!(best_block_height, BlockHeight::new(1));
    verify_wallet_balance(&chain_config, &wallet, block1_amount);

    // Create the second block that sends the reward to the wallet
    let block2_amount = Amount::from_atoms(20000);
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::Change,
        (LOOKAHEAD_SIZE - 1).try_into().unwrap(),
    );
    let block2 = Block::new(
        vec![],
        block1_id.into(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block2_amount,
        )
        .unwrap()]),
    )
    .unwrap();
    let block2_id = block2.header().block_id();
    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);

    // Verify that the second block reward is also received
    let (best_block_id, best_block_height) = get_best_block(&wallet);
    assert_eq!(best_block_id, block2_id);
    assert_eq!(best_block_height, BlockHeight::new(2));
    verify_wallet_balance(
        &chain_config,
        &wallet,
        (block1_amount + block2_amount).unwrap(),
    );

    // Create a new block to replace the second block
    let block2_amount_new = Amount::from_atoms(30000);
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        (LOOKAHEAD_SIZE - 1).try_into().unwrap(),
    );
    let block2_new = Block::new(
        vec![],
        block1_id.into(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block2_amount_new,
        )
        .unwrap()]),
    )
    .unwrap();
    let block2_new_id = block2_new.header().block_id();
    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2_new]);

    // Verify that the balance includes outputs from block1 and block2_new, but not block2
    let (best_block_id, best_block_height) = get_best_block(&wallet);
    assert_eq!(best_block_id, block2_new_id);
    assert_eq!(best_block_height, BlockHeight::new(2));
    verify_wallet_balance(
        &chain_config,
        &wallet,
        (block1_amount + block2_amount_new).unwrap(),
    );
}

#[test]
fn wallet_balance_block_transactions() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let tx_amount1 = Amount::from_atoms(10000);
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );

    let transaction1 = Transaction::new(
        0,
        Vec::new(),
        vec![make_address_output(chain_config.as_ref(), address, tx_amount1).unwrap()],
    )
    .unwrap();
    let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();
    let block1 = Block::new(
        vec![signed_transaction1],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    verify_wallet_balance(&chain_config, &wallet, tx_amount1);
}

#[test]
// Verify that outputs can be created and consumed in the same block
fn wallet_balance_parent_child_transactions() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let tx_amount1 = Amount::from_atoms(20000);
    let tx_amount2 = Amount::from_atoms(10000);

    let address1 = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let address2 = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        1.try_into().unwrap(),
    );

    let transaction1 = Transaction::new(
        0,
        Vec::new(),
        vec![make_address_output(chain_config.as_ref(), address1, tx_amount1).unwrap()],
    )
    .unwrap();
    let transaction_id1 = transaction1.get_id();
    let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();

    let transaction2 = Transaction::new(
        0,
        vec![TxInput::from_utxo(OutPointSourceId::Transaction(transaction_id1), 0)],
        vec![make_address_output(chain_config.as_ref(), address2, tx_amount2).unwrap()],
    )
    .unwrap();
    let signed_transaction2 =
        SignedTransaction::new(transaction2, vec![InputWitness::NoSignature(None)]).unwrap();

    let block1 = Block::new(
        vec![signed_transaction1, signed_transaction2],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    verify_wallet_balance(&chain_config, &wallet, tx_amount2);
}

#[track_caller]
fn test_wallet_accounts(
    chain_config: &Arc<ChainConfig>,
    wallet: &DefaultWallet,
    expected_accounts: Vec<U31>,
) {
    let accounts = wallet.account_indexes().cloned().collect::<Vec<_>>();
    assert_eq!(accounts, expected_accounts);

    let db_copy = wallet.db.clone();
    let wallet = Wallet::load_wallet(Arc::clone(chain_config), db_copy, None).unwrap();
    let accounts = wallet.account_indexes().cloned().collect::<Vec<_>>();
    assert_eq!(accounts, expected_accounts);
}

#[test]
fn wallet_accounts_creation() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    test_wallet_accounts(&chain_config, &wallet, vec![DEFAULT_ACCOUNT_INDEX]);
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1,
            Amount::from_atoms(100),
        )
        .unwrap()]),
    )
    .unwrap();
    // DEFAULT_ACCOUNT_INDEX now has 1 transaction so next account can be created
    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);
    let res = wallet.create_next_account(Some("name".into())).unwrap();
    assert_eq!(res, (U31::from_u32(1).unwrap(), Some("name".into())));

    // but we cannot create a third account as the new one has no transactions
    let error = wallet.create_next_account(None).err().unwrap();
    assert_eq!(error, WalletError::EmptyLastAccount);

    let acc1_pk = wallet.get_new_public_key(res.0).unwrap();
    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::PublicKey(acc1_pk),
            )],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();

    // even with an unconfirmed transaction we cannot create a new account
    wallet.add_unconfirmed_tx(tx.clone(), &WalletEventsNoOp).unwrap();
    let error = wallet.create_next_account(None).err().unwrap();
    assert_eq!(error, WalletError::EmptyLastAccount);

    let block2 = Block::new(
        vec![tx],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();
    // after getting a confirmed transaction we can create a new account
    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);
    let res = wallet.create_next_account(Some("name2".into())).unwrap();
    assert_eq!(res, (U31::from_u32(2).unwrap(), Some("name2".into())));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_accounts_creation_fail(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    // Need at least one address used from the previous account in order to create a new account
    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 1..NETWORK_FEE + 10000));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);
    let password = Some(gen_random_password(&mut rng));
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet().unwrap();

    let err = wallet.create_next_account(None);
    assert_eq!(
        err,
        Err(WalletError::DatabaseError(
            wallet_storage::Error::WalletLocked
        ))
    );

    let name: String = (0..rng.gen_range(0..10)).map(|_| rng.gen::<char>()).collect();

    // success after unlock
    wallet.unlock_wallet(&password.unwrap()).unwrap();
    if name.is_empty() {
        let err = wallet.create_next_account(Some(name));
        assert_eq!(err, Err(WalletError::EmptyAccountName));
    } else {
        let (new_account_index, new_name) = wallet.create_next_account(Some(name.clone())).unwrap();
        assert_ne!(new_account_index, DEFAULT_ACCOUNT_INDEX);
        assert_eq!(new_name.unwrap(), name);
        assert_eq!(wallet.number_of_accounts(), 2);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_recover_new_account(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let err = wallet.create_next_account(None).err().unwrap();
    assert_eq!(err, WalletError::EmptyLastAccount);

    let mut total_amounts = BTreeMap::new();
    let mut last_account_index = DEFAULT_ACCOUNT_INDEX;
    let blocks = (0..rng.gen_range(1..1000))
        .map(|idx| {
            let tx_amount1 = Amount::from_atoms(rng.gen_range(1..10));
            total_amounts
                .entry(last_account_index)
                .and_modify(|amount: &mut Amount| *amount = (*amount + tx_amount1).unwrap())
                .or_insert(tx_amount1);

            let address = wallet.get_new_address(last_account_index).unwrap().1;

            let transaction1 = Transaction::new(
                0,
                Vec::new(),
                vec![make_address_output(chain_config.as_ref(), address, tx_amount1).unwrap()],
            )
            .unwrap();
            let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();
            let block = Block::new(
                vec![signed_transaction1],
                chain_config.genesis_block_id(),
                chain_config.genesis_block().timestamp(),
                ConsensusData::None,
                BlockReward::new(Vec::new()),
            )
            .unwrap();

            scan_wallet(&mut wallet, BlockHeight::new(idx), vec![block.clone()]);

            if rng.gen_bool(0.2) {
                last_account_index = wallet.create_next_account(None).unwrap().0;
            }
            block
        })
        .collect_vec();

    // verify all accounts have the expected balances
    for (acc_idx, expected_balance) in total_amounts.iter() {
        let coin_balance = wallet
            .get_balance(
                *acc_idx,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                UtxoState::Confirmed.into(),
                WithLocked::Unlocked,
            )
            .unwrap()
            .get(&Currency::Coin)
            .copied()
            .unwrap_or(Amount::ZERO);
        assert_eq!(coin_balance, *expected_balance);
    }

    // Create a new wallet with the same mnemonic
    let mut wallet = create_wallet(chain_config);
    // scan the blocks again
    scan_wallet(&mut wallet, BlockHeight::new(0), blocks.clone());

    // verify the wallet has recovered all of the accounts
    assert_eq!(wallet.number_of_accounts(), total_amounts.len(),);

    // verify all accounts have the expected balances
    for (acc_idx, expected_balance) in total_amounts {
        let coin_balance = wallet
            .get_balance(
                acc_idx,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                UtxoState::Confirmed.into(),
                WithLocked::Unlocked,
            )
            .unwrap()
            .get(&Currency::Coin)
            .copied()
            .unwrap_or(Amount::ZERO);
        assert_eq!(coin_balance, expected_balance);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_cant_sign_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 1..NETWORK_FEE + 10000));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let password = Some(gen_random_password(&mut rng));
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet().unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let new_output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(
            rng.gen_range(1..=block1_amount.into_atoms() - NETWORK_FEE),
        )),
        Destination::AnyoneCanSpend,
    );

    assert_eq!(
        wallet.create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output.clone()],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        ),
        Err(WalletError::DatabaseError(
            wallet_storage::Error::WalletLocked
        ))
    );

    // success after unlock
    wallet.unlock_wallet(&password.unwrap()).unwrap();
    if rng.gen::<bool>() {
        wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                vec![new_output],
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap();
    } else {
        // check if we remove the password it should fail to lock
        wallet.encrypt_wallet(&None).unwrap();

        let err = wallet.lock_wallet().unwrap_err();
        assert_eq!(
            err,
            WalletError::DatabaseError(wallet_storage::Error::WalletLockedWithoutAPassword)
        );

        // check that the kdf challenge has been deleted
        assert!(wallet
            .db
            .transaction_ro()
            .unwrap()
            .get_encryption_key_kdf_challenge()
            .unwrap()
            .is_none());

        wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                vec![new_output],
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_transaction_with_fees(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(100000..1000000));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let num_outputs = rng.gen_range(1..10);
    let amount_to_transfer = Amount::from_atoms(
        rng.gen_range(1..=(block1_amount.into_atoms() / num_outputs - NETWORK_FEE)),
    );

    let outputs: Vec<TxOutput> = (0..num_outputs)
        .map(|_| gen_random_transfer(&mut rng, amount_to_transfer))
        .collect();

    let feerate = FeeRate::new(Amount::from_atoms(1000));
    let transaction = wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, outputs, feerate, feerate)
        .unwrap();
    wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

    let tx_size = serialization::Encode::encoded_size(&transaction);
    let fee = feerate.compute_fee(tx_size).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert!(coin_balance <= ((block1_amount - amount_to_transfer).unwrap() - fee.into()).unwrap());
}

#[test]
fn lock_wallet_fail_empty_password() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config);
    let empty_password = Some(String::new());
    assert_eq!(
        wallet.encrypt_wallet(&empty_password),
        Err(WalletError::DatabaseError(
            wallet_storage::Error::WalletEmptyPassword
        ))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_stake_pool_and_list_pool_ids(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    let block1_id = block1.get_id();
    let block1_timestamp = block1.timestamp();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = block1_amount;

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            None,
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
            StakePoolDataArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
            },
        )
        .unwrap();
    let block2 = Block::new(
        vec![stake_pool_transaction],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::CreateStakePool,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        pool_amount
    );

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_id = pool_ids.first().unwrap().0;
    let decommission_tx = wallet
        .decommission_stake_pool(
            DEFAULT_ACCOUNT_INDEX,
            pool_id,
            pool_amount,
            FeeRate::new(Amount::from_atoms(0)),
        )
        .unwrap();

    let block3 = Block::new(
        vec![decommission_tx],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(2), vec![block3]);

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::CreateStakePool,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        pool_amount,
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_spend_from_delegations(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(2..100));
    let block1_amount = (chain_config.min_stake_pool_pledge() + delegation_amount).unwrap();
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address.clone(),
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    let block1_id = block1.get_id();
    let block1_timestamp = block1.timestamp();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = chain_config.min_stake_pool_pledge();

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            None,
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
            StakePoolDataArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
            },
        )
        .unwrap();
    let block2 = Block::new(
        vec![stake_pool_transaction],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::CreateStakePool,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        block1_amount,
    );

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_id = pool_ids.first().unwrap().0;
    let (delegation_id, delegation_tx) = wallet
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(chain_config.as_ref(), address.clone(), pool_id)
                .unwrap()],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();

    let block3 = Block::new(
        vec![delegation_tx],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(2), vec![block3]);

    let delegation_stake_tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![TxOutput::DelegateStaking(delegation_amount, delegation_id)],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();

    let block4 = Block::new(
        vec![delegation_stake_tx],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(3), vec![block4]);

    let delegation_tx1 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            Amount::from_atoms(1),
            delegation_id,
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();

    wallet.add_unconfirmed_tx(delegation_tx1.clone(), &WalletEventsNoOp).unwrap();
    let delegation_tx1 = vec![delegation_tx1];

    let delegation_tx2 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address,
            Amount::from_atoms(1),
            delegation_id,
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();
    wallet.add_unconfirmed_tx(delegation_tx2.clone(), &WalletEventsNoOp).unwrap();
    let delegation_tx2 = vec![delegation_tx2];

    // Check delegation balance after unconfirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_amount) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(
        deleg_amount,
        (delegation_amount - Amount::from_atoms(2)).unwrap()
    );

    let block5 = Block::new(
        delegation_tx1,
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(4), vec![block5]);
    let block6 = Block::new(
        delegation_tx2,
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(5), vec![block6]);

    // Check delegation balance after confirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_amount) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(
        deleg_amount,
        (delegation_amount - Amount::from_atoms(2)).unwrap()
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_transfer_tokens(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.token_min_issuance_fee())
    .unwrap();
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address.clone(),
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    let block1_id = block1.get_id();
    let block1_timestamp = block1.timestamp();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let amount_fraction = (block1_amount.into_atoms() - NETWORK_FEE) / 10;
    let mut token_amount_to_issue = Amount::from_atoms(rng.gen_range(1..amount_fraction));

    let (issued_token_id, token_issuance_transaction) = if rng.gen::<bool>() {
        wallet
            .issue_new_token(
                DEFAULT_ACCOUNT_INDEX,
                address2,
                TokenIssuance {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    amount_to_issue: token_amount_to_issue,
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                },
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap()
    } else {
        token_amount_to_issue = Amount::from_atoms(1);
        wallet
            .issue_new_nft(
                DEFAULT_ACCOUNT_INDEX,
                address2,
                Metadata {
                    creator: None,
                    name: "Name".as_bytes().to_vec(),
                    description: "SomeNFT".as_bytes().to_vec(),
                    ticker: "XXXX".as_bytes().to_vec(),
                    icon_uri: DataOrNoVec::from(None),
                    additional_metadata_uri: DataOrNoVec::from(None),
                    media_uri: DataOrNoVec::from(None),
                    media_hash: "123456".as_bytes().to_vec(),
                },
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap()
    };

    let block2 = Block::new(
        vec![token_issuance_transaction],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address.clone(),
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        ((block1_amount * 2).unwrap() - chain_config.token_min_issuance_fee()).unwrap()
    );
    let token_balances = currency_balances
        .into_iter()
        .filter_map(|(c, amount)| match c {
            Currency::Coin => None,
            Currency::Token(token_id) => Some((token_id, amount)),
        })
        .collect_vec();
    assert_eq!(token_balances.len(), 1);
    let (token_id, token_amount) = token_balances.first().expect("some");
    assert_eq!(*token_id, issued_token_id);
    assert_eq!(*token_amount, token_amount_to_issue);

    let tokens_to_transfer =
        Amount::from_atoms(rng.gen_range(1..=token_amount_to_issue.into_atoms()));

    let some_other_address = PublicKeyHash::from_low_u64_be(1);
    let new_output = TxOutput::Transfer(
        OutputValue::Token(Box::new(TokenData::TokenTransfer(TokenTransfer {
            token_id: *token_id,
            amount: tokens_to_transfer,
        }))),
        Destination::Address(some_other_address),
    );

    let transfer_tokens_transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();
    wallet
        .add_unconfirmed_tx(transfer_tokens_transaction.clone(), &WalletEventsNoOp)
        .unwrap();

    let block3 = Block::new(
        vec![transfer_tokens_transaction],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(2), vec![block3]);

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        ((block1_amount * 3).unwrap() - chain_config.token_min_issuance_fee()).unwrap()
    );
    let token_balances = currency_balances
        .into_iter()
        .filter_map(|(c, amount)| match c {
            Currency::Coin => None,
            Currency::Token(token_id) => Some((token_id, amount)),
        })
        .collect_vec();
    assert!(token_balances.len() <= 1);
    let token_amount = token_balances
        .first()
        .map_or(Amount::ZERO, |(_token_id, token_amount)| *token_amount);
    assert_eq!(
        token_amount,
        (token_amount_to_issue - tokens_to_transfer).expect("")
    );

    let not_enough_tokens_to_transfer =
        Amount::from_atoms(rng.gen_range(
            token_amount_to_issue.into_atoms()..=token_amount_to_issue.into_atoms() + 100,
        ));

    let some_other_address = PublicKeyHash::from_low_u64_be(1);
    let new_output = TxOutput::Transfer(
        OutputValue::Token(Box::new(TokenData::TokenTransfer(TokenTransfer {
            token_id: *token_id,
            amount: not_enough_tokens_to_transfer,
        }))),
        Destination::Address(some_other_address),
    );

    let transfer_tokens_error = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .err()
        .unwrap();

    assert_eq!(
        transfer_tokens_error,
        WalletError::CoinSelectionError(UtxoSelectorError::NotEnoughFunds(
            (token_amount_to_issue - tokens_to_transfer).unwrap(),
            not_enough_tokens_to_transfer
        ))
    )
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_then_transfer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    let timestamp = chain_config.genesis_block().timestamp().add_int_seconds(10).unwrap();

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        timestamp,
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address.clone(),
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    let seconds_between_blocks = rng.gen_range(10..100);
    let block1_id = block1.get_id();
    // not important that it is not the actual median
    wallet.set_median_time(timestamp).unwrap();
    let timestamp = block1.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    // check balance
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let destination = address2.decode_object(chain_config.as_ref()).unwrap();
    let amount_fraction = (block1_amount.into_atoms() - NETWORK_FEE) / 10;

    let block_count_lock = rng.gen_range(1..10);
    let amount_to_lock_then_transfer = Amount::from_atoms(rng.gen_range(1..amount_fraction));
    let new_output = gen_random_lock_then_transfer(
        &mut rng,
        amount_to_lock_then_transfer,
        destination,
        block_count_lock,
        BlockHeight::new(2),
        seconds_between_blocks,
        timestamp,
    );

    let lock_then_transfer_transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();
    wallet
        .add_unconfirmed_tx(lock_then_transfer_transaction.clone(), &WalletEventsNoOp)
        .unwrap();

    let block2 = Block::new(
        vec![lock_then_transfer_transaction],
        block1_id.into(),
        timestamp,
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    // not important that it is not the actual median
    wallet.set_median_time(timestamp).unwrap();
    let mut timestamp = block2.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);

    // check balance
    let balance_without_locked_transer =
        ((block1_amount * 2).unwrap() - amount_to_lock_then_transfer).unwrap();

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        balance_without_locked_transer
    );

    // check that for block_count_lock, the amount is not included
    for idx in 0..block_count_lock {
        let currency_balances = wallet
            .get_balance(
                DEFAULT_ACCOUNT_INDEX,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                UtxoState::Confirmed.into(),
                WithLocked::Unlocked,
            )
            .unwrap();
        // check that the amount is still not unlocked
        assert_eq!(
            currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
            balance_without_locked_transer
        );

        let currency_balances = wallet
            .get_balance(
                DEFAULT_ACCOUNT_INDEX,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                UtxoState::Confirmed.into(),
                WithLocked::Locked,
            )
            .unwrap();
        // check that the amount is still locked
        assert_eq!(
            currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
            amount_to_lock_then_transfer
        );

        let new_block = Block::new(
            vec![],
            chain_config.genesis_block_id(),
            timestamp,
            ConsensusData::None,
            BlockReward::new(vec![]),
        )
        .unwrap();
        // not important that it is not the actual median
        wallet.set_median_time(timestamp).unwrap();
        timestamp = new_block.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
        scan_wallet(&mut wallet, BlockHeight::new(2 + idx), vec![new_block]);
    }

    // check that after block_count_lock, the amount is included
    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        (balance_without_locked_transer + amount_to_lock_then_transfer).unwrap()
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_multiple_transactions_in_single_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let blocks_to_add = rng.gen_range(1..10);

    let mut amounts = vec![];
    for i in 0..blocks_to_add {
        // Generate a new block which sends reward to the wallet
        let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 1..NETWORK_FEE + 10000));
        let address = get_address(
            &chain_config,
            MNEMONIC,
            DEFAULT_ACCOUNT_INDEX,
            KeyPurpose::ReceiveFunds,
            i.try_into().unwrap(),
        );
        let block1 = Block::new(
            vec![],
            chain_config.genesis_block_id(),
            chain_config.genesis_block().timestamp(),
            ConsensusData::None,
            BlockReward::new(vec![make_address_output(
                chain_config.as_ref(),
                address,
                block1_amount,
            )
            .unwrap()]),
        )
        .unwrap();

        scan_wallet(&mut wallet, BlockHeight::new(i as u64), vec![block1]);
        amounts.push(block1_amount);
    }

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    let total_balance = amounts.iter().cloned().sum::<Option<Amount>>().unwrap();
    assert_eq!(coin_balance, total_balance);

    let mut used_inputs = BTreeSet::new();
    let mut transactions = vec![];
    let mut total_change = Amount::ZERO;

    for block_amount in amounts {
        let amount_to_transfer = rng.gen_range(1..=block_amount.into_atoms());
        let amount_to_transfer = Amount::from_atoms(amount_to_transfer);
        let change = (block_amount - amount_to_transfer).unwrap();

        total_change = (total_change + change).unwrap();

        let new_output = TxOutput::Transfer(
            OutputValue::Coin(amount_to_transfer),
            Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(
                    &mut rng,
                    crypto::key::KeyKind::Secp256k1Schnorr,
                )
                .1,
            ),
        );

        let transaction = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                vec![new_output],
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap();
        wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push(transaction);
        wallet.scan_mempool(transactions.as_slice(), &WalletEventsNoOp).unwrap();
    }

    let block = Block::new(
        transactions,
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    scan_wallet(
        &mut wallet,
        BlockHeight::new(blocks_to_add as u64),
        vec![block],
    );

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, total_change);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_scan_multiple_transactions_from_mempool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    let num_transactions_to_scan_from_mempool = rng.gen_range(1..5);

    let total_num_transactions: u32 = num_transactions_to_scan_from_mempool + 1;

    // Generate a new block which sends reward to the wallet
    // with enough coins for the total transactions
    let block1_amount = Amount::from_atoms(rng.gen_range(
        (NETWORK_FEE + 1) * (total_num_transactions as u128)
            ..=(NETWORK_FEE + 1) * (total_num_transactions as u128) + 10000,
    ));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1.clone()]);

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    // create 3 transactions that depend on each other
    let mut used_inputs = BTreeSet::new();
    let mut transactions = vec![];
    let mut total_amount = block1_amount;

    for idx in 1..(num_transactions_to_scan_from_mempool - 1) {
        let amount_to_transfer = Amount::from_atoms(rng.gen_range(
            1..=(total_amount.into_atoms() - (num_transactions_to_scan_from_mempool - idx) as u128),
        ));
        let change = (total_amount - amount_to_transfer).unwrap();

        let address = get_address(
            &chain_config,
            MNEMONIC,
            DEFAULT_ACCOUNT_INDEX,
            KeyPurpose::ReceiveFunds,
            (idx + 1).try_into().unwrap(),
        );
        let change_output = make_address_output(chain_config.as_ref(), address, change).unwrap();

        let new_output = TxOutput::Transfer(
            OutputValue::Coin(amount_to_transfer),
            Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(
                    &mut rng,
                    crypto::key::KeyKind::Secp256k1Schnorr,
                )
                .1,
            ),
        );

        let transaction = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                vec![new_output, change_output],
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap();

        wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push(transaction);
        total_amount = change;
    }

    assert!(total_amount.into_atoms() > 1);
    let amount_to_transfer = rng.gen_range(1..total_amount.into_atoms());
    let amount_to_keep = (total_amount - Amount::from_atoms(amount_to_transfer)).unwrap();

    // Last transaction doesn't have wallets's outputs so the wallet will need to identify it by
    // the inputs which also come from another transaction in the mempool
    let new_output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(amount_to_transfer)),
        Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr)
                .1,
        ),
    );
    let transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();
    wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

    for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
        // assert the utxos used in this transaction have not been used before
        assert!(used_inputs.insert(utxo.clone()));
    }

    transactions.push(transaction);
    wallet.scan_mempool(transactions.as_slice(), &WalletEventsNoOp).unwrap();

    // create new wallet
    let mut wallet = create_wallet(chain_config);

    // scan the first block
    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    // scan mempool transaction in random order
    transactions.shuffle(&mut rng);
    wallet.scan_mempool(transactions.as_slice(), &WalletEventsNoOp).unwrap();

    // Should fail to spend more than we have
    let should_fail_to_send = (amount_to_keep + Amount::from_atoms(1)).unwrap();
    let new_output = TxOutput::Transfer(
        OutputValue::Coin(should_fail_to_send),
        Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr)
                .1,
        ),
    );
    let err = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(
        err,
        WalletError::CoinSelectionError(UtxoSelectorError::NotEnoughFunds(
            amount_to_keep,
            should_fail_to_send
        ))
    );

    let new_output = TxOutput::Transfer(
        OutputValue::Coin(amount_to_keep),
        Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr)
                .1,
        ),
    );

    let transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            vec![new_output],
            FeeRate::new(Amount::ZERO),
            FeeRate::new(Amount::ZERO),
        )
        .unwrap();
    wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

    let transaction_id = transaction.transaction().get_id();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    wallet.abandon_transaction(DEFAULT_ACCOUNT_INDEX, transaction_id).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, amount_to_keep);

    // if we add it back from the mempool it should return even if abandoned
    wallet.scan_mempool(&[transaction], &WalletEventsNoOp).unwrap();
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_abandone_transactions(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    let total_num_transactions: u32 = rng.gen_range(1..5);

    // Generate a new block which sends reward to the wallet
    // with enough coins for the total transactions
    let block1_amount = Amount::from_atoms(rng.gen_range(
        (NETWORK_FEE + 1) * (total_num_transactions as u128)
            ..=(NETWORK_FEE + 1) * (total_num_transactions as u128) + 10000,
    ));
    let address = get_address(
        &chain_config,
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(
            chain_config.as_ref(),
            address,
            block1_amount,
        )
        .unwrap()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    // create multiple transactions that depend on each other
    let mut used_inputs = BTreeSet::new();
    let mut transactions = vec![];
    let mut total_amount = block1_amount;

    for idx in 0..total_num_transactions {
        let amount_to_transfer = Amount::from_atoms(
            rng.gen_range(1..=(total_amount.into_atoms() - (total_num_transactions - idx) as u128)),
        );
        let change = (total_amount - amount_to_transfer).unwrap();

        let address = get_address(
            &chain_config,
            MNEMONIC,
            DEFAULT_ACCOUNT_INDEX,
            KeyPurpose::ReceiveFunds,
            (idx + 1).try_into().unwrap(),
        );
        let change_output = make_address_output(chain_config.as_ref(), address, change).unwrap();

        let new_output = TxOutput::Transfer(
            OutputValue::Coin(amount_to_transfer),
            Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(
                    &mut rng,
                    crypto::key::KeyKind::Secp256k1Schnorr,
                )
                .1,
            ),
        );

        let transaction = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                vec![new_output, change_output],
                FeeRate::new(Amount::ZERO),
                FeeRate::new(Amount::ZERO),
            )
            .unwrap();
        wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push((transaction, total_amount));
        total_amount = change;
    }

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, total_amount);

    let abandonable_transactions = wallet.pending_transactions(DEFAULT_ACCOUNT_INDEX).unwrap();

    assert_eq!(abandonable_transactions.len(), transactions.len());

    let txs_to_abandone = rng.gen_range(0..total_num_transactions) as usize;
    let (txs_to_keep, txs_to_abandone) = transactions.split_at(txs_to_abandone);

    assert!(!txs_to_abandone.is_empty());

    let transaction_id = txs_to_abandone.first().unwrap().0.transaction().get_id();
    wallet.abandon_transaction(DEFAULT_ACCOUNT_INDEX, transaction_id).unwrap();

    let coins_after_abandon = txs_to_abandone.first().unwrap().1;

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, coins_after_abandon);

    let txs_to_keep: Vec<_> = txs_to_keep.iter().map(|(tx, _)| tx.clone()).collect();
    wallet.scan_mempool(txs_to_keep.as_slice(), &WalletEventsNoOp).unwrap();
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, coins_after_abandon);
}
