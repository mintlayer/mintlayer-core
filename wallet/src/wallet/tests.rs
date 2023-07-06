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
    send_request::make_address_output,
    DefaultWallet,
};
use std::collections::BTreeSet;

use super::*;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_mainnet, create_regtest, Builder, ChainType},
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::{OutputValue, TokenData, TokenIssuance, TokenTransfer},
        Destination, Genesis, OutPointSourceId, TxInput,
    },
    primitives::Idable,
};
use crypto::{
    key::hdkd::{child_number::ChildNumber, derivable::Derivable, derivation_path::DerivationPath},
    random::{CryptoRng, Rng, SliceRandom},
};
use itertools::Itertools;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use wallet_storage::WalletStorageEncryptionRead;
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    utxo_types::{UtxoState, UtxoType},
};

// TODO: Many of these tests require randomization...

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const NETWORK_FEE: u128 = 10000;

fn gen_random_password(rng: &mut (impl Rng + CryptoRng)) -> String {
    (0..rng.gen_range(1..100)).map(|_| rng.gen::<char>()).collect()
}

fn gen_random_lock_then_transfer(
    rng: &mut (impl Rng + CryptoRng),
    amount: Amount,
    pkh: PublicKeyHash,
    lock_for_blocks: u64,
    current_block_height: BlockHeight,
    seconds_between_blocks: u64,
    current_timestamp: BlockTimestamp,
) -> TxOutput {
    match rng.gen_range(0..4) {
        0 => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            Destination::Address(pkh),
            OutputTimeLock::ForBlockCount(lock_for_blocks),
        ),
        1 => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            Destination::Address(pkh),
            OutputTimeLock::UntilHeight(current_block_height.checked_add(lock_for_blocks).unwrap()),
        ),
        2 => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            Destination::Address(pkh),
            OutputTimeLock::ForSeconds(seconds_between_blocks * lock_for_blocks),
        ),
        _ => TxOutput::LockThenTransfer(
            OutputValue::Coin(amount),
            Destination::Address(pkh),
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
) -> Address {
    let (root_key, _root_vrf_key) = MasterKeyChain::mnemonic_to_root_key(mnemonic, None).unwrap();
    let mut address_path = make_account_path(chain_config, account_index).into_vec();
    address_path.push(purpose.get_deterministic_index());
    address_path.push(ChildNumber::from_normal(address_index));
    let address_priv_key = root_key
        .derive_absolute_path(&DerivationPath::try_from(address_path).unwrap())
        .unwrap();
    Address::from_public_key(
        chain_config,
        &address_priv_key.to_public_key().into_public_key(),
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
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, expected_balance);

    // Loading a copy of the wallet from the same DB should be safe because loading is an R/O operation
    let db_copy = wallet.db.clone();
    let wallet = Wallet::load_wallet(Arc::clone(chain_config), db_copy).unwrap();
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    // Check that the loaded wallet has the same balance
    assert_eq!(coin_balance, expected_balance);
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

    let db = create_wallet_in_memory().unwrap();

    let wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    verify_wallet_balance(&chain_config, &wallet, expected_balance);
}

#[test]
fn wallet_creation_in_memory() {
    let chain_config = Arc::new(create_regtest());
    let empty_db = create_wallet_in_memory().unwrap();

    // fail to load an empty wallet
    match Wallet::load_wallet(Arc::clone(&chain_config), empty_db) {
        Ok(_) => panic!("Wallet loading should fail"),
        Err(err) => assert_eq!(err, WalletError::WalletNotInitialized),
    }

    let empty_db = create_wallet_in_memory().unwrap();
    // initialize a new wallet with mnemonic
    let wallet = Wallet::new_wallet(Arc::clone(&chain_config), empty_db, MNEMONIC, None).unwrap();
    let initialized_db = wallet.db;

    // successfully load a wallet from initialized db
    let _wallet = Wallet::load_wallet(chain_config, initialized_db).unwrap();
}

#[test]
fn wallet_balance_genesis() {
    let chain_type = ChainType::Mainnet;

    let genesis_amount = Amount::from_atoms(12345);
    let genesis_output = TxOutput::Transfer(
        OutputValue::Coin(genesis_amount),
        Destination::AnyoneCanSpend,
    );

    test_balance_from_genesis(chain_type, vec![genesis_output.clone()], genesis_amount);

    let genesis_amount_2 = Amount::from_atoms(54321);
    let genesis_output_2 = TxOutput::LockThenTransfer(
        OutputValue::Coin(genesis_amount_2),
        Destination::AnyoneCanSpend,
        OutputTimeLock::UntilHeight(BlockHeight::zero()),
    );

    test_balance_from_genesis(
        chain_type,
        vec![genesis_output, genesis_output_2],
        (genesis_amount + genesis_amount_2).unwrap(),
    );

    let address_indexes = [0, LOOKAHEAD_SIZE - 1, LOOKAHEAD_SIZE];
    let chain_config = Arc::new(Builder::new(chain_type).build());
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
            let genesis_output = make_address_output(address, genesis_amount).unwrap();

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
    let genesis_output = TxOutput::Transfer(
        OutputValue::Coin(genesis_amount),
        Destination::AnyoneCanSpend,
    );
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        vec![genesis_output],
    );
    let chain_config = Arc::new(Builder::new(chain_type).genesis_custom(genesis).build());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);

    assert_eq!(coin_balance, Amount::ZERO);
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
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
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();
    let block1_id = block1.header().block_id();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    // Verify that the first block reward has been received
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
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
        BlockReward::new(vec![make_address_output(address, block2_amount).unwrap()]),
    )
    .unwrap();
    let block2_id = block2.header().block_id();
    wallet.scan_new_blocks(BlockHeight::new(1), vec![block2]).unwrap();

    // Verify that the second block reward is also received
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
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
        BlockReward::new(vec![
            make_address_output(address, block2_amount_new).unwrap()
        ]),
    )
    .unwrap();
    let block2_new_id = block2_new.header().block_id();
    wallet.scan_new_blocks(BlockHeight::new(1), vec![block2_new]).unwrap();

    // Verify that the balance includes outputs from block1 and block2_new, but not block2
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
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

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

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
        vec![make_address_output(address, tx_amount1).unwrap()],
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

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    verify_wallet_balance(&chain_config, &wallet, tx_amount1);
}

#[test]
// Verify that outputs can be created and consumed in the same block
fn wallet_balance_parent_child_transactions() {
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

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
        vec![make_address_output(address1, tx_amount1).unwrap()],
    )
    .unwrap();
    let transaction_id1 = transaction1.get_id();
    let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();

    let transaction2 = Transaction::new(
        0,
        vec![TxInput::from_utxo(OutPointSourceId::Transaction(transaction_id1), 0)],
        vec![make_address_output(address2, tx_amount2).unwrap()],
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

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

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
    let wallet = Wallet::load_wallet(Arc::clone(chain_config), db_copy).unwrap();
    let accounts = wallet.account_indexes().cloned().collect::<Vec<_>>();
    assert_eq!(accounts, expected_accounts);
}

#[test]
fn wallet_accounts_creation() {
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    test_wallet_accounts(&chain_config, &wallet, vec![DEFAULT_ACCOUNT_INDEX]);

    let error = wallet.create_account(None).err().unwrap();
    assert_eq!(error, WalletError::EmptyLastAccount);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_accounts_creation_fail(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

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
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();
    let password = Some(gen_random_password(&mut rng));
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet().unwrap();

    let err = wallet.create_account(None);
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
        let err = wallet.create_account(Some(name));
        assert_eq!(err, Err(WalletError::EmptyAccountName));
    } else {
        let (new_account_index, new_name) = wallet.create_account(Some(name.clone())).unwrap();
        assert_ne!(new_account_index, DEFAULT_ACCOUNT_INDEX);
        assert_eq!(new_name.unwrap(), name);
        assert_eq!(wallet.number_of_accounts(), 2);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_cant_sign_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    let password = Some(gen_random_password(&mut rng));
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet().unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        wallet.create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output.clone()]),
        Err(WalletError::DatabaseError(
            wallet_storage::Error::WalletLocked
        ))
    );

    // success after unlock
    wallet.unlock_wallet(&password.unwrap()).unwrap();
    if rng.gen::<bool>() {
        wallet
            .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
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
            .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
            .unwrap();
    }
}

#[test]
fn lock_wallet_fail_empty_password() {
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
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

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();

    let block1_id = block1.get_id();
    let block1_timestamp = block1.timestamp();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = (block1_amount - Amount::from_atoms(NETWORK_FEE)).unwrap();

    let stake_pool_transaction =
        wallet.create_stake_pool_tx(DEFAULT_ACCOUNT_INDEX, pool_amount, None).unwrap();
    let block2 = Block::new(
        vec![stake_pool_transaction],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    wallet.scan_new_blocks(BlockHeight::new(1), vec![block2]).unwrap();

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::CreateStakePool,
            UtxoState::Confirmed.into(),
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        pool_amount
    );

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(pool_ids.len(), 1);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_transfer_tokens(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        BlockReward::new(vec![
            make_address_output(address.clone(), block1_amount).unwrap()
        ]),
    )
    .unwrap();

    let block1_id = block1.get_id();
    let block1_timestamp = block1.timestamp();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pkh = PublicKeyHash::try_from(address2.data(&chain_config).unwrap()).unwrap();

    let amount_fraction = (block1_amount.into_atoms() - NETWORK_FEE) / 10;

    let token_amount_to_issue = Amount::from_atoms(rng.gen_range(1..amount_fraction));
    let new_output = TxOutput::Transfer(
        OutputValue::Token(Box::new(TokenData::TokenIssuance(Box::new(
            TokenIssuance {
                token_ticker: "XXXX".as_bytes().to_vec(),
                amount_to_issue: token_amount_to_issue,
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: "http://uri".as_bytes().to_vec(),
            },
        )))),
        Destination::Address(pkh),
    );

    let token_issuance_transaction = wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap();

    let block2 = Block::new(
        vec![token_issuance_transaction],
        block1_id.into(),
        block1_timestamp,
        ConsensusData::None,
        BlockReward::new(vec![
            make_address_output(address.clone(), block1_amount).unwrap()
        ]),
    )
    .unwrap();

    wallet.scan_new_blocks(BlockHeight::new(1), vec![block2]).unwrap();

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        ((block1_amount * 2).unwrap() - Amount::from_atoms(NETWORK_FEE)).unwrap()
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
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap();

    let block3 = Block::new(
        vec![transfer_tokens_transaction],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();
    wallet.scan_new_blocks(BlockHeight::new(2), vec![block3]).unwrap();

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap();
    assert_eq!(
        currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
        ((block1_amount * 3).unwrap() - Amount::from_atoms(NETWORK_FEE * 2)).unwrap()
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
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
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

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        BlockReward::new(vec![
            make_address_output(address.clone(), block1_amount).unwrap()
        ]),
    )
    .unwrap();

    let seconds_between_blocks = rng.gen_range(10..100);
    let block1_id = block1.get_id();
    // not important that it is not the actual median
    wallet.set_median_time(timestamp).unwrap();
    let timestamp = block1.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    // check balance
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pkh = PublicKeyHash::try_from(address2.data(&chain_config).unwrap()).unwrap();

    let amount_fraction = (block1_amount.into_atoms() - NETWORK_FEE) / 10;

    let block_count_lock = rng.gen_range(1..10);
    let amount_to_lock_then_transfer = Amount::from_atoms(rng.gen_range(1..amount_fraction));
    let new_output = gen_random_lock_then_transfer(
        &mut rng,
        amount_to_lock_then_transfer,
        pkh,
        block_count_lock,
        BlockHeight::new(2),
        seconds_between_blocks,
        timestamp,
    );

    let lock_then_transfer_transaction = wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap();

    let block2 = Block::new(
        vec![lock_then_transfer_transaction],
        block1_id.into(),
        timestamp,
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();

    // not important that it is not the actual median
    wallet.set_median_time(timestamp).unwrap();
    let mut timestamp = block2.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
    wallet.scan_new_blocks(BlockHeight::new(1), vec![block2]).unwrap();

    // check balance
    let balance_without_locked_transer =
        (((block1_amount * 2).unwrap() - amount_to_lock_then_transfer).unwrap()
            - Amount::from_atoms(NETWORK_FEE))
        .unwrap();

    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
            )
            .unwrap();
        assert_eq!(
            currency_balances.get(&Currency::Coin).copied().unwrap_or(Amount::ZERO),
            balance_without_locked_transer
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
        wallet.scan_new_blocks(BlockHeight::new(2 + idx), vec![new_block]).unwrap();
    }

    // check that after block_count_lock, the amount is included
    let currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
fn wallet_sync_new_account(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let err = wallet.create_account(None).err().unwrap();
    assert_eq!(err, WalletError::EmptyLastAccount);

    let mut total_amount = Amount::ZERO;
    let blocks = (0..rng.gen_range(1..10))
        .map(|idx| {
            let tx_amount1 = Amount::from_atoms(rng.gen_range(1..1000));
            total_amount = (total_amount + tx_amount1).unwrap();
            let address = get_address(
                &chain_config,
                MNEMONIC,
                DEFAULT_ACCOUNT_INDEX,
                KeyPurpose::ReceiveFunds,
                idx.try_into().unwrap(),
            );

            let transaction1 = Transaction::new(
                0,
                Vec::new(),
                vec![make_address_output(address, tx_amount1).unwrap()],
            )
            .unwrap();
            let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();
            Block::new(
                vec![signed_transaction1],
                chain_config.genesis_block_id(),
                chain_config.genesis_block().timestamp(),
                ConsensusData::None,
                BlockReward::new(Vec::new()),
            )
            .unwrap()
        })
        .collect_vec();

    // move old account 1..10 block further then genesis
    wallet.scan_new_blocks(BlockHeight::new(0), blocks.clone()).unwrap();
    verify_wallet_balance(&chain_config, &wallet, total_amount);

    // create new account which is back on genesis
    let (new_account_index, _name) = wallet.create_account(None).unwrap();
    assert_ne!(new_account_index, DEFAULT_ACCOUNT_INDEX);
    assert_eq!(wallet.number_of_accounts(), 2);

    // sync new account with the new block
    for block in blocks {
        // not yet synced
        let err = wallet
            .get_balance(
                new_account_index,
                UtxoType::Transfer.into(),
                UtxoState::Confirmed.into(),
            )
            .err()
            .unwrap();
        assert_eq!(
            err,
            WalletError::AccountNotSyncedWithIndex(new_account_index)
        );

        let (_, block_height) = wallet.get_best_block_for_unsynced_account().unwrap();
        wallet.scan_new_blocks_for_unsynced_account(block_height, vec![block]).unwrap();
    }
    // now both account are in sync and can be used
    let coin_balance = wallet
        .get_balance(
            new_account_index,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
fn wallet_multiple_transactions_in_single_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

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
            BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
        )
        .unwrap();

        wallet.scan_new_blocks(BlockHeight::new(i as u64), vec![block1]).unwrap();
        amounts.push(block1_amount);
    }

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        let amount_to_transfer = rng.gen_range(1..=block_amount.into_atoms() - NETWORK_FEE);
        let amount_to_transfer = Amount::from_atoms(amount_to_transfer);
        let change = ((block_amount - amount_to_transfer).unwrap()
            - Amount::from_atoms(NETWORK_FEE))
        .unwrap();

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
            .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
            .unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push(transaction);
        wallet.scan_mempool(transactions.as_slice()).unwrap();
    }

    let block = Block::new(
        transactions,
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    wallet
        .scan_new_blocks(BlockHeight::new(blocks_to_add as u64), vec![block])
        .unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1.clone()]).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        let amount_to_transfer = (total_amount - Amount::from_atoms(NETWORK_FEE)).unwrap();

        let address = get_address(
            &chain_config,
            MNEMONIC,
            DEFAULT_ACCOUNT_INDEX,
            KeyPurpose::ReceiveFunds,
            idx.try_into().unwrap(),
        );
        let new_output = make_address_output(address, amount_to_transfer).unwrap();

        let transaction = wallet
            .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
            .unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push(transaction);
        total_amount = amount_to_transfer;
    }

    assert!(total_amount.into_atoms() > (NETWORK_FEE + 1) * 2);
    let amount_to_keep =
        rng.gen_range((NETWORK_FEE + 1)..=(total_amount.into_atoms() - NETWORK_FEE));
    let amount_to_transfer =
        (total_amount - Amount::from_atoms(amount_to_keep + NETWORK_FEE)).unwrap();

    // Last transaction doesn't have wallets's outputs so the wallet will need to identify it by
    // the inputs which also come from another transaction in the mempool
    let new_output = TxOutput::Transfer(
        OutputValue::Coin(amount_to_transfer),
        Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr)
                .1,
        ),
    );
    let transaction = wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap();

    for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
        // assert the utxos used in this transaction have not been used before
        assert!(used_inputs.insert(utxo.clone()));
    }

    transactions.push(transaction);
    wallet.scan_mempool(transactions.as_slice()).unwrap();

    // create new wallet
    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    // scan the first block
    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    // scan mempool transaction in random order
    transactions.shuffle(&mut rng);
    wallet.scan_mempool(transactions.as_slice()).unwrap();

    // wallet should now have amount_to_keep left as unconfirmed balance to spend
    let total_amount_without_network_fee = Amount::from_atoms(amount_to_keep - NETWORK_FEE);

    // Should fail to spend more than we have
    let should_fail_to_send = (total_amount_without_network_fee + Amount::from_atoms(1)).unwrap();
    let new_output = TxOutput::Transfer(
        OutputValue::Coin(should_fail_to_send),
        Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr)
                .1,
        ),
    );
    let err = wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap_err();
    assert_eq!(
        err,
        WalletError::CoinSelectionError(UtxoSelectorError::NotEnoughFunds(
            (total_amount_without_network_fee + Amount::from_atoms(NETWORK_FEE)).unwrap(),
            (should_fail_to_send + Amount::from_atoms(NETWORK_FEE)).unwrap()
        ))
    );

    let new_output = TxOutput::Transfer(
        OutputValue::Coin(total_amount_without_network_fee),
        Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr)
                .1,
        ),
    );

    let transaction = wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap();

    let transaction_id = transaction.transaction().get_id();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
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
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::from_atoms(amount_to_keep));

    // if we add it back from the mempool it should return even if abandoned
    wallet.scan_mempool(&[transaction]).unwrap();
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
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

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        BlockReward::new(vec![make_address_output(address, block1_amount).unwrap()]),
    )
    .unwrap();

    wallet.scan_new_blocks(BlockHeight::new(0), vec![block1]).unwrap();

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed.into(),
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
        let amount_to_transfer = (total_amount - Amount::from_atoms(NETWORK_FEE)).unwrap();

        let address = get_address(
            &chain_config,
            MNEMONIC,
            DEFAULT_ACCOUNT_INDEX,
            KeyPurpose::ReceiveFunds,
            (idx + 1).try_into().unwrap(),
        );
        let new_output = make_address_output(address, amount_to_transfer).unwrap();

        let transaction = wallet
            .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
            .unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push((transaction, total_amount));
        total_amount = amount_to_transfer;
    }

    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
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
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, coins_after_abandon);

    let txs_to_keep: Vec<_> = txs_to_keep.iter().map(|(tx, _)| tx.clone()).collect();
    wallet.scan_mempool(txs_to_keep.as_slice()).unwrap();
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
            UtxoState::Confirmed | UtxoState::InMempool,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, coins_after_abandon);
}
