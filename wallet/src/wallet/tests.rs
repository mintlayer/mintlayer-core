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

use super::*;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_mainnet, create_regtest, Builder, ChainType},
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::OutputValue,
        Destination, Genesis, OutPointSourceId, TxInput,
    },
    primitives::Idable,
};
use crypto::{
    key::hdkd::{child_number::ChildNumber, derivable::Derivable, derivation_path::DerivationPath},
    random::{CryptoRng, Rng},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use wallet_types::{account_info::DEFAULT_ACCOUNT_INDEX, utxo_types::UtxoType};

// TODO: Many of these tests require randomization...

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn get_address(
    chain_config: &ChainConfig,
    mnemonic: &str,
    account_index: U31,
    purpose: KeyPurpose,
    address_index: U31,
) -> Address {
    let root_key = MasterKeyChain::mnemonic_to_root_key(mnemonic, None).unwrap();
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
    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
    assert_eq!(coin_balance, expected_balance);

    // Loading a copy of the wallet from the same DB should be safe because loading is an R/O operation
    let db_copy = wallet.db.clone();
    let wallet = Wallet::load_wallet(Arc::clone(chain_config), db_copy).unwrap();
    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
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

    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

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
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
    assert_eq!(coin_balance, genesis_amount);

    let password = gen_random_password(&mut rng);
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet();

    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
    assert_eq!(coin_balance, genesis_amount);
}

#[test]
fn wallet_balance_block_reward() {
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
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
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

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
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

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
        vec![TxInput::new(OutPointSourceId::Transaction(transaction_id1), 0)],
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
    let mut wallet = Wallet::load_wallet(Arc::clone(chain_config), db_copy).unwrap();
    let accounts = wallet.account_indexes().cloned().collect::<Vec<_>>();
    assert_eq!(accounts, expected_accounts);

    for account_index in expected_accounts {
        wallet.create_account(account_index).expect_err("Account should already exist");
    }
}

#[test]
fn wallet_accounts_creation() {
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    test_wallet_accounts(&chain_config, &wallet, vec![]);

    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();
    test_wallet_accounts(&chain_config, &wallet, vec![DEFAULT_ACCOUNT_INDEX]);

    wallet.create_account(1.try_into().unwrap()).unwrap();
    test_wallet_accounts(
        &chain_config,
        &wallet,
        vec![DEFAULT_ACCOUNT_INDEX, 1.try_into().unwrap()],
    );

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    wallet.create_account(123.try_into().unwrap()).unwrap();
    test_wallet_accounts(&chain_config, &wallet, vec![123.try_into().unwrap()]);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_accounts_creation_fail(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    let password = gen_random_password(&mut rng);
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet();

    let err = wallet.create_account(rng.gen_range(0..1 << 31).try_into().unwrap());
    assert_eq!(
        err,
        Err(WalletError::KeyChainError(KeyChainError::DatabaseError(
            wallet_storage::Error::WalletLocked()
        )))
    );

    // success after unlock
    wallet.unlock_wallet(&password).unwrap();
    wallet.create_account(rng.gen_range(0..1 << 31).try_into().unwrap()).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_wallet_cant_sign_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();
    let mut wallet = Wallet::new_wallet(Arc::clone(&chain_config), db, MNEMONIC, None).unwrap();
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
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

    let password = gen_random_password(&mut rng);
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet();

    let (coin_balance, _) = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer,
        )
        .unwrap();
    assert_eq!(coin_balance, block1_amount);

    let new_output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(
            rng.gen_range(1..block1_amount.into_atoms() - NETWORK_FEE),
        )),
        Destination::AnyoneCanSpend,
    );

    assert_eq!(
        wallet.create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output.clone()]),
        Err(WalletError::KeyChainError(KeyChainError::DatabaseError(
            wallet_storage::Error::WalletLocked()
        )))
    );

    // success after unlock
    wallet.unlock_wallet(&password).unwrap();
    wallet
        .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, vec![new_output])
        .unwrap();
}

const NETWORK_FEE: u128 = 10000;

fn gen_random_password(rng: &mut (impl Rng + CryptoRng)) -> Option<String> {
    let new_password: String = (0..rng.gen_range(0..100)).map(|_| rng.gen::<char>()).collect();
    if new_password.is_empty() {
        Some(new_password)
    } else {
        None
    }
}
