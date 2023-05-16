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

use crate::key_chain::{make_account_path, LOOKAHEAD_SIZE};

use super::*;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward},
        config::{create_mainnet, create_regtest, Builder, ChainType},
        timelock::OutputTimeLock,
        tokens::OutputValue,
        Destination, Genesis,
    },
};
use crypto::key::hdkd::{
    child_number::ChildNumber, derivable::Derivable, derivation_path::DerivationPath,
};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;

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

    let mut wallet =
        Wallet::new_wallet(Arc::clone(&chain_config), Arc::clone(&db), MNEMONIC, None).unwrap();
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, expected_balance);
    drop(wallet);

    let wallet = Wallet::load_wallet(chain_config, db).unwrap();
    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, expected_balance);
}

#[test]
fn wallet_creation_in_memory() {
    let chain_config = Arc::new(create_regtest());
    let db = create_wallet_in_memory().unwrap();

    match Wallet::load_wallet(Arc::clone(&chain_config), Arc::clone(&db)) {
        Ok(_) => panic!("Wallet loading should fail"),
        Err(err) => assert_eq!(err, WalletError::WalletNotInitialized),
    }

    let wallet =
        Wallet::new_wallet(Arc::clone(&chain_config), Arc::clone(&db), MNEMONIC, None).unwrap();
    drop(wallet);

    let _wallet = Wallet::load_wallet(chain_config, db).unwrap();
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
            let genesis_output = TxOutput::Transfer(
                OutputValue::Coin(genesis_amount),
                Destination::Address(PublicKeyHash::try_from(&address).unwrap()),
            );

            if address_index.into_u32() == LOOKAHEAD_SIZE {
                test_balance_from_genesis(chain_type, vec![genesis_output], Amount::ZERO);
            } else {
                test_balance_from_genesis(chain_type, vec![genesis_output], genesis_amount);
            }
        }
    }
}

#[test]
fn wallet_balance_block_reward() {
    let chain_config = Arc::new(create_mainnet());

    let db = create_wallet_in_memory().unwrap();

    let mut wallet =
        Wallet::new_wallet(Arc::clone(&chain_config), Arc::clone(&db), MNEMONIC, None).unwrap();
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
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
        common::chain::block::ConsensusData::None,
        BlockReward::new(vec![TxOutput::Transfer(
            OutputValue::Coin(block1_amount),
            Destination::Address(PublicKeyHash::try_from(&address).unwrap()),
        )]),
    )
    .unwrap();
    let block1_id = block1.header().block_id();
    wallet.scan_new_blocks(BlockHeight::new(1), vec![block1]).unwrap();

    // Verify that the first block reward has been received
    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, block1_amount);
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
    assert_eq!(best_block_id, block1_id);
    assert_eq!(best_block_height, BlockHeight::new(1));

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
        common::chain::block::ConsensusData::None,
        BlockReward::new(vec![TxOutput::Transfer(
            OutputValue::Coin(block2_amount),
            Destination::Address(PublicKeyHash::try_from(&address).unwrap()),
        )]),
    )
    .unwrap();
    let block2_id = block2.header().block_id();
    wallet.scan_new_blocks(BlockHeight::new(2), vec![block2]).unwrap();

    // Verify that the second block reward is also received
    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, (block1_amount + block2_amount).unwrap());
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
    assert_eq!(best_block_id, block2_id);
    assert_eq!(best_block_height, BlockHeight::new(2));

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
        common::chain::block::ConsensusData::None,
        BlockReward::new(vec![TxOutput::Transfer(
            OutputValue::Coin(block2_amount_new),
            Destination::Address(PublicKeyHash::try_from(&address).unwrap()),
        )]),
    )
    .unwrap();
    let block2_new_id = block2_new.header().block_id();
    wallet.scan_new_blocks(BlockHeight::new(2), vec![block2_new]).unwrap();

    // Verify that the balance includes outputs from block1 and block2_new, but not block2
    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, (block1_amount + block2_amount_new).unwrap());
    let (best_block_id, best_block_height) = wallet.get_best_block().unwrap();
    assert_eq!(best_block_id, block2_new_id);
    assert_eq!(best_block_height, BlockHeight::new(2));
}
