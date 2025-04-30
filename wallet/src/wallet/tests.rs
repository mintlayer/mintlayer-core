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

use std::{
    collections::BTreeSet,
    num::{NonZeroU8, NonZeroUsize},
};

use itertools::Itertools;
use rstest::rstest;

use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_mainnet, create_regtest, create_unit_test_config, Builder, ChainType},
        output_value::{OutputValue, RpcOutputValue},
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{RPCIsTokenFrozen, TokenData, TokenIssuanceV0, TokenIssuanceV1},
        AccountSpending, ChainstateUpgradeBuilder, Destination, Genesis, OutPointSourceId, TxInput,
    },
    primitives::{per_thousand::PerThousand, Idable, H256},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, derivable::Derivable, derivation_path::DerivationPath},
        KeyKind,
    },
    vrf::transcript::no_rng::VRFTranscript,
};
use randomness::{CryptoRng, Rng, SliceRandom};
use serialization::{extras::non_empty_vec::DataOrNoVec, hex::HexEncode, Encode};
use storage::raw::DbMapId;
use test_utils::{
    assert_matches, assert_matches_return_val,
    nft_utils::random_token_issuance_v1,
    random::{make_seedable_rng, Seed},
};
use wallet_storage::{schema, WalletStorageEncryptionRead};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    partially_signed_transaction::{
        PartiallySignedTransaction, PartiallySignedTransactionCreationError, TxAdditionalInfo,
    },
    seed_phrase::{PassPhrase, StoreSeedPhrase},
    utxo_types::{UtxoState, UtxoType},
    AccountWalletTxId, Currency, WalletTx,
};

use crate::{
    key_chain::{make_account_path, LOOKAHEAD_SIZE},
    send_request::{make_address_output, make_create_delegation_output},
    signer::software_signer::SoftwareSignerProvider,
    wallet_events::WalletEventsNoOp,
    DefaultWallet,
};

use super::*;

// TODO: Many of these tests require randomization...

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const MNEMONIC2: &str =
    "disease woman cave illness sample crew swamp robust crumble infant news sign liquid rigid alter";

const NETWORK_FEE: u128 = 10000;

fn get_best_block<B, P>(wallet: &Wallet<B, P>) -> (Id<GenBlock>, BlockHeight)
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    *wallet.get_best_block().first_key_value().unwrap().1
}

#[track_caller]
fn scan_wallet<B, P>(wallet: &mut Wallet<B, P>, height: BlockHeight, blocks: Vec<Block>)
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
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
        crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1,
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
        Destination::PublicKey(address_priv_key.to_public_key().into_public_key()),
    )
    .unwrap()
}

fn get_coin_balance_for_acc<B, P>(wallet: &Wallet<B, P>, account: U31) -> Amount
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let coin_balance = wallet
        .get_balance(account, UtxoState::Confirmed.into(), WithLocked::Unlocked)
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    coin_balance
}

fn get_coin_balance_with_inactive<B, P>(wallet: &Wallet<B, P>) -> Amount
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let coin_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoState::Confirmed | UtxoState::Inactive | UtxoState::InMempool,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    coin_balance
}

fn get_balance_with(
    wallet: &DefaultWallet,
    currency: Currency,
    utxo_states: UtxoStates,
    with_locked: WithLocked,
) -> Amount {
    let coin_balance = wallet
        .get_balance(DEFAULT_ACCOUNT_INDEX, utxo_states, with_locked)
        .unwrap()
        .get(&currency)
        .copied()
        .unwrap_or(Amount::ZERO);
    coin_balance
}

fn get_coin_balance<B, P>(wallet: &Wallet<B, P>) -> Amount
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    get_coin_balance_for_acc(wallet, DEFAULT_ACCOUNT_INDEX)
}

fn get_currency_balances<B, P>(wallet: &Wallet<B, P>) -> (Amount, Vec<(TokenId, Amount)>)
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let mut currency_balances = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();

    let coins = currency_balances.remove(&Currency::Coin).unwrap_or(Amount::ZERO);

    let token_balances = currency_balances
        .into_iter()
        .filter_map(|(c, amount)| match c {
            Currency::Coin => None,
            Currency::Token(token_id) => Some((token_id, amount)),
        })
        .collect_vec();
    (coins, token_balances)
}

#[track_caller]
fn verify_wallet_balance<B, P>(
    chain_config: &Arc<ChainConfig>,
    wallet: &Wallet<B, P>,
    expected_balance: Amount,
) where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let coin_balance = get_coin_balance(wallet);
    assert_eq!(coin_balance, expected_balance);

    // Loading a copy of the wallet from the same DB should be safe because loading is an R/O operation
    let db_copy = wallet.db.clone();
    let wallet = Wallet::load_wallet(
        Arc::clone(chain_config),
        db_copy,
        None,
        |_| Ok(()),
        WalletControllerMode::Hot,
        false,
        |db_tx| SoftwareSignerProvider::load_from_database(chain_config.clone(), db_tx),
    )
    .unwrap()
    .wallet()
    .unwrap();

    wallet.get_best_block();

    let coin_balance = get_coin_balance(&wallet);
    // Check that the loaded wallet has the same balance
    assert_eq!(coin_balance, expected_balance);
}

#[track_caller]
fn create_wallet(chain_config: Arc<ChainConfig>) -> DefaultWallet {
    create_wallet_with_mnemonic(chain_config, MNEMONIC)
}

#[track_caller]
fn create_wallet_with_mnemonic(chain_config: Arc<ChainConfig>, mnemonic: &str) -> DefaultWallet {
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    Wallet::create_new_wallet(
        chain_config.clone(),
        db,
        (BlockHeight::new(0), genesis_block_id),
        WalletType::Hot,
        |db_tx| {
            Ok(SoftwareSignerProvider::new_from_mnemonic(
                chain_config,
                db_tx,
                mnemonic,
                None,
                StoreSeedPhrase::DoNotStore,
            )?)
        },
    )
    .unwrap()
    .wallet()
    .unwrap()
}

#[track_caller]
fn create_block<B, P>(
    chain_config: &Arc<ChainConfig>,
    wallet: &mut Wallet<B, P>,
    transactions: Vec<SignedTransaction>,
    reward: Amount,
    block_height: u64,
) -> (Address<Destination>, Block)
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let block1 = Block::new(
        transactions,
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(address.clone(), reward)]),
    )
    .unwrap();

    scan_wallet(wallet, BlockHeight::new(block_height), vec![block1.clone()]);
    (address, block1)
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
    let chain_config = Arc::new(
        Builder::new(chain_type)
            .genesis_custom(genesis)
            // Force empty checkpoints because a custom genesis is used.
            .checkpoints(BTreeMap::new())
            .build(),
    );

    let wallet = create_wallet(chain_config.clone());

    verify_wallet_balance(&chain_config, &wallet, expected_balance);
}

#[test]
fn wallet_creation_in_memory() {
    let chain_config = Arc::new(create_regtest());
    let empty_db = create_wallet_in_memory().unwrap();
    let chain_config2 = chain_config.clone();

    // fail to load an empty wallet
    match Wallet::load_wallet(
        Arc::clone(&chain_config),
        empty_db,
        None,
        |_| Ok(()),
        WalletControllerMode::Hot,
        false,
        |db_tx| SoftwareSignerProvider::load_from_database(chain_config2, db_tx),
    ) {
        Ok(_) => panic!("Wallet loading should fail"),
        Err(err) => assert_eq!(err, WalletError::WalletNotInitialized),
    }

    // initialize a new wallet with mnemonic
    let wallet = create_wallet(chain_config.clone());
    let initialized_db = wallet.db;

    // successfully load a wallet from initialized db
    let _wallet = Wallet::load_wallet(
        chain_config.clone(),
        initialized_db,
        None,
        |_| Ok(()),
        WalletControllerMode::Hot,
        false,
        |db_tx| SoftwareSignerProvider::load_from_database(chain_config.clone(), db_tx),
    )
    .unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_migration_to_v2(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let address = get_address(
        &create_regtest(),
        MNEMONIC,
        DEFAULT_ACCOUNT_INDEX,
        KeyPurpose::ReceiveFunds,
        0.try_into().unwrap(),
    );
    let genesis_amount = Amount::from_atoms(100);
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        vec![TxOutput::Transfer(OutputValue::Coin(genesis_amount), address.into_object())],
    );
    let chain_type = ChainType::Regtest;
    let chain_config = Arc::new(Builder::new(chain_type).genesis_custom(genesis).build());
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    let mut wallet = Wallet::create_new_wallet(
        Arc::clone(&chain_config),
        db,
        (BlockHeight::new(0), genesis_block_id),
        WalletType::Hot,
        |db_tx| {
            Ok(SoftwareSignerProvider::new_from_mnemonic(
                chain_config.clone(),
                db_tx,
                MNEMONIC,
                None,
                StoreSeedPhrase::DoNotStore,
            )?)
        },
    )
    .unwrap()
    .wallet()
    .unwrap();

    verify_wallet_balance(&chain_config, &wallet, genesis_amount);

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

    let wallet = Wallet::load_wallet(
        Arc::clone(&chain_config),
        new_db,
        password,
        |_| Ok(()),
        WalletControllerMode::Hot,
        false,
        |db_tx| SoftwareSignerProvider::load_from_database(chain_config.clone(), db_tx),
    )
    .unwrap()
    .wallet()
    .unwrap();

    // Migration has been done and new version is v2
    assert_eq!(
        wallet.db.transaction_ro().unwrap().get_storage_version().unwrap(),
        CURRENT_WALLET_VERSION
    );

    // accounts have been reset back to genesis to rescan the blockchain
    assert_eq!(
        wallet.get_best_block_for_account(DEFAULT_ACCOUNT_INDEX).unwrap(),
        (chain_config.genesis_block_id(), BlockHeight::new(0))
    );
    verify_wallet_balance(&chain_config, &wallet, genesis_amount);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_seed_phrase_retrieval(#[case] seed: Seed) {
    use wallet_types::seed_phrase::SeedPhraseLanguage;

    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    // create wallet without saving the seed phrase
    {
        let wallet = create_wallet(chain_config.clone());
        let seed_phrase = wallet.seed_phrase().unwrap();
        assert!(seed_phrase.is_none());
    }

    let wallet_passphrase: Option<String> = if rng.gen::<bool>() {
        Some(gen_random_password(&mut rng))
    } else {
        None
    };

    // create wallet with saving the seed phrase
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    let mut wallet = Wallet::create_new_wallet(
        Arc::clone(&chain_config),
        db,
        (BlockHeight::new(0), genesis_block_id),
        WalletType::Hot,
        |db_tx| {
            Ok(SoftwareSignerProvider::new_from_mnemonic(
                chain_config.clone(),
                db_tx,
                MNEMONIC,
                wallet_passphrase.as_ref().map(|p| p.as_ref()),
                StoreSeedPhrase::Store,
            )?)
        },
    )
    .unwrap()
    .wallet()
    .unwrap();

    let wallet_passphrase = PassPhrase::new(zeroize::Zeroizing::new(wallet_passphrase));

    {
        let seed_phrase = wallet.seed_phrase().unwrap().unwrap();
        let (seed_phrase_language, seed_phrase, passphrase) = match seed_phrase {
            SerializableSeedPhrase::V0(language, seed_phrase) => (
                language,
                seed_phrase,
                PassPhrase::new(zeroize::Zeroizing::new(None)),
            ),
            SerializableSeedPhrase::V1(language, seed_phrase, passphrase) => {
                (language, seed_phrase, passphrase)
            }
        };
        assert_eq!(seed_phrase.mnemonic().join(" "), MNEMONIC);
        assert_eq!(seed_phrase_language, SeedPhraseLanguage::English);
        assert_eq!(passphrase, wallet_passphrase);
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
        let (seed_phrase_language, seed_phrase, passphrase) = match seed_phrase {
            SerializableSeedPhrase::V0(language, seed_phrase) => (
                language,
                seed_phrase,
                PassPhrase::new(zeroize::Zeroizing::new(None)),
            ),
            SerializableSeedPhrase::V1(language, seed_phrase, passphrase) => {
                (language, seed_phrase, passphrase)
            }
        };
        assert_eq!(seed_phrase.mnemonic().join(" "), MNEMONIC);
        assert_eq!(seed_phrase_language, SeedPhraseLanguage::English);
        assert_eq!(passphrase, wallet_passphrase);
    }

    {
        // Deleting the seed phrase will return it
        let seed_phrase = wallet.delete_seed_phrase().unwrap().unwrap();
        let (seed_phrase_language, seed_phrase, passphrase) = match seed_phrase {
            SerializableSeedPhrase::V0(language, seed_phrase) => (
                language,
                seed_phrase,
                PassPhrase::new(zeroize::Zeroizing::new(None)),
            ),
            SerializableSeedPhrase::V1(language, seed_phrase, passphrase) => {
                (language, seed_phrase, passphrase)
            }
        };
        assert_eq!(seed_phrase.mnemonic().join(" "), MNEMONIC);
        assert_eq!(seed_phrase_language, SeedPhraseLanguage::English);
        assert_eq!(passphrase, wallet_passphrase);
    }

    // Now the seed phrase doesn't exist in the wallet anymore
    let seed_phrase = wallet.seed_phrase().unwrap();
    assert!(seed_phrase.is_none());
}

#[test]
fn wallet_seed_phrase_check_address() {
    let chain_config = Arc::new(create_mainnet());

    // create wallet with saving the seed phrase
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    let wallet_passphrase: Option<String> = None;
    let mut wallet = Wallet::create_new_wallet(
        Arc::clone(&chain_config),
        db,
        (BlockHeight::new(0), genesis_block_id),
        WalletType::Hot,
        |db_tx| {
            Ok(SoftwareSignerProvider::new_from_mnemonic(
                chain_config.clone(),
                db_tx,
                MNEMONIC,
                wallet_passphrase.as_ref().map(|p| p.as_ref()),
                StoreSeedPhrase::Store,
            )?)
        },
    )
    .unwrap()
    .wallet()
    .unwrap();

    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pk = wallet.find_public_key(DEFAULT_ACCOUNT_INDEX, address.1.into_object()).unwrap();

    // m/44'/19788'/0'/0/0 for MNEMONIC
    let expected_pk = "03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade";
    assert_eq!(expected_pk, pk.hex_encode().strip_prefix("00").unwrap());

    let db = create_wallet_in_memory().unwrap();
    let wallet_passphrase: Option<String> = Some("phrase123".into());
    let mut wallet = Wallet::create_new_wallet(
        Arc::clone(&chain_config),
        db,
        (BlockHeight::new(0), genesis_block_id),
        WalletType::Hot,
        |db_tx| {
            Ok(SoftwareSignerProvider::new_from_mnemonic(
                chain_config.clone(),
                db_tx,
                MNEMONIC,
                wallet_passphrase.as_ref().map(|p| p.as_ref()),
                StoreSeedPhrase::Store,
            )?)
        },
    )
    .unwrap()
    .wallet()
    .unwrap();

    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(address.0, ChildNumber::from_index_with_hardened_bit(0));
    let pk = wallet.find_public_key(DEFAULT_ACCOUNT_INDEX, address.1.into_object()).unwrap();

    // m/44'/19788'/0'/0/0 for MNEMONIC with passphrase: phrase123
    let expected_pk = "03f5afc96d42babad096261c743398ecad90bfd5dbf59dea840ef276a1bc2a62fb";
    assert_eq!(expected_pk, pk.hex_encode().strip_prefix("00").unwrap());

    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(address.0, ChildNumber::from_index_with_hardened_bit(1));
    let pk = wallet.find_public_key(DEFAULT_ACCOUNT_INDEX, address.1.into_object()).unwrap();
    // m/44'/19788'/0'/0/1 for MNEMONIC with passphrase: phrase123
    let expected_pk2 = "0284857ecbeb0c19f078f4224313d9f43a86fcc875ffa6e00feca621bdc200d14a";
    assert_eq!(expected_pk2, pk.hex_encode().strip_prefix("00").unwrap());
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
        address.as_object().clone(),
    );

    test_balance_from_genesis(chain_type, vec![genesis_output.clone()], genesis_amount);

    let genesis_amount_2 = Amount::from_atoms(54321);
    let genesis_output_2 = TxOutput::LockThenTransfer(
        OutputValue::Coin(genesis_amount_2),
        address.into_object(),
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
            let genesis_output = make_address_output(address, genesis_amount);

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
    let genesis_output =
        TxOutput::Transfer(OutputValue::Coin(genesis_amount), address.into_object());
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        vec![genesis_output],
    );
    let chain_config = Arc::new(
        Builder::new(chain_type)
            .genesis_custom(genesis)
            // Force empty checkpoints because a custom genesis is used.
            .checkpoints(BTreeMap::new())
            .build(),
    );

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, genesis_amount);

    let password = gen_random_password(&mut rng);
    wallet.encrypt_wallet(&Some(password)).unwrap();
    wallet.lock_wallet().unwrap();

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, genesis_amount);
}

#[test]
fn wallet_balance_block_reward() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);
    let (best_block_id, best_block_height) = get_best_block(&wallet);
    assert_eq!(best_block_id, chain_config.genesis_block_id());
    assert_eq!(best_block_height, BlockHeight::new(0));

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(10000);
    let (_, block1) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    // Verify that the first block reward has been received
    let (best_block_id, best_block_height) = get_best_block(&wallet);
    assert_eq!(best_block_id, block1.get_id());
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
        block1.get_id().into(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(address, block2_amount)]),
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
        block1.get_id().into(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![make_address_output(address, block2_amount_new)]),
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
        vec![make_address_output(address, tx_amount1)],
    )
    .unwrap();
    let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![signed_transaction1],
        Amount::ZERO,
        0,
    );

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
        vec![make_address_output(address1, tx_amount1)],
    )
    .unwrap();
    let transaction_id1 = transaction1.get_id();
    let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();

    let transaction2 = Transaction::new(
        0,
        vec![TxInput::from_utxo(OutPointSourceId::Transaction(transaction_id1), 0)],
        vec![make_address_output(address2, tx_amount2)],
    )
    .unwrap();
    let signed_transaction2 =
        SignedTransaction::new(transaction2, vec![InputWitness::NoSignature(None)]).unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![signed_transaction1, signed_transaction2],
        Amount::ZERO,
        0,
    );

    verify_wallet_balance(&chain_config, &wallet, tx_amount2);
}

#[track_caller]
fn test_wallet_accounts<B, P>(
    chain_config: &Arc<ChainConfig>,
    wallet: &Wallet<B, P>,
    expected_accounts: Vec<U31>,
) where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let accounts = wallet.account_indexes().cloned().collect::<Vec<_>>();
    assert_eq!(accounts, expected_accounts);

    let db_copy = wallet.db.clone();
    let wallet = Wallet::load_wallet(
        Arc::clone(chain_config),
        db_copy,
        None,
        |_| Ok(()),
        WalletControllerMode::Hot,
        false,
        |db_tx| SoftwareSignerProvider::load_from_database(chain_config.clone(), db_tx),
    )
    .unwrap()
    .wallet()
    .unwrap();
    let accounts = wallet.account_indexes().cloned().collect::<Vec<_>>();
    assert_eq!(accounts, expected_accounts);
}

#[test]
fn wallet_accounts_creation() {
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    test_wallet_accounts(&chain_config, &wallet, vec![DEFAULT_ACCOUNT_INDEX]);
    // DEFAULT_ACCOUNT_INDEX now has 1 transaction so next account can be created
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![],
        Amount::from_atoms(100),
        0,
    );

    let res = wallet.create_next_account(Some("name".into())).unwrap();
    assert_eq!(res, (U31::from_u32(1).unwrap(), Some("name".into())));

    // but we cannot create a third account as the new one has no transactions
    let error = wallet.create_next_account(None).err().unwrap();
    assert_eq!(error, WalletError::EmptyLastAccount);

    let acc1_pk = wallet.get_new_address(res.0).unwrap().1;
    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                acc1_pk.into_object(),
            )],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    // even with an unconfirmed transaction we cannot create a new account
    wallet.add_unconfirmed_tx(tx.clone(), &WalletEventsNoOp).unwrap();
    let error = wallet.create_next_account(None).err().unwrap();
    assert_eq!(error, WalletError::EmptyLastAccount);

    // after getting a confirmed transaction we can create a new account
    let _ = create_block(&chain_config, &mut wallet, vec![tx], Amount::ZERO, 1);
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
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);
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
    let blocks = (0..rng.gen_range(1..100))
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
                vec![make_address_output(address, tx_amount1)],
            )
            .unwrap();
            let signed_transaction1 = SignedTransaction::new(transaction1, Vec::new()).unwrap();
            let (_, block) = create_block(
                &chain_config,
                &mut wallet,
                vec![signed_transaction1],
                Amount::ZERO,
                idx,
            );

            if rng.gen_bool(0.2) {
                last_account_index = wallet.create_next_account(None).unwrap().0;
            }
            block
        })
        .collect_vec();

    // verify all accounts have the expected balances
    for (acc_idx, expected_balance) in total_amounts.iter() {
        let coin_balance = get_coin_balance_for_acc(&wallet, *acc_idx);
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
        let coin_balance = get_coin_balance_for_acc(&wallet, acc_idx);
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

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 1..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let password = Some(gen_random_password(&mut rng));
    wallet.encrypt_wallet(&password).unwrap();
    wallet.lock_wallet().unwrap();

    let coin_balance = get_coin_balance(&wallet);
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
            [new_output.clone()],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
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
                [new_output],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
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
                [new_output],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap();
    }
}
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_get_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());
    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(100000..1000000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [gen_random_transfer(&mut rng, Amount::from_atoms(1))],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let tx_id = tx.transaction().get_id();

    // try to find not registered transaction
    let err = wallet.get_transaction(DEFAULT_ACCOUNT_INDEX, tx_id).unwrap_err();
    assert_eq!(err, WalletError::NoTransactionFound(tx_id));

    wallet
        .add_account_unconfirmed_tx(DEFAULT_ACCOUNT_INDEX, tx.clone(), &WalletEventsNoOp)
        .unwrap();
    let found_tx = wallet.get_transaction(DEFAULT_ACCOUNT_INDEX, tx_id).unwrap();

    assert_eq!(*found_tx.state(), TxState::Inactive(1));
    assert_eq!(found_tx.get_transaction(), tx.transaction());

    // put the tx in a block and scan it as confirmed
    let (_, block) = create_block(
        &chain_config,
        &mut wallet,
        vec![tx.clone()],
        Amount::ZERO,
        1,
    );
    let found_tx = wallet.get_transaction(DEFAULT_ACCOUNT_INDEX, tx_id).unwrap();

    assert_eq!(
        *found_tx.state(),
        TxState::Confirmed(BlockHeight::new(2), block.timestamp(), 0)
    );
    assert_eq!(found_tx.get_transaction(), tx.transaction());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_list_mainchain_transactions(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet = create_wallet(chain_config.clone());
    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(100000..1000000));
    let (addr, _) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);
    let dest = addr.into_object();

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // send some coins to the address
    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::Transfer(OutputValue::Coin(block1_amount), dest.clone())],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let send_tx_id = tx.transaction().get_id();

    // put the tx in a block and scan it as confirmed
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![tx.clone()],
        Amount::ZERO,
        1,
    );

    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [gen_random_transfer(&mut rng, block1_amount)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();
    let spend_from_tx_id = tx.transaction().get_id();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![tx.clone()],
        Amount::ZERO,
        2,
    );

    let txs = wallet.mainchain_transactions(DEFAULT_ACCOUNT_INDEX, Some(dest), 100).unwrap();
    // should have 2 txs the send to and the spent from
    assert_eq!(txs.len(), 2);
    assert!(txs.iter().any(|info| info.id == send_tx_id));
    assert!(txs.iter().any(|info| info.id == spend_from_tx_id));
}

// Check 3 scenarios for fee calculation by the wallet
// 1. give X amount of coins to the wallet
// 2. Try to create a transaction where the feerate is so high that the UTXO will need to pay more
//    fee than it has so it will return an NoUTXOs error
// 3. Successfuly create a TX with many outputs and make sure the fee paid is within the range of
//    [0-16] bytes * feerate (16 bytes is the MAX u128 Amount used by the change output)
//
// 4. Create a sweep TX using the previously created many outputs. The sweep command does not
//    create any change output so check that the fee paid is exactly the correct one based on the
//    final size of the transaction.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_transactions_with_fees(#[case] seed: Seed) {
    use crate::destination_getters::{get_tx_output_destination, HtlcSpendingCondition};

    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(30000000..50000000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // Check that if the feerate is too high UTXOs will be filtered out
    // if their value is < the fee needed to spend that input
    {
        // feerate such that the fee for the input is larger than the input amount
        // 103 is the size of the signature required for the input
        let very_big_feerate =
            FeeRate::from_total_tx_fee(block1_amount.into(), NonZeroUsize::new(103).unwrap())
                .unwrap();
        let err = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [gen_random_transfer(&mut rng, Amount::from_atoms(1))],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                very_big_feerate,
                very_big_feerate,
                TxAdditionalInfo::new(),
            )
            .unwrap_err();

        match err {
            WalletError::CoinSelectionError(UtxoSelectorError::NoUtxos) => {}
            _ => panic!("wrong error"),
        }
    }

    // make a transaction with multiple outputs to the same address so we can later sweep them all
    // again
    let num_outputs = rng.gen_range(1..1000);
    let amount_to_transfer_per_output = Amount::from_atoms(
        rng.gen_range(NETWORK_FEE..=((block1_amount.into_atoms() - NETWORK_FEE) / num_outputs / 2)),
    );
    let amount_to_transfer = (amount_to_transfer_per_output * num_outputs).unwrap();

    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1.into_object();
    let outputs: Vec<TxOutput> = (0..num_outputs)
        .map(|_| {
            TxOutput::Transfer(
                OutputValue::Coin(amount_to_transfer_per_output),
                address.clone(),
            )
        })
        // also add some random outputs to test out different TxOutput types
        .chain(
            (0..num_outputs).map(|_| gen_random_transfer(&mut rng, amount_to_transfer_per_output)),
        )
        .collect();

    let feerate = FeeRate::from_amount_per_kb(Amount::from_atoms(rng.gen_range(1..1000)));
    let transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            outputs,
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            feerate,
            feerate,
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let tx_size = serialization::Encode::encoded_size(&transaction);

    // 16 bytes (u128) is the max tx size diffference in the estimation,
    // because of the compact encoding for the change amount which is unknown beforhand
    let max_size_diff = std::mem::size_of::<u128>();
    let min_fee = feerate.compute_fee(tx_size).unwrap();
    let max_fee = feerate.compute_fee(tx_size + max_size_diff).unwrap();

    // register the successful transaction and check the balance
    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            transaction.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();
    let coin_balance1 = get_coin_balance_with_inactive(&wallet);
    let expected_balance_max =
        ((block1_amount - amount_to_transfer).unwrap() - min_fee.into()).unwrap();
    let expected_balance_min =
        ((block1_amount - amount_to_transfer).unwrap() - max_fee.into()).unwrap();

    assert!(coin_balance1 >= expected_balance_min);
    assert!(coin_balance1 <= expected_balance_max);

    let selected_utxos = wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::IssueNft,
            UtxoState::Confirmed | UtxoState::Inactive,
            WithLocked::Unlocked,
        )
        .unwrap()
        .into_iter()
        .filter(|(_, output)| {
            get_tx_output_destination(output, &|_| None, HtlcSpendingCondition::Skip)
                .is_some_and(|dest| dest == address)
        })
        .collect::<Vec<_>>();

    // make sure we have selected all of the previously created outputs
    assert!(selected_utxos.len() >= num_outputs as usize);

    let account1 = wallet.create_next_account(None).unwrap().0;
    let address2 = wallet.get_new_address(account1).unwrap().1.into_object();
    let feerate = FeeRate::from_amount_per_kb(Amount::from_atoms(rng.gen_range(1..1000)));
    let transaction = wallet
        .create_sweep_transaction(
            DEFAULT_ACCOUNT_INDEX,
            address2,
            selected_utxos,
            feerate,
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let tx_size = serialization::Encode::encoded_size(&transaction);
    let exact_fee = feerate.compute_fee(tx_size).unwrap();

    // register the successful transaction and check the balance
    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            transaction.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();
    let coin_balance2 = get_coin_balance_with_inactive(&wallet);
    // sweep pays fees from the transfer amount itself
    assert_eq!(coin_balance2, (coin_balance1 - amount_to_transfer).unwrap());

    // add the tx to the new account and check the balance
    wallet
        .add_account_unconfirmed_tx(account1, transaction.clone(), &WalletEventsNoOp)
        .unwrap();

    let coin_balance3 = wallet
        .get_balance(
            account1,
            UtxoState::Confirmed | UtxoState::Inactive | UtxoState::InMempool,
            WithLocked::Unlocked,
        )
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);

    // the sweep command should pay exactly the correct fee as it has no change outputs
    let expected_balance3 = (amount_to_transfer - exact_fee.into()).unwrap();
    assert_eq!(coin_balance3, expected_balance3);
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
fn spend_from_user_specified_utxos(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    // Generate a new block which sends reward to the wallet
    let utxo_amount = Amount::from_atoms(rng.gen_range(100..10000));
    let reward_outputs = (0..10)
        .map(|idx| {
            let address = get_address(
                &chain_config,
                MNEMONIC,
                DEFAULT_ACCOUNT_INDEX,
                KeyPurpose::ReceiveFunds,
                idx.try_into().unwrap(),
            );
            make_address_output(address, utxo_amount)
        })
        .collect_vec();
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(reward_outputs),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let utxos = wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    let burn_amount = Amount::from_atoms(rng.gen_range(1..utxo_amount.into_atoms()));

    {
        let missing_utxo =
            UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 123);
        let err = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [TxOutput::Burn(OutputValue::Coin(burn_amount))],
                SelectedInputs::Utxos(vec![missing_utxo.clone()]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap_err();
        assert_eq!(err, WalletError::CannotFindUtxo(missing_utxo.clone()));

        let err = wallet
            .find_used_tokens(DEFAULT_ACCOUNT_INDEX, &[missing_utxo.clone()])
            .unwrap_err();

        assert_eq!(err, WalletError::CannotFindUtxo(missing_utxo));
    }

    let selected_utxos = utxos
        .iter()
        .map(|(outpoint, _)| outpoint)
        .take(rng.gen_range(1..utxos.len()))
        .cloned()
        .collect_vec();

    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::Burn(OutputValue::Coin(burn_amount))],
            SelectedInputs::Utxos(selected_utxos.clone()),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    // check that we only have the selected_utxo as inputs
    assert_eq!(tx.inputs().len(), selected_utxos.len());
    for tx_input in tx.inputs() {
        assert!(selected_utxos.contains(tx_input.utxo_outpoint().unwrap()));
    }

    // check that there is a change output
    assert_eq!(tx.outputs().len(), 2);
    let change_amount =
        ((utxo_amount * selected_utxos.len() as u128).unwrap() - burn_amount).unwrap();
    for out in tx.outputs() {
        match out {
            TxOutput::Transfer(value, _) => {
                assert_eq!(value.coin_amount().unwrap(), change_amount)
            }
            TxOutput::Burn(value) => assert_eq!(value.coin_amount().unwrap(), burn_amount),
            _ => panic!("unexpected output"),
        }
    }

    {
        wallet
            .add_account_unconfirmed_tx(DEFAULT_ACCOUNT_INDEX, tx, &WalletEventsNoOp)
            .unwrap();
        // Try to select the same UTXOs now they should be already consumed

        let err = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [TxOutput::Burn(OutputValue::Coin(burn_amount))],
                SelectedInputs::Utxos(selected_utxos.clone()),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            WalletError::ConsumedUtxo(selected_utxos.first().unwrap().clone())
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_stake_pool_and_list_pool_ids(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = block1_amount;

    let (standalone_sk, standalone_pk) =
        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    wallet
        .add_standalone_private_key(DEFAULT_ACCOUNT_INDEX, standalone_sk, None)
        .unwrap();
    let decommission_key = Destination::PublicKey(standalone_pk);

    let err = wallet
        .create_stake_pool_tx_with_vrf_key(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.clone(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap_err();
    assert_eq!(err, WalletError::VrfKeyMustBeProvided);

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.clone(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();
    let stake_pool_transaction_id = stake_pool_transaction.transaction().get_id();
    let (addr, block2) = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);
    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert_eq!(pool_ids.len(), 1);
    let pool_ids = wallet
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert_eq!(pool_ids.len(), 1);

    let (pool_id, pool_data) = pool_ids.first().unwrap();
    assert_eq!(&pool_data.decommission_key, &decommission_key);
    assert_eq!(
        &pool_data.utxo_outpoint,
        &UtxoOutPoint::new(OutPointSourceId::Transaction(stake_pool_transaction_id), 0)
    );

    let mut create_stake_pool_utxos = wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::CreateStakePool.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(create_stake_pool_utxos.len(), 1);
    let (_, output) = create_stake_pool_utxos.pop().unwrap();
    match output {
        TxOutput::CreateStakePool(id, data) => {
            assert_eq!(id, *pool_id);
            assert_eq!(data.pledge(), pool_amount);
        }
        _ => panic!("wrong TxOutput type"),
    };

    let pos_data = wallet.get_pos_gen_block_data(DEFAULT_ACCOUNT_INDEX, *pool_id).unwrap();

    let block3 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::PoS(Box::new(PoSData::new(
            vec![TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(stake_pool_transaction_id),
                0,
            ))],
            vec![],
            *pool_id,
            pos_data.vrf_private_key().produce_vrf_data(VRFTranscript::new(&[])),
            common::primitives::Compact(0),
        ))),
        BlockReward::new(vec![TxOutput::ProduceBlockFromStake(
            addr.into_object(),
            *pool_id,
        )]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(2), vec![block3.clone()]);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);
    let (_pool_id, pool_data) = pool_ids.first().unwrap();
    assert_eq!(
        &pool_data.utxo_outpoint,
        &UtxoOutPoint::new(OutPointSourceId::BlockReward(block3.get_id().into()), 0)
    );

    // do a reorg back to block 2
    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2.clone()]);
    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);
    let (pool_id, pool_data) = pool_ids.first().unwrap();
    assert_eq!(
        &pool_data.utxo_outpoint,
        &UtxoOutPoint::new(OutPointSourceId::Transaction(stake_pool_transaction_id), 0)
    );

    let decommission_tx = wallet
        .decommission_stake_pool(
            DEFAULT_ACCOUNT_INDEX,
            *pool_id,
            pool_amount,
            None,
            FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![decommission_tx],
        Amount::ZERO,
        2,
    );
    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());
    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert!(pool_ids.is_empty());
    let pool_ids = wallet
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, pool_amount,);
}

// Create a pool in wallet1 using staker destination and vrf public key from wallet2 and
// decommission address from wallet1.
// Check that the pool is returned by wallet1.get_pool_ids(WalletPoolsFilter::Decommission) and
// wallet2.get_pool_ids(WalletPoolsFilter::Stake) but not vice versa.
// Also check that using Destination::PublicKeyHash as the staker destination returns an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_stake_pool_for_different_wallet_and_list_pool_ids(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet1 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    let coin_balance1 = get_coin_balance(&wallet1);
    assert_eq!(coin_balance1, Amount::ZERO);
    let coin_balance2 = get_coin_balance(&wallet2);
    assert_eq!(coin_balance2, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let (_, block1) = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block1]);

    let pool_ids1 = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids1.is_empty());
    let pool_ids2 = wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids2.is_empty());

    let coin_balance1 = get_coin_balance(&wallet1);
    assert_eq!(coin_balance1, block1_amount);
    let coin_balance2 = get_coin_balance(&wallet2);
    assert_eq!(coin_balance2, Amount::ZERO);

    let pool_amount = block1_amount;
    let margin_ratio_per_thousand = PerThousand::new_from_rng(&mut rng);
    let cost_per_block =
        Amount::from_atoms(rng.gen_range(0..10) * 10_u128.pow(chain_config.coin_decimals() as u32));

    let decommission_dest = wallet1.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1.into_object();

    let staker_key_hash_dest =
        wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1.into_object();
    assert_matches!(&staker_key_hash_dest, Destination::PublicKeyHash(_));
    let staker_key = wallet2
        .find_public_key(DEFAULT_ACCOUNT_INDEX, staker_key_hash_dest.clone())
        .unwrap();
    let staker_key_dest = Destination::PublicKey(staker_key);
    let staker_vrf_public_key = wallet2.get_vrf_key(DEFAULT_ACCOUNT_INDEX).unwrap().1.into_object();

    // First, try to create the pool using staker_key_hash_dest as the staker address; this should fail.
    let err = wallet1
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand,
                cost_per_block,
                decommission_key: decommission_dest.clone(),
                staker_key: Some(staker_key_hash_dest),
                vrf_public_key: Some(staker_vrf_public_key.clone()),
            },
        )
        .unwrap_err();
    assert_eq!(err, WalletError::StakerDestinationMustBePublicKey);

    let coin_balance1 = get_coin_balance(&wallet1);
    assert_eq!(coin_balance1, block1_amount);
    let coin_balance2 = get_coin_balance(&wallet2);
    assert_eq!(coin_balance2, Amount::ZERO);

    // Now use staker_key_dest.
    let stake_pool_transaction = wallet1
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand,
                cost_per_block,
                decommission_key: decommission_dest.clone(),
                staker_key: Some(staker_key_dest.clone()),
                vrf_public_key: Some(staker_vrf_public_key.clone()),
            },
        )
        .unwrap();
    let stake_pool_transaction_id = stake_pool_transaction.transaction().get_id();

    let stake_pool_transaction2 = wallet1
        .create_stake_pool_tx_with_vrf_key(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand,
                cost_per_block,
                decommission_key: decommission_dest.clone(),
                staker_key: Some(staker_key_dest.clone()),
                vrf_public_key: Some(staker_vrf_public_key.clone()),
            },
        )
        .unwrap();
    let stake_pool_transaction_id2 = stake_pool_transaction2.transaction().get_id();
    assert_eq!(stake_pool_transaction_id, stake_pool_transaction_id2);

    let (_, block2) = create_block(
        &chain_config,
        &mut wallet1,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(1), vec![block2.clone()]);

    let coin_balance1 = get_coin_balance(&wallet1);
    assert_eq!(coin_balance1, Amount::ZERO);
    let coin_balance2 = get_coin_balance(&wallet2);
    assert_eq!(coin_balance2, Amount::ZERO);

    let pool_ids_for_staking1 =
        wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert!(pool_ids_for_staking1.is_empty());
    let pool_ids_for_decommission1 = wallet1
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert_eq!(pool_ids_for_decommission1.len(), 1);

    let pool_ids_for_decommission2 = wallet2
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert!(pool_ids_for_decommission2.is_empty());
    let pool_ids_for_staking2 =
        wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert_eq!(pool_ids_for_staking2.len(), 1);

    assert_eq!(pool_ids_for_decommission1[0], pool_ids_for_staking2[0]);

    let (pool_id, pool_data) = pool_ids_for_staking2.first().unwrap();
    assert_eq!(pool_data.decommission_key, decommission_dest);
    assert_eq!(pool_data.stake_destination, staker_key_dest);
    assert_eq!(pool_data.vrf_public_key, staker_vrf_public_key);
    assert_eq!(
        pool_data.margin_ratio_per_thousand,
        margin_ratio_per_thousand
    );
    assert_eq!(pool_data.cost_per_block, cost_per_block);
    assert_eq!(
        &pool_data.utxo_outpoint,
        &UtxoOutPoint::new(OutPointSourceId::Transaction(stake_pool_transaction_id), 0)
    );

    let mut create_stake_pool_utxos = wallet2
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::CreateStakePool.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();
    assert_eq!(create_stake_pool_utxos.len(), 1);
    let (_, output) = create_stake_pool_utxos.pop().unwrap();
    let (pool_id_in_utxo, stake_pool_data_in_utxo) =
        assert_matches_return_val!(output, TxOutput::CreateStakePool(id, data), (id, *data));
    let expected_stake_pool_data = StakePoolData::new(
        pool_amount,
        staker_key_dest.clone(),
        staker_vrf_public_key.clone(),
        decommission_dest.clone(),
        margin_ratio_per_thousand,
        cost_per_block,
    );
    assert_eq!(pool_id_in_utxo, *pool_id);
    assert_eq!(stake_pool_data_in_utxo, expected_stake_pool_data);

    let pos_data = wallet2.get_pos_gen_block_data(DEFAULT_ACCOUNT_INDEX, *pool_id).unwrap();

    let block3 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::PoS(Box::new(PoSData::new(
            vec![TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(stake_pool_transaction_id),
                0,
            ))],
            vec![],
            *pool_id,
            pos_data.vrf_private_key().produce_vrf_data(VRFTranscript::new(&[])),
            common::primitives::Compact(0),
        ))),
        BlockReward::new(vec![TxOutput::ProduceBlockFromStake(
            staker_key_dest.clone(),
            *pool_id,
        )]),
    )
    .unwrap();

    scan_wallet(&mut wallet1, BlockHeight::new(2), vec![block3.clone()]);
    scan_wallet(&mut wallet2, BlockHeight::new(2), vec![block3.clone()]);

    let pool_ids_for_staking1 =
        wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert!(pool_ids_for_staking1.is_empty());
    let pool_ids_for_decommission1 = wallet1
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert_eq!(pool_ids_for_decommission1.len(), 1);

    let pool_ids_for_decommission2 = wallet2
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert!(pool_ids_for_decommission2.is_empty());
    let pool_ids_for_staking2 =
        wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert_eq!(pool_ids_for_staking2.len(), 1);

    assert_eq!(pool_ids_for_decommission1[0], pool_ids_for_staking2[0]);

    let (pool_id_after_block3, pool_data_after_block) = pool_ids_for_staking2.first().unwrap();
    assert_eq!(pool_id_after_block3, pool_id);
    assert_eq!(pool_data_after_block.decommission_key, decommission_dest);
    assert_eq!(pool_data_after_block.stake_destination, staker_key_dest);
    assert_eq!(pool_data_after_block.vrf_public_key, staker_vrf_public_key);
    assert_eq!(
        pool_data_after_block.margin_ratio_per_thousand,
        margin_ratio_per_thousand
    );
    assert_eq!(pool_data_after_block.cost_per_block, cost_per_block);
    assert_eq!(
        &pool_data_after_block.utxo_outpoint,
        &UtxoOutPoint::new(OutPointSourceId::BlockReward(block3.get_id().into()), 0)
    );

    let decommission_tx = wallet1
        .decommission_stake_pool(
            DEFAULT_ACCOUNT_INDEX,
            *pool_id,
            pool_amount,
            None,
            FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
        )
        .unwrap();

    let (_, block4) = create_block(
        &chain_config,
        &mut wallet1,
        vec![decommission_tx],
        Amount::ZERO,
        3,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(3), vec![block4]);

    let pool_ids1 = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids1.is_empty());
    let pool_ids2 = wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids2.is_empty());

    let coin_balance1 = get_coin_balance(&wallet1);
    assert_eq!(coin_balance1, pool_amount);
    let coin_balance2 = get_coin_balance(&wallet2);
    assert_eq!(coin_balance2, Amount::ZERO);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reset_keys_after_failed_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let not_enough = (block1_amount + Amount::from_atoms(1)).unwrap();

    let last_issued_address = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap()
        .last_issued();

    let result = wallet.create_stake_pool_tx(
        DEFAULT_ACCOUNT_INDEX,
        FeeRate::from_amount_per_kb(Amount::ZERO),
        FeeRate::from_amount_per_kb(Amount::ZERO),
        StakePoolCreationArguments {
            amount: not_enough,
            margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
            cost_per_block: Amount::ZERO,
            decommission_key: Destination::AnyoneCanSpend,
            staker_key: None,
            vrf_public_key: None,
        },
    );
    // check that result is an error and we last issued address is still the same
    assert!(result.is_err());
    assert_eq!(
        last_issued_address,
        wallet
            .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
            .unwrap()
            .last_issued(),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn send_to_unknown_delegation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(2..100));
    let block1_amount = delegation_amount;
    let block_height = 0;
    let (_, block) = create_block(
        &chain_config,
        &mut wallet,
        vec![],
        block1_amount,
        block_height,
    );

    scan_wallet(
        &mut wallet2,
        BlockHeight::new(block_height),
        vec![block.clone()],
    );

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, delegation_amount);
    let coin_balance = get_coin_balance(&wallet2);
    assert_eq!(coin_balance, Amount::ZERO);

    let block_height = 1;
    let (_, block) = create_block(
        &chain_config,
        &mut wallet2,
        vec![],
        block1_amount,
        block_height,
    );

    scan_wallet(
        &mut wallet,
        BlockHeight::new(block_height),
        vec![block.clone()],
    );

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, delegation_amount);
    let coin_balance = get_coin_balance(&wallet2);
    assert_eq!(coin_balance, delegation_amount);

    let unknown_pool_id = PoolId::new(H256::zero());
    let address2 = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let (wallet2_delegation_id, delegation_tx) = wallet2
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address2.clone(), unknown_pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block_height = 2;
    let (_, block) = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx],
        Amount::ZERO,
        block_height,
    );
    scan_wallet(
        &mut wallet2,
        BlockHeight::new(block_height),
        vec![block.clone()],
    );

    let delegation_data =
        wallet2.get_delegation(DEFAULT_ACCOUNT_INDEX, wallet2_delegation_id).unwrap();
    assert_eq!(delegation_data.pool_id, unknown_pool_id);
    assert_eq!(&delegation_data.destination, address2.as_object());
    assert!(delegation_data.not_staked_yet);

    // Stake from wallet1 to wallet2's delegation
    let delegation_stake_tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::DelegateStaking(delegation_amount, wallet2_delegation_id)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let block_height = 3;
    let (_, block) = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_stake_tx],
        block1_amount,
        block_height,
    );
    scan_wallet(
        &mut wallet2,
        BlockHeight::new(block_height),
        vec![block.clone()],
    );

    // Wallet2 should see the transaction and know that someone has staked to the delegation
    let delegation_data =
        wallet2.get_delegation(DEFAULT_ACCOUNT_INDEX, wallet2_delegation_id).unwrap();
    assert_eq!(delegation_data.pool_id, unknown_pool_id);
    assert_eq!(&delegation_data.destination, address2.as_object());
    assert!(!delegation_data.not_staked_yet);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let (other_acc_idx, _) = wallet.create_next_account(None).unwrap();
    let address = wallet.get_new_address(other_acc_idx).unwrap().1;

    let unknown_pool_id = PoolId::new(H256::zero());
    let (delegation_id, delegation_tx) = wallet
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address.clone(), unknown_pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx],
        Amount::ZERO,
        2,
    );

    // the new delegation even though created from DEFAULT_ACCOUNT_INDEX is not theirs
    assert_eq!(
        wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().count(),
        0
    );
    // the new delegation should be registered to the other account
    let delegations = wallet.get_delegations(other_acc_idx).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    assert_eq!(*delegations.first().unwrap().0, delegation_id);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_spend_from_delegations(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(2..100));
    let block1_amount = (chain_config.min_stake_pool_pledge() + delegation_amount).unwrap();
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = chain_config.min_stake_pool_pledge();

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: Destination::AnyoneCanSpend,
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();

    let (address, _) = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, (block1_amount - pool_amount).unwrap(),);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_id = pool_ids.first().unwrap().0;
    let (delegation_id, delegation_tx) = wallet
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address.clone(), pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx],
        Amount::ZERO,
        2,
    );

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert!(deleg_data.not_staked_yet);
    assert_eq!(deleg_data.last_nonce, None);
    assert_eq!(deleg_data.pool_id, pool_id);
    assert_eq!(&deleg_data.destination, address.as_object());

    let delegation_stake_tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::DelegateStaking(delegation_amount, delegation_id)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_stake_tx],
        Amount::ZERO,
        3,
    );

    let delegation_tx1 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            Amount::from_atoms(1),
            delegation_id,
            Amount::from_atoms(2),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            delegation_tx1.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();
    let delegation_tx1 = vec![delegation_tx1];

    // Check delegation balance after unconfirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));

    // Send delegation to account 1
    // test that account 1 will receive the money but not register the delegation id as theirs
    let (other_acc_idx, _) = wallet.create_next_account(None).unwrap();
    let address = wallet.get_new_address(other_acc_idx).unwrap().1;

    let delegation_tx2 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            Amount::from_atoms(1),
            delegation_id,
            Amount::from_atoms(1),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            delegation_tx2.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Check delegation balance after unconfirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(1)));

    let (_, block5) = create_block(&chain_config, &mut wallet, delegation_tx1, Amount::ZERO, 4);

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx2.clone()],
        Amount::ZERO,
        5,
    );

    // Check delegation balance after confirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, _deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);

    // test that account 1 will receive the money but not register the delegation id as theirs
    let coin_balance = wallet
        .get_balance(other_acc_idx, UtxoState::Confirmed.into(), WithLocked::Any)
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::from_atoms(1));

    let delegations = wallet.get_delegations(other_acc_idx).unwrap().collect_vec();
    assert!(delegations.is_empty());

    // roll back the delegation tx to test removal code
    scan_wallet(&mut wallet, BlockHeight::new(4), vec![block5]);

    let coin_balance = wallet
        .get_balance(other_acc_idx, UtxoState::Confirmed.into(), WithLocked::Any)
        .unwrap()
        .get(&Currency::Coin)
        .copied()
        .unwrap_or(Amount::ZERO);
    assert_eq!(coin_balance, Amount::ZERO);

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            delegation_tx2.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();
    let delegation_tx3 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address,
            Amount::from_atoms(1),
            delegation_id,
            Amount::from_atoms(1),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    wallet
        .add_account_unconfirmed_tx(DEFAULT_ACCOUNT_INDEX, delegation_tx3, &WalletEventsNoOp)
        .unwrap();

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(2)));

    // abandon tx2 should also abandon tx3 and roll back account nonce to 0
    wallet
        .abandon_transaction(DEFAULT_ACCOUNT_INDEX, delegation_tx2.transaction().get_id())
        .unwrap();

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_transfer_tokens(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // True for fungible, false for NFT
    let issue_fungible_token = rng.gen::<bool>();

    let issuance_fee = if issue_fungible_token {
        chain_config.fungible_token_issuance_fee()
    } else {
        chain_config.nft_issuance_fee(BlockHeight::zero())
    };

    let some_coins = 100;
    // Generate a new block which sends reward to the issuing wallet.
    let mut block1_amount = (Amount::from_atoms(
        rng.gen_range(NETWORK_FEE + some_coins..NETWORK_FEE + some_coins * 100),
    ) + issuance_fee)
        .unwrap();

    if issue_fungible_token {
        block1_amount =
            (block1_amount + chain_config.token_supply_change_fee(BlockHeight::zero())).unwrap();
    }

    let token_authority_and_destination = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    // Issue token randomly from wallet2 to wallet1 or wallet1 to wallet2
    let (random_issuing_wallet, other_wallet) = if rng.gen::<bool>() {
        (&mut wallet, &mut wallet2)
    } else {
        (&mut wallet2, &mut wallet)
    };

    let (_, block) = create_block(
        &chain_config,
        random_issuing_wallet,
        vec![],
        block1_amount,
        0,
    );
    scan_wallet(other_wallet, BlockHeight::new(0), vec![block.clone()]);

    let coin_balance = get_coin_balance(random_issuing_wallet);
    assert_eq!(coin_balance, block1_amount);

    let amount_fraction = (block1_amount.into_atoms() - NETWORK_FEE) / 10;
    let mut token_amount_to_issue = Amount::from_atoms(rng.gen_range(1..amount_fraction));

    let mut number_of_decimals = rng.gen_range(1..18);
    let token_ticker = "XXXX".as_bytes().to_vec();
    let (issued_token_id, token_issuance_transactions) = if issue_fungible_token {
        let token_issuance = TokenIssuanceV1 {
            token_ticker: token_ticker.clone(),
            number_of_decimals,
            metadata_uri: "http://uri".as_bytes().to_vec(),
            total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
            authority: token_authority_and_destination.as_object().clone(),
            is_freezable: common::chain::tokens::IsTokenFreezable::No,
        };
        // issue a new token from a random wallet 1 or 2 to a destination from wallet1
        let (issued_token_id, token_issuance_transaction) = random_issuing_wallet
            .issue_new_token(
                DEFAULT_ACCOUNT_INDEX,
                TokenIssuance::V1(token_issuance.clone()),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
            )
            .unwrap();

        let freezable = token_issuance.is_freezable.as_bool();
        let token_info = RPCFungibleTokenInfo::new(
            issued_token_id,
            token_issuance.token_ticker,
            token_issuance.number_of_decimals,
            token_issuance.metadata_uri,
            Amount::ZERO,
            token_issuance.total_supply.into(),
            false,
            RPCIsTokenFrozen::NotFrozen { freezable },
            token_issuance.authority,
        );

        random_issuing_wallet
            .add_account_unconfirmed_tx(
                DEFAULT_ACCOUNT_INDEX,
                token_issuance_transaction.clone(),
                &WalletEventsNoOp,
            )
            .unwrap();
        other_wallet
            .add_account_unconfirmed_tx(
                DEFAULT_ACCOUNT_INDEX,
                token_issuance_transaction.clone(),
                &WalletEventsNoOp,
            )
            .unwrap();

        // transfer the remaining coins from the random wallet to wallet1 so it can continue with
        // other transactions
        let transfer_tx = random_issuing_wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [TxOutput::Transfer(
                    OutputValue::Coin((block1_amount - issuance_fee).unwrap()),
                    token_authority_and_destination.as_object().clone(),
                )],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap();
        wallet
            .add_account_unconfirmed_tx(
                DEFAULT_ACCOUNT_INDEX,
                transfer_tx.clone(),
                &WalletEventsNoOp,
            )
            .unwrap();

        // wallet1 should know about the issued token from the random wallet
        let unconfirmed_token_info =
            wallet.get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info).unwrap();
        let mint_transaction = wallet
            .mint_tokens(
                DEFAULT_ACCOUNT_INDEX,
                &unconfirmed_token_info,
                token_amount_to_issue,
                token_authority_and_destination,
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
            )
            .unwrap();

        (
            issued_token_id,
            vec![token_issuance_transaction, transfer_tx, mint_transaction],
        )
    } else {
        number_of_decimals = 0;
        token_amount_to_issue = Amount::from_atoms(1);
        let (issued_token_id, nft_issuance_transaction) = random_issuing_wallet
            .issue_new_nft(
                DEFAULT_ACCOUNT_INDEX,
                token_authority_and_destination.clone(),
                Metadata {
                    creator: None,
                    name: "Name".as_bytes().to_vec(),
                    description: "SomeNFT".as_bytes().to_vec(),
                    ticker: token_ticker.clone(),
                    icon_uri: DataOrNoVec::from(None),
                    additional_metadata_uri: DataOrNoVec::from(None),
                    media_uri: DataOrNoVec::from(None),
                    media_hash: "123456".as_bytes().to_vec(),
                },
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
            )
            .unwrap();
        random_issuing_wallet
            .add_unconfirmed_tx(nft_issuance_transaction.clone(), &WalletEventsNoOp)
            .unwrap();

        let transfer_tx = random_issuing_wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [TxOutput::Transfer(
                    OutputValue::Coin((block1_amount - issuance_fee).unwrap()),
                    token_authority_and_destination.as_object().clone(),
                )],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap();
        (issued_token_id, vec![nft_issuance_transaction, transfer_tx])
    };

    let _ = create_block(
        &chain_config,
        &mut wallet,
        token_issuance_transactions,
        block1_amount,
        1,
    );

    let (coin_balance, token_balances) = get_currency_balances(&wallet);

    let mut expected_amount = ((block1_amount * 2).unwrap() - issuance_fee).unwrap();

    if issue_fungible_token {
        expected_amount =
            (expected_amount - chain_config.token_supply_change_fee(BlockHeight::zero())).unwrap();
    }

    assert_eq!(coin_balance, expected_amount);
    assert_eq!(token_balances.len(), 1);
    let (token_id, token_amount) = token_balances.first().expect("some");
    assert_eq!(*token_id, issued_token_id);
    assert_eq!(*token_amount, token_amount_to_issue);

    let tokens_to_transfer =
        Amount::from_atoms(rng.gen_range(1..=token_amount_to_issue.into_atoms()));

    let some_other_address = PublicKeyHash::from_low_u64_be(1);
    let new_output = TxOutput::Transfer(
        OutputValue::TokenV1(*token_id, tokens_to_transfer),
        Destination::PublicKeyHash(some_other_address),
    );

    let additional_info = TxAdditionalInfo::with_token_info(
        *token_id,
        TokenAdditionalInfo {
            num_decimals: number_of_decimals,
            ticker: token_ticker.clone(),
        },
    );
    let transfer_tokens_transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info.clone(),
        )
        .unwrap();
    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            transfer_tokens_transaction.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![transfer_tokens_transaction],
        block1_amount,
        2,
    );

    let (coin_balance, token_balances) = get_currency_balances(&wallet);
    let mut expected_amount = ((block1_amount * 3).unwrap() - issuance_fee).unwrap();
    if issue_fungible_token {
        expected_amount =
            (expected_amount - chain_config.token_supply_change_fee(BlockHeight::zero())).unwrap();
    }
    assert_eq!(coin_balance, expected_amount,);
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
        OutputValue::TokenV1(*token_id, not_enough_tokens_to_transfer),
        Destination::PublicKeyHash(some_other_address),
    );

    let transfer_tokens_error = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .err()
        .unwrap();

    let remaining_tokens = (token_amount_to_issue - tokens_to_transfer).unwrap();
    if remaining_tokens == Amount::ZERO {
        assert_eq!(
            transfer_tokens_error,
            WalletError::CoinSelectionError(UtxoSelectorError::NoUtxos)
        );
    } else {
        assert_eq!(
            transfer_tokens_error,
            WalletError::CoinSelectionError(UtxoSelectorError::NotEnoughFunds(
                remaining_tokens,
                not_enough_tokens_to_transfer
            ))
        )
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_tokens_v0_are_ignored(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let token_ticker = "XXXX".as_bytes().to_vec();
    let number_of_decimals = rng.gen_range(1..18);
    let result = wallet.create_transaction_to_addresses(
        DEFAULT_ACCOUNT_INDEX,
        [TxOutput::Transfer(
            OutputValue::TokenV0(Box::new(TokenData::TokenIssuance(Box::new(
                TokenIssuanceV0 {
                    token_ticker,
                    number_of_decimals,
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                    amount_to_issue: Amount::from_atoms(rng.gen_range(1..10000)),
                },
            )))),
            address2.into_object(),
        )],
        SelectedInputs::Utxos(vec![]),
        BTreeMap::new(),
        FeeRate::from_amount_per_kb(Amount::ZERO),
        FeeRate::from_amount_per_kb(Amount::ZERO),
        TxAdditionalInfo::new(),
    );

    matches!(
        result.unwrap_err(),
        WalletError::InvalidTransaction(CheckTransactionError::DeprecatedTokenOperationVersion(
            common::chain::TokenIssuanceVersion::V0,
            _
        ))
    );

    let (_, token_balances) = get_currency_balances(&wallet);
    // the token should be ignored
    assert_eq!(token_balances.len(), 0);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn freeze_and_unfreeze_tokens(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + (chain_config.fungible_token_issuance_fee() * 4).unwrap())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let fixed_max_amount = Amount::from_atoms(rng.gen_range(1..100000));
    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let token_issuance = TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: "http://uri".as_bytes().to_vec(),
        total_supply: common::chain::tokens::TokenTotalSupply::Fixed(fixed_max_amount),
        authority: address2.as_object().clone(),
        is_freezable: common::chain::tokens::IsTokenFreezable::Yes,
    };

    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block1_amount,
        1,
    );

    let freezable = token_issuance.is_freezable.as_bool();
    let token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let amount_to_mint = Amount::from_atoms(rng.gen_range(1..=fixed_max_amount.into_atoms()));
    let mint_tx = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            amount_to_mint,
            address2,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![mint_tx], block2_amount, 2);

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let freeze_tx = wallet
        .freeze_token(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            IsTokenUnfreezable::Yes,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet.add_unconfirmed_tx(freeze_tx.clone(), &WalletEventsNoOp).unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.check_can_freeze().unwrap_err(),
        WalletError::CannotFreezeAlreadyFrozenToken
    );
    unconfirmed_token_info.check_can_unfreeze().unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(2)
    );

    // unfreeze the token

    let unfreeze_tx = wallet
        .unfreeze_token(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet.add_unconfirmed_tx(unfreeze_tx.clone(), &WalletEventsNoOp).unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    unconfirmed_token_info.check_can_freeze().unwrap();
    assert_eq!(
        unconfirmed_token_info.check_can_unfreeze().unwrap_err(),
        WalletError::CannotUnfreezeANotFrozenToken
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(3)
    );

    // test abandoning a transaction
    wallet
        .abandon_transaction(DEFAULT_ACCOUNT_INDEX, freeze_tx.transaction().get_id())
        .unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    unconfirmed_token_info.check_can_freeze().unwrap();
    assert_eq!(
        unconfirmed_token_info.check_can_unfreeze().unwrap_err(),
        WalletError::CannotUnfreezeANotFrozenToken
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(1)
    );

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![freeze_tx, unfreeze_tx],
        block2_amount,
        3,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(3)
    );

    unconfirmed_token_info.check_can_freeze().unwrap();
    assert_eq!(
        unconfirmed_token_info.check_can_unfreeze().unwrap_err(),
        WalletError::CannotUnfreezeANotFrozenToken
    );

    // freeze but don't allow unfreezing
    let freeze_tx = wallet
        .freeze_token(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            IsTokenUnfreezable::No,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let tokens_to_transfer = Amount::from_atoms(rng.gen_range(1..=amount_to_mint.into_atoms()));
    let some_other_address = PublicKeyHash::from_low_u64_be(1);
    let new_output = TxOutput::Transfer(
        OutputValue::TokenV1(issued_token_id, tokens_to_transfer),
        Destination::PublicKeyHash(some_other_address),
    );

    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let transfer_tokens_transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    wallet
        .add_unconfirmed_tx(transfer_tokens_transaction.clone(), &WalletEventsNoOp)
        .unwrap();
    wallet.add_unconfirmed_tx(freeze_tx.clone(), &WalletEventsNoOp).unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.check_can_freeze().unwrap_err(),
        WalletError::CannotFreezeAlreadyFrozenToken
    );
    assert_eq!(
        unconfirmed_token_info.check_can_unfreeze().unwrap_err(),
        WalletError::CannotUnfreezeToken
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(4)
    );

    // cannot freeze again
    let err = wallet
        .freeze_token(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            IsTokenUnfreezable::No,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotFreezeAlreadyFrozenToken);

    // cannot unfreeze
    let err = wallet
        .unfreeze_token(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotUnfreezeToken);

    let _ = create_block(
        &chain_config,
        &mut wallet,
        // confirm the freeze tx but not the transfer
        vec![freeze_tx],
        block2_amount,
        4,
    );

    // now the transfer tx should be conflicting
    let pending_txs = wallet.pending_transactions(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(1, pending_txs.len());
    let pending_tx = pending_txs.first().unwrap();
    assert_eq!(
        transfer_tokens_transaction.transaction().get_id(),
        pending_tx.get_id()
    );
    let conflicted_token_balance = wallet
        .get_balance(
            DEFAULT_ACCOUNT_INDEX,
            UtxoState::Conflicted.into(),
            WithLocked::Unlocked,
        )
        .unwrap()
        .remove(&Currency::Token(issued_token_id))
        .unwrap_or(Amount::ZERO);
    assert_eq!(
        conflicted_token_balance,
        (amount_to_mint - tokens_to_transfer).unwrap()
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_token_supply_fixed(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let fixed_max_amount = Amount::from_atoms(rng.gen_range(1..100000));
    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let token_issuance = TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: "http://uri".as_bytes().to_vec(),
        total_supply: common::chain::tokens::TokenTotalSupply::Fixed(fixed_max_amount),
        authority: address2.as_object().clone(),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    };
    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block1_amount,
        1,
    );

    let freezable = token_issuance.is_freezable.as_bool();
    let mut token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.authority().unwrap(),
        address2.as_object()
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(0)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        Amount::ZERO,
    );

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(1..=fixed_max_amount.into_atoms()));
    let mint_transaction = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet.add_unconfirmed_tx(mint_transaction.clone(), &WalletEventsNoOp).unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    // Try to mint more then the fixed maximum
    let leftover = (fixed_max_amount - token_amount_to_mint).unwrap();
    let token_amount_to_mint_more_than_maximum =
        (leftover + Amount::from_atoms(rng.gen_range(1..1000))).unwrap();
    let err = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint_more_than_maximum,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();

    assert_eq!(
        err,
        WalletError::CannotMintFixedTokenSupply(
            fixed_max_amount,
            token_amount_to_mint,
            token_amount_to_mint_more_than_maximum
        )
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(1)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        token_amount_to_mint,
    );

    // test abandoning a transaction
    {
        wallet
            .abandon_transaction(
                DEFAULT_ACCOUNT_INDEX,
                mint_transaction.transaction().get_id(),
            )
            .unwrap();

        let unconfirmed_token_info = wallet
            .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
            .unwrap();

        assert_eq!(
            unconfirmed_token_info.get_next_nonce().unwrap(),
            AccountNonce::new(0)
        );

        assert_eq!(
            unconfirmed_token_info.current_supply().unwrap(),
            Amount::ZERO,
        );
    }

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![mint_transaction],
        block2_amount,
        2,
    );
    token_info.circulating_supply = unconfirmed_token_info.current_supply().unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(1)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        token_amount_to_mint,
    );

    // Try to unmint more than the current total supply
    let token_amount_to_unmint = (token_amount_to_mint + Amount::from_atoms(1)).unwrap();
    let err = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(
        err,
        WalletError::CannotUnmintTokenSupply(token_amount_to_unmint, token_amount_to_mint)
    );

    let token_amount_to_unmint =
        Amount::from_atoms(rng.gen_range(1..=token_amount_to_mint.into_atoms()));
    let unmint_transaction = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet
        .add_unconfirmed_tx(unmint_transaction.clone(), &WalletEventsNoOp)
        .unwrap();
    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![unmint_transaction],
        block2_amount,
        3,
    );
    token_info.circulating_supply = unconfirmed_token_info.current_supply().unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(2)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        (token_amount_to_mint - token_amount_to_unmint).unwrap(),
    );
    assert_eq!(
        unconfirmed_token_info.check_can_lock().unwrap_err(),
        WalletError::CannotLockTokenSupply("Fixed")
    );

    let err = wallet
        .lock_token_supply(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotLockTokenSupply("Fixed"));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_token_supply_unlimited(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let token_issuance = TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: "http://uri".as_bytes().to_vec(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: address2.as_object().clone(),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    };
    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );

    let freezable = token_issuance.is_freezable.as_bool();
    let mut token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.authority().unwrap(),
        address2.as_object()
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(0)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        Amount::ZERO,
    );

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(1..10000));
    let mint_transaction = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet.add_unconfirmed_tx(mint_transaction.clone(), &WalletEventsNoOp).unwrap();
    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![mint_transaction],
        block2_amount,
        2,
    );
    token_info.circulating_supply = unconfirmed_token_info.current_supply().unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(1)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        token_amount_to_mint,
    );

    // Try to unmint more than the current total supply
    let token_amount_to_unmint = (token_amount_to_mint + Amount::from_atoms(1)).unwrap();
    let err = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(
        err,
        WalletError::CannotUnmintTokenSupply(token_amount_to_unmint, token_amount_to_mint)
    );

    let token_amount_to_unmint =
        Amount::from_atoms(rng.gen_range(1..=token_amount_to_mint.into_atoms()));
    let unmint_transaction = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    wallet
        .add_unconfirmed_tx(unmint_transaction.clone(), &WalletEventsNoOp)
        .unwrap();
    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![unmint_transaction],
        block2_amount,
        3,
    );
    token_info.circulating_supply = unconfirmed_token_info.current_supply().unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(2)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        (token_amount_to_mint - token_amount_to_unmint).unwrap(),
    );
    assert_eq!(
        unconfirmed_token_info.check_can_lock().unwrap_err(),
        WalletError::CannotLockTokenSupply("Unlimited")
    );

    let err = wallet
        .lock_token_supply(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotLockTokenSupply("Unlimited"));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_and_lock_token_supply_lockable(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let token_issuance = TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: "http://uri".as_bytes().to_vec(),
        total_supply: common::chain::tokens::TokenTotalSupply::Lockable,
        authority: address2.as_object().clone(),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    };
    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );

    let freezable = token_issuance.is_freezable.as_bool();
    let mut token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.authority().unwrap(),
        address2.as_object()
    );

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(0)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        Amount::ZERO,
    );

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(2..100));
    let mint_transaction = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    wallet.add_unconfirmed_tx(mint_transaction.clone(), &WalletEventsNoOp).unwrap();
    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![mint_transaction],
        block2_amount,
        2,
    );
    token_info.circulating_supply = unconfirmed_token_info.current_supply().unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(1)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        token_amount_to_mint,
    );

    // Try to unmint more than the current total supply
    let token_amount_to_unmint = (token_amount_to_mint + Amount::from_atoms(1)).unwrap();
    let err = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(
        err,
        WalletError::CannotUnmintTokenSupply(token_amount_to_unmint, token_amount_to_mint)
    );

    let token_amount_to_unmint =
        Amount::from_atoms(rng.gen_range(1..=token_amount_to_mint.into_atoms()));
    let unmint_transaction = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet
        .add_unconfirmed_tx(unmint_transaction.clone(), &WalletEventsNoOp)
        .unwrap();
    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![unmint_transaction],
        block2_amount,
        3,
    );
    token_info.circulating_supply = unconfirmed_token_info.current_supply().unwrap();

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(2)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        (token_amount_to_mint - token_amount_to_unmint).unwrap(),
    );
    assert!(unconfirmed_token_info.check_can_lock().is_ok());

    let lock_transaction = wallet
        .lock_token_supply(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![lock_transaction],
        block2_amount,
        4,
    );
    token_info.is_locked = true;

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    assert_eq!(
        unconfirmed_token_info.get_next_nonce().unwrap(),
        AccountNonce::new(3)
    );

    assert_eq!(
        unconfirmed_token_info.current_supply().unwrap(),
        (token_amount_to_mint - token_amount_to_unmint).unwrap(),
    );

    assert_eq!(
        unconfirmed_token_info.check_can_lock(),
        Err(WalletError::CannotLockTokenSupply("Locked"))
    );

    let err = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotChangeLockedTokenSupply);
    let err = wallet
        .unmint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_unmint,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotChangeLockedTokenSupply);

    let err = wallet
        .lock_token_supply(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap_err();
    assert_eq!(err, WalletError::CannotLockTokenSupply("Locked"));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_then_transfer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
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
        BlockReward::new(vec![make_address_output(address.clone(), block1_amount)]),
    )
    .unwrap();

    let seconds_between_blocks = rng.gen_range(10..100);
    let block1_id = block1.get_id();
    // not important that it is not the actual median
    wallet.set_median_time(timestamp).unwrap();
    let timestamp = block1.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    // check balance
    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let destination = address2.into_object();
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
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
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
        BlockReward::new(vec![make_address_output(address, block1_amount)]),
    )
    .unwrap();

    // not important that it is not the actual median
    wallet.set_median_time(timestamp).unwrap();
    let mut timestamp = block2.timestamp().add_int_seconds(seconds_between_blocks).unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(1), vec![block2]);

    // check balance
    let balance_without_locked_transfer =
        ((block1_amount * 2).unwrap() - amount_to_lock_then_transfer).unwrap();

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, balance_without_locked_transfer);

    // check that for block_count_lock, the amount is not included
    for idx in 0..block_count_lock {
        let coin_balance = get_coin_balance(&wallet);
        // check that the amount is still not unlocked
        assert_eq!(coin_balance, balance_without_locked_transfer);

        let currency_balances = wallet
            .get_balance(
                DEFAULT_ACCOUNT_INDEX,
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
    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(
        coin_balance,
        (balance_without_locked_transfer + amount_to_lock_then_transfer).unwrap()
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
        let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, i as u64);
        amounts.push(block1_amount);
    }

    let coin_balance = get_coin_balance(&wallet);
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
                crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
            ),
        );

        let transaction = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [new_output],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
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

    let _ = create_block(
        &chain_config,
        &mut wallet,
        transactions,
        Amount::ZERO,
        blocks_to_add as u64,
    );

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, total_change);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_scan_multiple_transactions_from_mempool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    let num_transactions_to_scan_from_mempool = rng.gen_range(1..5);

    let total_num_transactions: u32 = num_transactions_to_scan_from_mempool + 1;

    // Generate a new block which sends reward to the wallet
    // with enough coins for the total transactions
    let block1_amount = Amount::from_atoms(rng.gen_range(
        (NETWORK_FEE + 1) * (total_num_transactions as u128)
            ..=(NETWORK_FEE + 1) * (total_num_transactions as u128) + 10000,
    ));
    let (_, block1) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
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
        let change_output = make_address_output(address, change);

        let new_output = TxOutput::Transfer(
            OutputValue::Coin(amount_to_transfer),
            Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
            ),
        );

        let transaction = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [new_output, change_output],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
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
            crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
        ),
    );
    let transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
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
            crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
        ),
    );
    let err = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
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
            crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
        ),
    );

    let transaction = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [new_output],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();
    wallet.add_unconfirmed_tx(transaction.clone(), &WalletEventsNoOp).unwrap();

    let transaction_id = transaction.transaction().get_id();

    let coin_balance = get_coin_balance_with_inactive(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    wallet.abandon_transaction(DEFAULT_ACCOUNT_INDEX, transaction_id).unwrap();

    let coin_balance = get_coin_balance_with_inactive(&wallet);
    assert_eq!(coin_balance, amount_to_keep);

    // if we add it back from the mempool it should return even if abandoned
    wallet.scan_mempool(&[transaction], &WalletEventsNoOp).unwrap();
    let coin_balance = get_coin_balance_with_inactive(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_abandon_transactions(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    let total_num_transactions: u32 = rng.gen_range(1..5);

    // Generate a new block which sends reward to the wallet
    // with enough coins for the total transactions
    let block1_amount = Amount::from_atoms(rng.gen_range(
        (NETWORK_FEE + 1) * (total_num_transactions as u128)
            ..=(NETWORK_FEE + 1) * (total_num_transactions as u128) + 10000,
    ));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
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
        let change_output = make_address_output(address, change);

        let new_output = TxOutput::Transfer(
            OutputValue::Coin(amount_to_transfer),
            Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
            ),
        );

        let transaction = wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [new_output, change_output],
                SelectedInputs::Utxos(vec![]),
                BTreeMap::new(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap();
        wallet
            .add_account_unconfirmed_tx(
                DEFAULT_ACCOUNT_INDEX,
                transaction.clone(),
                &WalletEventsNoOp,
            )
            .unwrap();

        for utxo in transaction.inputs().iter().map(|inp| inp.utxo_outpoint().unwrap()) {
            // assert the utxos used in this transaction have not been used before
            assert!(used_inputs.insert(utxo.clone()));
        }

        transactions.push((transaction, total_amount));
        total_amount = change;
    }

    let coin_balance = get_coin_balance_with_inactive(&wallet);
    assert_eq!(coin_balance, total_amount);

    let abandonable_transactions = wallet.pending_transactions(DEFAULT_ACCOUNT_INDEX).unwrap();

    assert_eq!(abandonable_transactions.len(), transactions.len());

    let txs_to_abandon = rng.gen_range(0..total_num_transactions) as usize;
    let (txs_to_keep, txs_to_abandon) = transactions.split_at(txs_to_abandon);

    assert!(!txs_to_abandon.is_empty());

    let transaction_id = txs_to_abandon.first().unwrap().0.transaction().get_id();
    wallet.abandon_transaction(DEFAULT_ACCOUNT_INDEX, transaction_id).unwrap();

    let coins_after_abandon = txs_to_abandon.first().unwrap().1;

    let coin_balance = get_coin_balance_with_inactive(&wallet);
    assert_eq!(coin_balance, coins_after_abandon);

    let txs_to_keep: Vec<_> = txs_to_keep.iter().map(|(tx, _)| tx.clone()).collect();
    wallet.scan_mempool(txs_to_keep.as_slice(), &WalletEventsNoOp).unwrap();
    let coin_balance = get_coin_balance_with_inactive(&wallet);
    assert_eq!(coin_balance, coins_after_abandon);

    // Check the db
    {
        let account_id = wallet.get_account(DEFAULT_ACCOUNT_INDEX).unwrap().get_account_id();
        let db_tx = wallet.database().transaction_ro().unwrap();
        let db_transactions = db_tx.get_transactions(&account_id).unwrap();

        let abandoned_tx_ids = txs_to_abandon
            .iter()
            .map(|(tx, _)| tx.transaction().get_id())
            .collect::<BTreeSet<_>>();

        for (_, wallet_tx) in db_transactions {
            match wallet_tx {
                WalletTx::Block(_) => {}
                WalletTx::Tx(tx_data) => {
                    if abandoned_tx_ids.contains(&tx_data.get_transaction().get_id()) {
                        assert_eq!(*tx_data.state(), TxState::Abandoned);
                    } else {
                        assert_ne!(*tx_data.state(), TxState::Abandoned);
                    }
                }
            };
        }
    }

    // Abandon the same tx again
    let result = wallet.abandon_transaction(DEFAULT_ACCOUNT_INDEX, transaction_id);
    assert_eq!(
        result.unwrap_err(),
        WalletError::CannotChangeTransactionState(TxState::Abandoned, TxState::Abandoned)
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_address_usage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());
    let mut wallet = create_wallet(chain_config.clone());

    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), None);
    assert_eq!(usage.last_issued(), None);

    // issue some new address
    let addresses_to_issue = rng.gen_range(1..10);
    for _ in 0..=addresses_to_issue {
        let _ = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    }

    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), None);
    assert_eq!(
        usage.last_issued(),
        Some(addresses_to_issue.try_into().unwrap())
    );

    let block1_amount = Amount::from_atoms(10000);
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let last_used = addresses_to_issue + 1;
    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), Some(last_used.try_into().unwrap()));
    assert_eq!(usage.last_issued(), Some(last_used.try_into().unwrap()));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wallet_set_lookahead_size(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());
    let mut wallet = create_wallet(chain_config.clone());

    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), None);
    assert_eq!(usage.last_issued(), None);

    // issue some new address
    let addresses_to_issue = rng.gen_range(1..10);
    for _ in 0..=addresses_to_issue {
        let _ = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    }

    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), None);
    assert_eq!(
        usage.last_issued(),
        Some(addresses_to_issue.try_into().unwrap())
    );

    let block1_amount = Amount::from_atoms(10000);
    let (_, block1) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let last_used = addresses_to_issue + 1;
    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), Some(last_used.try_into().unwrap()));
    assert_eq!(usage.last_issued(), Some(last_used.try_into().unwrap()));

    let coins = get_coin_balance_for_acc(&wallet, DEFAULT_ACCOUNT_INDEX);
    assert_eq!(coins, block1_amount);

    let less_than_last_used = rng.gen_range(1..=last_used);
    let err = wallet.set_lookahead_size(less_than_last_used, false).unwrap_err();
    assert_eq!(
        err,
        WalletError::ReducedLookaheadSize(less_than_last_used, last_used)
    );

    wallet.set_lookahead_size(less_than_last_used, true).unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1.clone()]);
    let coins = get_coin_balance_for_acc(&wallet, DEFAULT_ACCOUNT_INDEX);
    assert_eq!(coins, Amount::ZERO);
    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), None);
    assert_eq!(usage.last_issued(), None);

    let more_than_last_used = rng.gen_range(last_used + 1..100);
    wallet.set_lookahead_size(more_than_last_used, false).unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1.clone()]);
    let coins = get_coin_balance_for_acc(&wallet, DEFAULT_ACCOUNT_INDEX);
    assert_eq!(coins, block1_amount);
    let usage = wallet
        .get_addresses_usage(DEFAULT_ACCOUNT_INDEX, KeyPurpose::ReceiveFunds)
        .unwrap();
    assert_eq!(usage.last_used(), Some(last_used.try_into().unwrap()));
    assert_eq!(usage.last_issued(), Some(last_used.try_into().unwrap()));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_wrong_account(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let acc_0_index = DEFAULT_ACCOUNT_INDEX;
    let acc_1_index = U31::ONE;

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let pool_ids = wallet.get_pool_ids(acc_0_index, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = block1_amount;

    let res = wallet.create_next_account(Some("name".into())).unwrap();
    assert_eq!(res, (U31::from_u32(1).unwrap(), Some("name".into())));

    let decommission_key = wallet.get_new_address(acc_1_index).unwrap().1;

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            acc_0_index,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.into_object(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    let pool_ids = wallet.get_pool_ids(acc_0_index, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // Try to decommission the pool with default account
    let pool_id = pool_ids.first().unwrap().0;
    let decommission_cmd_res = wallet.decommission_stake_pool(
        acc_0_index,
        pool_id,
        pool_amount,
        None,
        FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
    );
    assert_eq!(
        decommission_cmd_res.unwrap_err(),
        WalletError::PartiallySignedTransactionInDecommissionCommand
    );

    // Decommission from the account that holds the key
    let decommission_tx = wallet
        .decommission_stake_pool(
            acc_1_index,
            pool_id,
            pool_amount,
            None,
            FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![decommission_tx],
        Amount::ZERO,
        2,
    );

    let coin_balance = get_coin_balance_for_acc(&wallet, acc_1_index);
    assert_eq!(coin_balance, pool_amount);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_request_wrong_account(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let acc_0_index = DEFAULT_ACCOUNT_INDEX;
    let acc_1_index = U31::ONE;

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let pool_ids = wallet.get_pool_ids(acc_0_index, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = block1_amount;

    let res = wallet.create_next_account(Some("name".into())).unwrap();
    assert_eq!(res, (U31::from_u32(1).unwrap(), Some("name".into())));

    let decommission_key = wallet.get_new_address(acc_1_index).unwrap().1;

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            acc_0_index,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.into_object(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    let pool_ids = wallet.get_pool_ids(acc_0_index, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // Try to create decommission request from account that holds the key
    let pool_id = pool_ids.first().unwrap().0;
    let decommission_req_res = wallet.decommission_stake_pool_request(
        acc_1_index,
        pool_id,
        pool_amount,
        None,
        FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
    );
    assert_eq!(
        decommission_req_res.unwrap_err(),
        WalletError::FullySignedTransactionInDecommissionReq
    );

    let decommission_partial_tx = wallet
        .decommission_stake_pool_request(
            acc_0_index,
            pool_id,
            pool_amount,
            None,
            FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
        )
        .unwrap();
    assert!(!decommission_partial_tx.all_signatures_available());
    matches!(
        decommission_partial_tx.into_signed_tx().unwrap_err(),
        PartiallySignedTransactionCreationError::FailedToConvertPartiallySignedTx(_)
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_decommission_pool_request_between_accounts(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let acc_0_index = DEFAULT_ACCOUNT_INDEX;
    let acc_1_index = U31::ONE;

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let (addr, _) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);
    let utxo = make_address_output(addr.clone(), block1_amount);

    let pool_ids = wallet.get_pool_ids(acc_0_index, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = block1_amount;

    let res = wallet.create_next_account(Some("name".into())).unwrap();
    assert_eq!(res, (U31::from_u32(1).unwrap(), Some("name".into())));

    let decommission_key = wallet.get_new_address(acc_1_index).unwrap().1;

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            acc_0_index,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.into_object(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();

    // remove the signatures and try to sign it again
    let tx = stake_pool_transaction.transaction().clone();
    let inps = tx.inputs().len();
    let ptx = PartiallySignedTransaction::new(
        tx,
        vec![None; inps],
        vec![Some(utxo)],
        vec![Some(addr.into_object())],
        None,
        TxAdditionalInfo::new(),
    )
    .unwrap();
    let stake_pool_transaction = wallet
        .sign_raw_transaction(acc_0_index, ptx)
        .unwrap()
        .0
        .into_signed_tx()
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    assert_eq!(get_coin_balance(&wallet), Amount::ZERO);

    let pool_ids = wallet.get_pool_ids(acc_0_index, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_id = pool_ids.first().unwrap().0;
    let decommission_partial_tx = wallet
        .decommission_stake_pool_request(
            acc_0_index,
            pool_id,
            pool_amount,
            None,
            FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
        )
        .unwrap();

    // Try to sign decommission request with wrong account
    let sign_from_acc0_res = wallet
        .sign_raw_transaction(acc_0_index, decommission_partial_tx.clone())
        .unwrap()
        .0;
    // the tx is still not fully signed
    assert!(!sign_from_acc0_res.all_signatures_available());

    let signed_tx = wallet
        .sign_raw_transaction(acc_1_index, decommission_partial_tx)
        .unwrap()
        .0
        .into_signed_tx()
        .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![signed_tx], Amount::ZERO, 2);

    // the pool amount is back after decommission
    assert_eq!(get_coin_balance(&wallet), pool_amount);
    assert_eq!(get_coin_balance_for_acc(&wallet, acc_1_index), Amount::ZERO);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_decommission_pool_request_cold_wallet(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut hot_wallet = create_wallet(chain_config.clone());

    // create cold wallet that is not synced and only contains decommission key
    let another_mnemonic =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mut cold_wallet = create_wallet_with_mnemonic(chain_config.clone(), another_mnemonic);
    let decommission_key = cold_wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let coin_balance = get_coin_balance(&hot_wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut hot_wallet, vec![], block1_amount, 0);

    let pool_ids = hot_wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&hot_wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = block1_amount;

    let res = hot_wallet.create_next_account(Some("name".into())).unwrap();
    assert_eq!(res, (U31::from_u32(1).unwrap(), Some("name".into())));

    let stake_pool_transaction = hot_wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.into_object(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();
    let _ = create_block(
        &chain_config,
        &mut hot_wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    let pool_ids = hot_wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_id = pool_ids.first().unwrap().0;
    let decommission_partial_tx = hot_wallet
        .decommission_stake_pool_request(
            DEFAULT_ACCOUNT_INDEX,
            pool_id,
            pool_amount,
            None,
            FeeRate::from_amount_per_kb(Amount::from_atoms(0)),
        )
        .unwrap();

    // sign the tx with cold wallet
    let partially_signed_transaction = cold_wallet
        .sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, decommission_partial_tx)
        .unwrap()
        .0;
    assert!(partially_signed_transaction.all_signatures_available());

    // sign it with the hot wallet should leave the signatures in place even if it can't find the
    // destinations for the inputs
    let partially_signed_transaction = hot_wallet
        .sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, partially_signed_transaction)
        .unwrap()
        .0;
    assert!(partially_signed_transaction.all_signatures_available());

    let signed_tx = partially_signed_transaction.into_signed_tx().unwrap();

    let _ = create_block(
        &chain_config,
        &mut hot_wallet,
        vec![signed_tx],
        Amount::ZERO,
        2,
    );

    let coin_balance = get_coin_balance(&hot_wallet);
    assert_eq!(coin_balance, pool_amount,);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn filter_pools(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet1 = create_wallet(chain_config.clone());

    // create another wallet to store decommission key
    let another_mnemonic =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), another_mnemonic);
    let decommission_key = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);
    let _ = create_block(&chain_config, &mut wallet2, vec![], block1_amount, 0);

    let pool_ids = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let pool_ids = wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let pool_amount = block1_amount;

    let stake_pool_transaction = wallet1
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: decommission_key.into_object(),
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();
    // sync for wallet1
    let _ = create_block(
        &chain_config,
        &mut wallet1,
        vec![stake_pool_transaction.clone()],
        Amount::ZERO,
        1,
    );
    // sync for wallet2
    let _ = create_block(
        &chain_config,
        &mut wallet2,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    // check wallet1 filter
    let pool_ids = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_ids = wallet1
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert_eq!(pool_ids.len(), 0);

    let pool_ids = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // check wallet2 filter
    let pool_ids = wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_ids = wallet2
        .get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Decommission)
        .unwrap();
    assert_eq!(pool_ids.len(), 1);

    let pool_ids = wallet2.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::Stake).unwrap();
    assert_eq!(pool_ids.len(), 0);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_send_request_cold_wallet(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut hot_wallet = create_wallet(chain_config.clone());

    // create cold wallet that is not synced
    let another_mnemonic =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mut cold_wallet = create_wallet_with_mnemonic(chain_config.clone(), another_mnemonic);
    let cold_wallet_address = cold_wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let coin_balance = get_coin_balance(&hot_wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the cold wallet address
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let reward_output = make_address_output(cold_wallet_address.clone(), block1_amount);
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![reward_output.clone()]),
    )
    .unwrap();

    scan_wallet(&mut hot_wallet, BlockHeight::new(0), vec![block1.clone()]);

    // hot wallet has 0 balance
    let coin_balance = get_coin_balance(&hot_wallet);
    assert_eq!(coin_balance, Amount::ZERO);
    let hot_wallet_address = hot_wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let to_send = Amount::from_atoms(1);
    let (send_req, _) = hot_wallet
        .create_unsigned_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::Transfer(OutputValue::Coin(to_send), hot_wallet_address.into_object())],
            SelectedInputs::Inputs(vec![(
                UtxoOutPoint::new(OutPointSourceId::BlockReward(block1.get_id().into()), 0),
                reward_output,
            )]),
            None,
            [(Currency::Coin, cold_wallet_address.clone())].into(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    // Try to sign request with the hot wallet
    let tx = hot_wallet
        .sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, send_req.clone())
        .unwrap()
        .0;
    // the tx is not fully signed
    assert!(!tx.all_signatures_available());

    // sign the tx with cold wallet
    let signed_tx = cold_wallet
        .sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, send_req)
        .unwrap()
        .0
        .into_signed_tx()
        .unwrap();

    let (_, block2) = create_block(
        &chain_config,
        &mut hot_wallet,
        vec![signed_tx],
        Amount::ZERO,
        1,
    );

    let coin_balance = get_coin_balance(&hot_wallet);
    assert_eq!(coin_balance, to_send,);

    // update cold wallet just to check the balance and utxos
    cold_wallet
        .scan_new_blocks(
            DEFAULT_ACCOUNT_INDEX,
            BlockHeight::new(0),
            vec![block1, block2],
            &WalletEventsNoOp,
        )
        .unwrap();

    let balance = (block1_amount - to_send).unwrap();
    assert_eq!(get_coin_balance(&cold_wallet), balance);

    let mut utxos = cold_wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();

    assert_eq!(utxos.len(), 1);
    let (_, output) = utxos.pop().unwrap();

    matches!(output, TxOutput::Transfer(OutputValue::Coin(value), dest)
            if value == balance && dest == cold_wallet_address.into_object());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_not_exhaustion_of_keys(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);
    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    // Generate a new block which sends reward to the cold wallet address
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let reward_output = make_address_output(address.clone(), block1_amount);
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![reward_output.clone()]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1.clone()]);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // can create 100 txs but will not run out of change addresses
    for _ in 0..100 {
        wallet
            .create_transaction_to_addresses(
                DEFAULT_ACCOUNT_INDEX,
                [TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(1)),
                    address.as_object().clone(),
                )],
                SelectedInputs::Inputs(vec![]),
                [].into(),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                TxAdditionalInfo::new(),
            )
            .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_add_standalone_private_key(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);
    // generate a random private key unrelated to the wallet and add it
    let (private_key, pub_key) =
        crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    wallet
        .add_standalone_private_key(DEFAULT_ACCOUNT_INDEX, private_key, None)
        .unwrap();

    // get the destination address from the new private key and send some coins to it
    let address =
        Address::new(&chain_config, Destination::PublicKeyHash((&pub_key).into())).unwrap();

    // Generate a new block which sends reward to the new address
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let output = make_address_output(address.clone(), block1_amount);

    let tx =
        SignedTransaction::new(Transaction::new(0, vec![], vec![output]).unwrap(), vec![]).unwrap();

    let block1 = Block::new(
        vec![tx.clone()],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1.clone()]);

    // Check amount is still zero
    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // but the transaction has been added to the wallet
    let tx_data = wallet
        .get_transaction(DEFAULT_ACCOUNT_INDEX, tx.transaction().get_id())
        .unwrap();

    assert_eq!(tx_data.get_transaction(), tx.transaction());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_add_standalone_multisig(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet1 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, Amount::ZERO);
    let coin_balance = get_coin_balance(&wallet2);
    assert_eq!(coin_balance, Amount::ZERO);

    let (_, address1) = wallet1.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key1 = wallet1.find_public_key(DEFAULT_ACCOUNT_INDEX, address1.into_object()).unwrap();

    let (_, address2) = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key2 = wallet2.find_public_key(DEFAULT_ACCOUNT_INDEX, address2.into_object()).unwrap();
    let (_, address3) = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key3 = wallet2.find_public_key(DEFAULT_ACCOUNT_INDEX, address3.into_object()).unwrap();

    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![pub_key3, pub_key2, pub_key1],
    )
    .unwrap();
    let multisig_hash = wallet1
        .add_standalone_multisig(DEFAULT_ACCOUNT_INDEX, challenge.clone(), None)
        .unwrap();

    let multisig_address =
        Address::new(&chain_config, Destination::ClassicMultisig(multisig_hash)).unwrap();

    // Generate a new block which sends reward to the new multisig address
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let output = make_address_output(multisig_address.clone(), block1_amount);

    let tx =
        SignedTransaction::new(Transaction::new(0, vec![], vec![output]).unwrap(), vec![]).unwrap();

    let block1 = Block::new(
        vec![tx.clone()],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap();

    scan_wallet(&mut wallet1, BlockHeight::new(0), vec![block1.clone()]);

    // Check amount is still zero
    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, Amount::ZERO);

    // but the transaction has been added to the wallet
    let tx_data = wallet1
        .get_transaction(DEFAULT_ACCOUNT_INDEX, tx.transaction().get_id())
        .unwrap();

    assert_eq!(tx_data.get_transaction(), tx.transaction());

    let spend_multisig_tx = Transaction::new(
        0,
        vec![TxInput::from_utxo(OutPointSourceId::Transaction(tx.transaction().get_id()), 0)],
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            Destination::AnyoneCanSpend,
        )],
    )
    .unwrap();
    let spend_multisig_tx = PartiallySignedTransaction::new(
        spend_multisig_tx,
        vec![None; 1],
        vec![Some(tx.outputs()[0].clone())],
        vec![Some(multisig_address.as_object().clone())],
        None,
        TxAdditionalInfo::new(),
    )
    .unwrap();

    // sign it with wallet1
    let (ptx, _, statuses) =
        wallet1.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, spend_multisig_tx).unwrap();

    // check it is still not fully signed
    assert!(ptx.all_signatures_available());
    assert!(!statuses.iter().all(|s| *s == SignatureStatus::FullySigned));

    // try to sign it with wallet1 again
    let (ptx, _, statuses) = wallet1.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, ptx).unwrap();

    // check it is still not fully signed
    assert!(ptx.all_signatures_available());
    assert!(!statuses.iter().all(|s| *s == SignatureStatus::FullySigned));

    // try to sign it with wallet2 but wallet2 does not have the multisig added as standalone
    let ptx = wallet2.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, ptx).unwrap().0;

    // add it to wallet2 as well
    wallet2.add_standalone_multisig(DEFAULT_ACCOUNT_INDEX, challenge, None).unwrap();

    // now we can sign it
    let (ptx, _, statuses) = wallet2.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, ptx).unwrap();

    // now it is fully signed
    assert!(ptx.all_signatures_available());
    assert!(statuses.iter().all(|s| *s == SignatureStatus::FullySigned));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_htlc_and_spend(#[case] seed: Seed) {
    use common::chain::htlc::HtlcSecret;

    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet1 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, block1_amount);

    let (_, address1) = wallet1.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key1 = wallet1.find_public_key(DEFAULT_ACCOUNT_INDEX, address1.into_object()).unwrap();

    let (_, address2) = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key2 = wallet2
        .find_public_key(DEFAULT_ACCOUNT_INDEX, address2.clone().into_object())
        .unwrap();

    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![pub_key1, pub_key2],
    )
    .unwrap();
    let multisig_hash = wallet1
        .add_standalone_multisig(DEFAULT_ACCOUNT_INDEX, challenge.clone(), None)
        .unwrap();
    wallet2
        .add_standalone_multisig(DEFAULT_ACCOUNT_INDEX, challenge.clone(), None)
        .unwrap();

    let secret = HtlcSecret::new_from_rng(&mut rng);
    let spend_key = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let htlc = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: spend_key.clone().into_object(),
        refund_timelock: OutputTimeLock::ForBlockCount(1),
        refund_key: Destination::ClassicMultisig(multisig_hash),
    };
    let output_value = OutputValue::Coin(coin_balance);

    let create_htlc_tx = wallet1
        .create_htlc_tx(
            DEFAULT_ACCOUNT_INDEX,
            output_value.clone(),
            htlc.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();
    let create_htlc_tx_id = create_htlc_tx.transaction().get_id();
    let (_, block2) = create_block(
        &chain_config,
        &mut wallet1,
        vec![create_htlc_tx.clone()],
        Amount::ZERO,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block2]);

    // Htlc is not accounted in balance
    assert_eq!(get_coin_balance(&wallet1), Amount::ZERO);
    assert_eq!(get_coin_balance(&wallet2), Amount::ZERO);

    // Htlc is available as utxo to spend
    let wallet1_utxos = wallet1
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Htlc.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Any,
        )
        .unwrap();
    assert!(wallet1_utxos.is_empty());
    let mut wallet2_utxos = wallet2
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Htlc.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Any,
        )
        .unwrap();
    assert_eq!(wallet2_utxos.len(), 1);
    let (_, output) = wallet2_utxos.pop().unwrap();
    match output {
        TxOutput::Htlc(actual_output_value, actual_htlc) => {
            assert_eq!(actual_output_value, output_value);
            assert_eq!(htlc, *actual_htlc);
        }
        _ => panic!("wrong TxOutput type"),
    };

    // spend with a secret
    let spend_tx = Transaction::new(
        0,
        vec![TxInput::from_utxo(create_htlc_tx_id.into(), 0)],
        vec![TxOutput::Transfer(output_value, address2.into_object())],
    )
    .unwrap();
    let spend_utxos = vec![create_htlc_tx.transaction().outputs().first().cloned()];
    let spend_ptx = PartiallySignedTransaction::new(
        spend_tx,
        vec![None],
        spend_utxos,
        vec![Some(spend_key.into_object())],
        Some(vec![Some(secret)]),
        TxAdditionalInfo::new(),
    )
    .unwrap();

    let (spend_ptx, _, new_statuses) =
        wallet2.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, spend_ptx).unwrap();
    assert_eq!(vec![SignatureStatus::FullySigned], new_statuses);

    let spend_tx = spend_ptx.into_signed_tx().unwrap();

    let (_, block2) = create_block(&chain_config, &mut wallet2, vec![spend_tx], Amount::ZERO, 1);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block2]);

    // Coins from htlc successfully transferred
    assert_eq!(get_coin_balance(&wallet1), Amount::ZERO);
    assert_eq!(get_coin_balance(&wallet2), coin_balance);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_htlc_and_refund(#[case] seed: Seed) {
    use common::chain::htlc::HtlcSecret;

    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_regtest());

    let mut wallet1 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000));
    let _ = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, block1_amount);
    assert_eq!(get_coin_balance(&wallet2), Amount::ZERO);

    let (_, address1) = wallet1.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key1 = wallet1
        .find_public_key(DEFAULT_ACCOUNT_INDEX, address1.clone().into_object())
        .unwrap();

    let (_, address2) = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap();
    let pub_key2 = wallet2.find_public_key(DEFAULT_ACCOUNT_INDEX, address2.into_object()).unwrap();

    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![pub_key1, pub_key2],
    )
    .unwrap();
    let multisig_hash = wallet1
        .add_standalone_multisig(DEFAULT_ACCOUNT_INDEX, challenge.clone(), None)
        .unwrap();
    wallet2
        .add_standalone_multisig(DEFAULT_ACCOUNT_INDEX, challenge.clone(), None)
        .unwrap();

    let secret = HtlcSecret::new_from_rng(&mut rng);
    let spend_key = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let refund_key = Destination::ClassicMultisig(multisig_hash);
    let htlc = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: spend_key.into_object(),
        refund_timelock: OutputTimeLock::ForBlockCount(1),
        refund_key: refund_key.clone(),
    };
    let output_value = OutputValue::Coin(coin_balance);

    let create_htlc_tx = wallet1
        .create_htlc_tx(
            DEFAULT_ACCOUNT_INDEX,
            output_value.clone(),
            htlc.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();
    let create_htlc_tx_id = create_htlc_tx.transaction().get_id();

    let refund_tx = Transaction::new(
        0,
        vec![TxInput::from_utxo(create_htlc_tx_id.into(), 0)],
        vec![TxOutput::Transfer(output_value, address1.into_object())],
    )
    .unwrap();
    let refund_utxos = vec![create_htlc_tx.transaction().outputs().first().cloned()];
    let refund_ptx = PartiallySignedTransaction::new(
        refund_tx,
        vec![None],
        refund_utxos,
        vec![Some(refund_key)],
        None,
        TxAdditionalInfo::new(),
    )
    .unwrap();

    let (_, block2) = create_block(
        &chain_config,
        &mut wallet1,
        vec![create_htlc_tx],
        Amount::ZERO,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block2]);

    // Htlc is not accounted in balance
    assert_eq!(get_coin_balance(&wallet1), Amount::ZERO);
    assert_eq!(get_coin_balance(&wallet2), Amount::ZERO);

    let wallet1_multisig_utxos = wallet1
        .get_multisig_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoTypes::ALL,
            UtxoStates::ALL,
            WithLocked::Any,
        )
        .unwrap();
    assert_eq!(wallet1_multisig_utxos.len(), 1);
    let wallet2_multisig_utxos = wallet2
        .get_multisig_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoTypes::ALL,
            UtxoStates::ALL,
            WithLocked::Any,
        )
        .unwrap();
    assert_eq!(wallet2_multisig_utxos.len(), 1);

    let (refund_ptx, prev_statuses, new_statuses) =
        wallet2.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, refund_ptx).unwrap();

    assert_eq!(vec![SignatureStatus::NotSigned], prev_statuses);
    assert_eq!(
        vec![SignatureStatus::PartialMultisig {
            required_signatures: 2,
            num_signatures: 1
        }],
        new_statuses
    );

    let (refund_ptx, prev_statuses, new_statuses) =
        wallet1.sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, refund_ptx).unwrap();
    assert_eq!(
        vec![SignatureStatus::PartialMultisig {
            required_signatures: 2,
            num_signatures: 1
        }],
        prev_statuses
    );
    assert_eq!(vec![SignatureStatus::FullySigned], new_statuses);

    let refund_tx = refund_ptx.into_signed_tx().unwrap();

    let (_, block3) = create_block(
        &chain_config,
        &mut wallet1,
        vec![refund_tx],
        Amount::ZERO,
        2,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block3]);

    // Refund can be seen in the wallet balance
    assert_eq!(get_coin_balance(&wallet1), coin_balance);
    assert_eq!(get_coin_balance(&wallet2), Amount::ZERO);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // Issue a token
    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let token_issuance =
        random_token_issuance_v1(&chain_config, address2.as_object().clone(), &mut rng);
    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );

    // Mint some tokens
    let freezable = token_issuance.is_freezable.as_bool();
    let token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(2..100));
    let mint_transaction = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![mint_transaction],
        Amount::ZERO,
        2,
    );

    let expected_balance = (block1_amount - chain_config.fungible_token_issuance_fee()).unwrap();
    let (coin_balance, token_balances) = get_currency_balances(&wallet);
    assert_eq!(coin_balance, expected_balance);
    assert_eq!(
        token_balances.first(),
        Some(&(issued_token_id, token_amount_to_mint))
    );

    // Create an order selling tokens for coins
    let ask_value = OutputValue::Coin(Amount::from_atoms(111));
    let give_value = OutputValue::TokenV1(issued_token_id, token_amount_to_mint);
    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let (_, create_order_tx) = wallet
        .create_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            ask_value.clone(),
            give_value.clone(),
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![create_order_tx],
        Amount::ZERO,
        3,
    );

    let (coin_balance, token_balances) = get_currency_balances(&wallet);
    assert_eq!(coin_balance, expected_balance);
    assert!(token_balances.is_empty());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_and_conclude(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // Issue a token
    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let token_issuance =
        random_token_issuance_v1(&chain_config, address2.as_object().clone(), &mut rng);
    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );

    // Mint some tokens
    let freezable = token_issuance.is_freezable.as_bool();
    let token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(2..100));
    let mint_transaction = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![mint_transaction],
        Amount::ZERO,
        2,
    );

    let expected_balance = (block1_amount - chain_config.fungible_token_issuance_fee()).unwrap();
    let (coin_balance, token_balances) = get_currency_balances(&wallet);
    assert_eq!(coin_balance, expected_balance);
    assert_eq!(
        token_balances.first(),
        Some(&(issued_token_id, token_amount_to_mint))
    );

    // Create an order selling tokens for coins
    let ask_value = OutputValue::Coin(Amount::from_atoms(111));
    let give_value = OutputValue::TokenV1(issued_token_id, token_amount_to_mint);
    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let (order_id, create_order_tx) = wallet
        .create_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            ask_value.clone(),
            give_value.clone(),
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();
    let order_info = RpcOrderInfo {
        conclude_key: address2.clone().into_object(),
        initially_asked: RpcOutputValue::Coin {
            amount: Amount::from_atoms(111),
        },
        initially_given: RpcOutputValue::Token {
            id: issued_token_id,
            amount: token_amount_to_mint,
        },
        give_balance: token_amount_to_mint,
        ask_balance: Amount::from_atoms(111),
        nonce: None,
    };

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![create_order_tx],
        Amount::ZERO,
        3,
    );

    let (coin_balance, token_balances) = get_currency_balances(&wallet);
    assert_eq!(coin_balance, expected_balance);
    assert!(token_balances.is_empty());

    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let conclude_order_tx = wallet
        .create_conclude_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info,
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![conclude_order_tx],
        Amount::ZERO,
        4,
    );

    let (coin_balance, token_balances) = get_currency_balances(&wallet);
    assert_eq!(coin_balance, expected_balance);
    assert_eq!(
        token_balances.first(),
        Some(&(issued_token_id, token_amount_to_mint))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_fill_completely_conclude(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet1 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    assert_eq!(get_coin_balance(&wallet1), Amount::ZERO);
    assert_eq!(get_coin_balance(&wallet2), Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let (_, block1) = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block1]);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, block1_amount);

    // Issue a token
    let address1 = wallet1.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let token_issuance =
        random_token_issuance_v1(&chain_config, address1.as_object().clone(), &mut rng);
    let (issued_token_id, token_issuance_transaction) = wallet1
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let (_, block2) = create_block(
        &chain_config,
        &mut wallet1,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(1), vec![block2]);

    // Mint some tokens
    let address2 = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let freezable = token_issuance.is_freezable.as_bool();
    let token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet1
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let token_amount_to_mint = Amount::from_atoms(100);
    let mint_transaction = wallet1
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let (_, block3) = create_block(
        &chain_config,
        &mut wallet2,
        vec![mint_transaction],
        Amount::from_atoms(NETWORK_FEE),
        2,
    );
    scan_wallet(&mut wallet1, BlockHeight::new(2), vec![block3]);

    {
        let expected_balance =
            (block1_amount - chain_config.fungible_token_issuance_fee()).unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty(),);
    }

    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE));
        assert_eq!(
            token_balances.first(),
            Some(&(issued_token_id, token_amount_to_mint))
        );
    }

    // Create an order selling coins for tokens
    let ask_value = OutputValue::TokenV1(issued_token_id, token_amount_to_mint);
    let sell_amount = Amount::from_atoms(1000);
    let give_value = OutputValue::Coin(sell_amount);
    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let (order_id, create_order_tx) = wallet1
        .create_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            ask_value.clone(),
            give_value.clone(),
            address1.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();
    let order_info = RpcOrderInfo {
        conclude_key: address1.clone().into_object(),
        initially_asked: RpcOutputValue::Token {
            id: issued_token_id,
            amount: token_amount_to_mint,
        },
        initially_given: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: sell_amount,
        ask_balance: token_amount_to_mint,
        nonce: None,
    };

    let (_, block4) = create_block(
        &chain_config,
        &mut wallet1,
        vec![create_order_tx],
        Amount::ZERO,
        3,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(3), vec![block4]);

    {
        let expected_balance =
            ((block1_amount - chain_config.fungible_token_issuance_fee()).unwrap() - sell_amount)
                .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty());
    }

    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE));
        assert_eq!(
            token_balances.first(),
            Some(&(issued_token_id, token_amount_to_mint))
        );
    }
    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );

    // Fill order partially
    let fill_order_tx_1 = wallet2
        .create_fill_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info,
            Amount::from_atoms(10),
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let (_, block5) = create_block(
        &chain_config,
        &mut wallet2,
        vec![fill_order_tx_1],
        Amount::ZERO,
        4,
    );
    scan_wallet(&mut wallet1, BlockHeight::new(4), vec![block5]);

    {
        let expected_balance =
            ((block1_amount - chain_config.fungible_token_issuance_fee()).unwrap() - sell_amount)
                .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty());
    }
    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE + 100));
        assert_eq!(
            token_balances.first(),
            Some(&(
                issued_token_id,
                (token_amount_to_mint - Amount::from_atoms(10)).unwrap()
            ))
        );
    }

    // Fill order completely
    let order_info = RpcOrderInfo {
        conclude_key: address1.clone().into_object(),
        initially_asked: RpcOutputValue::Token {
            id: issued_token_id,
            amount: token_amount_to_mint,
        },
        initially_given: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: (sell_amount - Amount::from_atoms(100)).unwrap(),
        ask_balance: (token_amount_to_mint - Amount::from_atoms(10)).unwrap(),
        nonce: Some(AccountNonce::new(0)),
    };

    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let fill_order_tx_2 = wallet2
        .create_fill_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info,
            (token_amount_to_mint - Amount::from_atoms(10)).unwrap(),
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let (_, block6) = create_block(
        &chain_config,
        &mut wallet2,
        vec![fill_order_tx_2],
        Amount::ZERO,
        5,
    );
    scan_wallet(&mut wallet1, BlockHeight::new(5), vec![block6]);

    {
        let expected_balance =
            ((block1_amount - chain_config.fungible_token_issuance_fee()).unwrap() - sell_amount)
                .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty());
    }
    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE + 1000));
        assert!(token_balances.is_empty());
    }

    // Conclude the order
    let order_info = RpcOrderInfo {
        conclude_key: address1.clone().into_object(),
        initially_asked: RpcOutputValue::Token {
            id: issued_token_id,
            amount: token_amount_to_mint,
        },
        initially_given: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: Amount::ZERO,
        ask_balance: Amount::ZERO,
        nonce: Some(AccountNonce::new(1)),
    };
    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let conclude_order_tx = wallet1
        .create_conclude_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info,
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let (_, block7) = create_block(
        &chain_config,
        &mut wallet1,
        vec![conclude_order_tx],
        Amount::ZERO,
        6,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(6), vec![block7]);

    {
        let expected_balance =
            ((block1_amount - chain_config.fungible_token_issuance_fee()).unwrap() - sell_amount)
                .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert_eq!(
            token_balances.first(),
            Some(&(issued_token_id, Amount::from_atoms(100)))
        );
    }
    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE + 1000));
        assert!(token_balances.is_empty());
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_fill_partially_conclude(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet1 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);
    let mut wallet2 = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC2);

    assert_eq!(get_coin_balance(&wallet1), Amount::ZERO);
    assert_eq!(get_coin_balance(&wallet2), Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = (Amount::from_atoms(rng.gen_range(NETWORK_FEE + 100..NETWORK_FEE + 10000))
        + chain_config.fungible_token_issuance_fee())
    .unwrap();

    let (_, block1) = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block1]);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, block1_amount);

    // Issue a token
    let address1 = wallet1.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let token_issuance =
        random_token_issuance_v1(&chain_config, address1.as_object().clone(), &mut rng);
    let (issued_token_id, token_issuance_transaction) = wallet1
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let (_, block2) = create_block(
        &chain_config,
        &mut wallet1,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(1), vec![block2]);

    // Mint some tokens
    let address2 = wallet2.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let freezable = token_issuance.is_freezable.as_bool();
    let token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info = wallet1
        .get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info.clone())
        .unwrap();

    let token_amount_to_mint = Amount::from_atoms(100);
    let mint_transaction = wallet1
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let (_, block3) = create_block(
        &chain_config,
        &mut wallet2,
        vec![mint_transaction],
        Amount::from_atoms(NETWORK_FEE),
        2,
    );
    scan_wallet(&mut wallet1, BlockHeight::new(2), vec![block3]);

    {
        let expected_balance =
            (block1_amount - chain_config.fungible_token_issuance_fee()).unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty(),);
    }

    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE));
        assert_eq!(
            token_balances.first(),
            Some(&(issued_token_id, token_amount_to_mint))
        );
    }

    // Create an order selling coins for tokens
    let ask_value = OutputValue::TokenV1(issued_token_id, token_amount_to_mint);
    let sell_amount = Amount::from_atoms(1000);
    let give_value = OutputValue::Coin(sell_amount);
    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let (order_id, create_order_tx) = wallet1
        .create_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            ask_value.clone(),
            give_value.clone(),
            address1.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();
    let order_info = RpcOrderInfo {
        conclude_key: address1.clone().into_object(),
        initially_asked: RpcOutputValue::Token {
            id: issued_token_id,
            amount: token_amount_to_mint,
        },
        initially_given: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: sell_amount,
        ask_balance: token_amount_to_mint,
        nonce: None,
    };

    let (_, block4) = create_block(
        &chain_config,
        &mut wallet1,
        vec![create_order_tx],
        Amount::ZERO,
        3,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(3), vec![block4]);

    {
        let expected_balance =
            ((block1_amount - chain_config.fungible_token_issuance_fee()).unwrap() - sell_amount)
                .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty());
    }

    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE));
        assert_eq!(
            token_balances.first(),
            Some(&(issued_token_id, token_amount_to_mint))
        );
    }

    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    // Fill order partially
    let fill_order_tx_1 = wallet2
        .create_fill_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info,
            Amount::from_atoms(10),
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let (_, block5) = create_block(
        &chain_config,
        &mut wallet2,
        vec![fill_order_tx_1],
        Amount::ZERO,
        4,
    );
    scan_wallet(&mut wallet1, BlockHeight::new(4), vec![block5]);

    {
        let expected_balance =
            ((block1_amount - chain_config.fungible_token_issuance_fee()).unwrap() - sell_amount)
                .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert!(token_balances.is_empty());
    }
    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE + 100));
        assert_eq!(
            token_balances.first(),
            Some(&(
                issued_token_id,
                (token_amount_to_mint - Amount::from_atoms(10)).unwrap()
            ))
        );
    }

    // Conclude the order
    let order_info = RpcOrderInfo {
        conclude_key: address1.clone().into_object(),
        initially_asked: RpcOutputValue::Token {
            id: issued_token_id,
            amount: token_amount_to_mint,
        },
        initially_given: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: (sell_amount - Amount::from_atoms(100)).unwrap(),
        ask_balance: (token_amount_to_mint - Amount::from_atoms(10)).unwrap(),
        nonce: Some(AccountNonce::new(0)),
    };

    let additional_info = TxAdditionalInfo::with_token_info(
        issued_token_id,
        TokenAdditionalInfo {
            num_decimals: unconfirmed_token_info.num_decimals(),
            ticker: unconfirmed_token_info.token_ticker().to_vec(),
        },
    );
    let conclude_order_tx = wallet1
        .create_conclude_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info,
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            additional_info,
        )
        .unwrap();

    let (_, block6) = create_block(
        &chain_config,
        &mut wallet1,
        vec![conclude_order_tx],
        Amount::ZERO,
        5,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(5), vec![block6]);

    {
        let expected_balance = ((block1_amount - chain_config.fungible_token_issuance_fee())
            .unwrap()
            - Amount::from_atoms(100))
        .unwrap();
        let (coin_balance, token_balances) = get_currency_balances(&wallet1);
        assert_eq!(coin_balance, expected_balance);
        assert_eq!(
            token_balances.first(),
            Some(&(issued_token_id, Amount::from_atoms(10)))
        );
    }
    {
        let (coin_balance, token_balances) = get_currency_balances(&wallet2);
        assert_eq!(coin_balance, Amount::from_atoms(NETWORK_FEE + 100));
        assert_eq!(
            token_balances.first(),
            Some(&(
                issued_token_id,
                (token_amount_to_mint - Amount::from_atoms(10)).unwrap()
            ))
        );
    }
}

// Create 2 wallets from the same mnemonic.
// Create a pool and a delegation with some stake for both wallets.
// Add 2 consecutive txs that spend share from delegation to the first wallet as unconfirmed.
// Add 1 txs that spends share from delegation with different amount (so that tx id is different)
// via the second wallet and submit it to the block.
// Check that 2 unconfirmed txs from the first wallet conflict with confirmed tx and got removed.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conflicting_delegation_account_nonce(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet1 = create_wallet(chain_config.clone());
    let mut wallet2 = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(10..100));
    let block1_amount = (chain_config.min_stake_pool_pledge() + delegation_amount).unwrap();
    let (_, block1) = create_block(&chain_config, &mut wallet1, vec![], block1_amount, 0);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block1]);

    let pool_ids = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, block1_amount);

    // Create a pool
    let pool_amount = chain_config.min_stake_pool_pledge();

    let stake_pool_transaction = wallet1
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: Destination::AnyoneCanSpend,
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();

    let (address, block2) = create_block(
        &chain_config,
        &mut wallet1,
        vec![stake_pool_transaction.clone()],
        Amount::ZERO,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(1), vec![block2]);

    let coin_balance = get_coin_balance(&wallet1);
    assert_eq!(coin_balance, (block1_amount - pool_amount).unwrap(),);

    let pool_ids = wallet1.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // Create a delegation
    let pool_id = pool_ids.first().unwrap().0;
    let (delegation_id, delegation_tx) = wallet1
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address.clone(), pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let (_, block3) = create_block(
        &chain_config,
        &mut wallet1,
        vec![delegation_tx],
        Amount::ZERO,
        2,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(2), vec![block3]);

    let mut delegations = wallet1.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert!(deleg_data.not_staked_yet);
    assert_eq!(deleg_data.last_nonce, None);
    assert_eq!(deleg_data.pool_id, pool_id);
    assert_eq!(&deleg_data.destination, address.as_object());

    // Delegate some coins
    let delegation_stake_tx = wallet1
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::DelegateStaking(delegation_amount, delegation_id)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let (_, block4) = create_block(
        &chain_config,
        &mut wallet1,
        vec![delegation_stake_tx],
        Amount::ZERO,
        3,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(3), vec![block4]);

    let coin_balance_after_delegating = get_coin_balance(&wallet1);
    assert_eq!(
        coin_balance_after_delegating,
        (block1_amount - pool_amount).and_then(|v| v - delegation_amount).unwrap(),
    );

    // Add unconfirmed txs
    let withdraw_amount_1 = Amount::from_atoms(1);
    let spend_from_delegation_tx_1 = wallet1
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_1,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    let spend_from_delegation_tx_1_id = spend_from_delegation_tx_1.transaction().get_id();

    wallet1
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            spend_from_delegation_tx_1.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    let withdraw_amount_2 = withdraw_amount_1;
    let spend_from_delegation_tx_2 = wallet1
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_2,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    let spend_from_delegation_tx_2_id = spend_from_delegation_tx_2.transaction().get_id();

    wallet1
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            spend_from_delegation_tx_2.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Check delegation after unconfirmed tx status
    let mut delegations = wallet1.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(1)));

    // Create and submit tx with different tx id
    let withdraw_amount_3 = Amount::from_atoms(5);
    let spend_from_delegation_tx_3 = wallet2
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_3,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    let spend_from_delegation_tx_3_id = spend_from_delegation_tx_3.transaction().get_id();

    let (_, block5) = create_block(
        &chain_config,
        &mut wallet2,
        vec![spend_from_delegation_tx_3],
        Amount::ZERO,
        4,
    );
    let block5_id = block5.get_id();
    scan_wallet(&mut wallet1, BlockHeight::new(4), vec![block5]);

    // if confirmed tx is added conflicting txs must be removed from the output cache
    let mut delegations = wallet1.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));

    let coin_balance = get_balance_with(
        &wallet1,
        Currency::Coin,
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_3).unwrap()
    );

    let coin_balance = get_balance_with(
        &wallet1,
        Currency::Coin,
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_3).unwrap()
    );

    assert_eq!(
        *wallet1
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_1_id)
            .unwrap()
            .state(),
        TxState::Conflicted(block5_id.into())
    );
    assert_eq!(
        *wallet1
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_2_id)
            .unwrap()
            .state(),
        TxState::Conflicted(block5_id.into())
    );
    assert_eq!(
        *wallet1
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_3_id)
            .unwrap()
            .state(),
        TxState::Confirmed(
            BlockHeight::new(5),
            chain_config.genesis_block().timestamp(),
            0
        )
    );

    // Abandon conflicting txs
    wallet1
        .abandon_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_1_id)
        .unwrap();
    assert_eq!(
        *wallet1
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_1_id)
            .unwrap()
            .state(),
        TxState::Abandoned
    );

    let mut delegations = wallet1.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));

    wallet1
        .abandon_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_2_id)
        .unwrap();
    assert_eq!(
        *wallet1
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_2_id)
            .unwrap()
            .state(),
        TxState::Abandoned
    );

    let mut delegations = wallet1.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));
}

// Create a pool and a delegation with some share.
// Create 2 consecutive txs that spend from delegation account and add them as unconfirmed.
// Check confirmed/unconfirmed balance and ensure that account nonce is incremented in OutputCache.
// Submit the first tx in a block.
// Check that confirmed balance changed and unconfirmed stayed the same.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conflicting_delegation_account_nonce_same_wallet(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(2..100));
    let block1_amount = (chain_config.min_stake_pool_pledge() + delegation_amount).unwrap();
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    // Create a pool
    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    let pool_amount = chain_config.min_stake_pool_pledge();

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: Destination::AnyoneCanSpend,
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();

    let (address, _) = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction],
        Amount::ZERO,
        1,
    );

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, (block1_amount - pool_amount).unwrap(),);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // Create a delegation
    let pool_id = pool_ids.first().unwrap().0;
    let (delegation_id, delegation_tx) = wallet
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address.clone(), pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx],
        Amount::ZERO,
        2,
    );

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert!(deleg_data.not_staked_yet);
    assert_eq!(deleg_data.last_nonce, None);
    assert_eq!(deleg_data.pool_id, pool_id);
    assert_eq!(&deleg_data.destination, address.as_object());

    // Delegate some coins
    let delegation_stake_tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::DelegateStaking(delegation_amount, delegation_id)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_stake_tx],
        Amount::ZERO,
        3,
    );

    let coin_balance_after_delegating = get_coin_balance(&wallet);
    assert_eq!(
        coin_balance_after_delegating,
        (block1_amount - pool_amount).and_then(|v| v - delegation_amount).unwrap(),
    );

    // Create first tx that spends from delegation
    let withdraw_amount_1 = Amount::from_atoms(1);
    let spend_from_delegation_tx_1 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_1,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            spend_from_delegation_tx_1.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Create second tx that spends from delegation
    let withdraw_amount_2 = withdraw_amount_1;
    let spend_from_delegation_tx_2 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_2,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            spend_from_delegation_tx_2.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Check delegation after unconfirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(1)));

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(coin_balance, coin_balance_after_delegating);

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_1)
            .and_then(|v| v + withdraw_amount_2)
            .unwrap()
    );

    // Submit first tx in a block
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![spend_from_delegation_tx_1],
        Amount::ZERO,
        4,
    );

    // Confirmed tx should replace the first one leaving the second one as descendant
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(1)));

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_1).unwrap()
    );

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_1)
            .and_then(|v| v + withdraw_amount_2)
            .unwrap()
    );
}

// Issue and mint some tokens.
// Create an order selling tokens for coins.
// Create 2 fill order txs and add them to a wallet as unconfirmed.
// Confirm the first tx in a block and check that it is accounted in confirmed balance
// and also that unconfirmed balance has second tx.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conflicting_order_account_nonce(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = common::chain::config::create_unit_test_config_builder()
        .chainstate_upgrades(
            common::chain::NetUpgrades::initialize(vec![(
                BlockHeight::zero(),
                ChainstateUpgradeBuilder::latest()
                    .orders_version(common::chain::OrdersVersion::V0)
                    .build(),
            )])
            .expect("cannot fail"),
        )
        .build();
    let chain_config = Arc::new(chain_config);

    let mut wallet = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let block1_amount = chain_config.fungible_token_issuance_fee();
    let _ = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);

    // Issue a token
    let address2 = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    let token_issuance =
        random_token_issuance_v1(&chain_config, address2.as_object().clone(), &mut rng);
    let (issued_token_id, token_issuance_transaction) = wallet
        .issue_new_token(
            DEFAULT_ACCOUNT_INDEX,
            TokenIssuance::V1(token_issuance.clone()),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let block2_amount = chain_config.token_supply_change_fee(BlockHeight::zero());
    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![token_issuance_transaction],
        block2_amount,
        1,
    );

    // Mint some tokens
    let freezable = token_issuance.is_freezable.as_bool();
    let token_info = RPCFungibleTokenInfo::new(
        issued_token_id,
        token_issuance.token_ticker,
        token_issuance.number_of_decimals,
        token_issuance.metadata_uri,
        Amount::ZERO,
        token_issuance.total_supply.into(),
        false,
        RPCIsTokenFrozen::NotFrozen { freezable },
        token_issuance.authority,
    );

    let unconfirmed_token_info =
        wallet.get_token_unconfirmed_info(DEFAULT_ACCOUNT_INDEX, token_info).unwrap();

    let token_amount_to_mint = Amount::from_atoms(100);
    let reward_to_spend_on_orders = Amount::from_atoms(100);
    let mint_transaction = wallet
        .mint_tokens(
            DEFAULT_ACCOUNT_INDEX,
            &unconfirmed_token_info,
            token_amount_to_mint,
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![mint_transaction],
        reward_to_spend_on_orders,
        2,
    );

    // Create an order selling tokens for coins
    let buy_amount = reward_to_spend_on_orders;
    let sell_amount = token_amount_to_mint;
    let ask_value = OutputValue::Coin(buy_amount);
    let give_value = OutputValue::TokenV1(issued_token_id, sell_amount);
    let (order_id, create_order_tx) = wallet
        .create_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            ask_value.clone(),
            give_value.clone(),
            address2.clone(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![create_order_tx],
        Amount::ZERO,
        3,
    );

    let (coin_balance_after_create_order, token_balance_after_create_order) =
        get_currency_balances(&wallet);
    assert_eq!(coin_balance_after_create_order, reward_to_spend_on_orders);
    assert!(token_balance_after_create_order.is_empty());

    let mut orders = wallet.get_orders(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(orders.len(), 1);
    let (actual_order_id, actual_order_data) = orders.pop().unwrap();
    assert_eq!(order_id, *actual_order_id);
    assert_eq!(actual_order_data.last_nonce, None);
    assert_eq!(&actual_order_data.conclude_key, address2.as_object());

    // Create 2 fill order txs and put them in unconfirmed
    let order_info = RpcOrderInfo {
        conclude_key: address2.clone().into_object(),
        initially_given: RpcOutputValue::Token {
            id: issued_token_id,
            amount: buy_amount,
        },
        initially_asked: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: sell_amount,
        ask_balance: buy_amount,
        nonce: None,
    };

    let spend_coins_1 = Amount::from_atoms(10);
    let received_tokens_1 = spend_coins_1;
    let fill_order_tx_1 = wallet
        .create_fill_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info.clone(),
            spend_coins_1,
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            fill_order_tx_1.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    let order_info = RpcOrderInfo {
        conclude_key: address2.clone().into_object(),
        initially_given: RpcOutputValue::Token {
            id: issued_token_id,
            amount: buy_amount,
        },
        initially_asked: RpcOutputValue::Coin {
            amount: sell_amount,
        },
        give_balance: sell_amount,
        ask_balance: buy_amount,
        nonce: Some(AccountNonce::new(0)),
    };

    let spend_coins_2 = Amount::from_atoms(3);
    let received_tokens_2 = spend_coins_2;
    let fill_order_tx_2 = wallet
        .create_fill_order_tx(
            DEFAULT_ACCOUNT_INDEX,
            order_id,
            order_info.clone(),
            spend_coins_2,
            None,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            fill_order_tx_2.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Check order data after unconfirmed tx status
    let mut orders = wallet.get_orders(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(orders.len(), 1);
    let (actual_order_id, order_data) = orders.pop().unwrap();
    assert_eq!(*actual_order_id, order_id);
    assert_eq!(order_data.last_nonce, Some(AccountNonce::new(1)));

    let _ = create_block(
        &chain_config,
        &mut wallet,
        vec![fill_order_tx_1],
        Amount::ZERO,
        4,
    );

    // if confirmed tx is added conflicting txs must be replaced in the output cache, leaving descendants intact
    let mut orders = wallet.get_orders(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(orders.len(), 1);
    let (actual_order_id, order_data) = orders.pop().unwrap();
    assert_eq!(*actual_order_id, order_id);
    assert_eq!(order_data.last_nonce, Some(AccountNonce::new(1)));

    let coin_balance_confirmed = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance_confirmed,
        (coin_balance_after_create_order - spend_coins_1).unwrap()
    );

    let coin_balance_unconfirmed = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance_unconfirmed,
        (coin_balance_after_create_order - spend_coins_1)
            .and_then(|v| v - spend_coins_2)
            .unwrap()
    );

    let token_balance_confirmed = get_balance_with(
        &wallet,
        Currency::Token(issued_token_id),
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(token_balance_confirmed, received_tokens_1);

    let token_balance_unconfirmed = get_balance_with(
        &wallet,
        Currency::Token(issued_token_id),
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        token_balance_unconfirmed,
        (received_tokens_1 + received_tokens_2).unwrap()
    );
}

// Create a pool and a delegation with some share.
// Create a tx that spends from delegation account multiple times. Add it as unconfirmed.
// Check confirmed/unconfirmed balance and ensure that account nonce is incremented in OutputCache.
// Create a tx via separate wallet that spends from the same delegation once.
// Submit the second tx in a block.
// Check that the first tx was marked as conflicting and the state was properly reversed.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conflicting_delegation_account_nonce_multiple_inputs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet = create_wallet(chain_config.clone());
    let mut wallet2 = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(10..100));
    let block1_amount = (chain_config.min_stake_pool_pledge() + delegation_amount).unwrap();
    let (_, block1) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block1]);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // Create a pool
    let pool_amount = chain_config.min_stake_pool_pledge();

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: Destination::AnyoneCanSpend,
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();

    let (address, block2) = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction.clone()],
        Amount::ZERO,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(1), vec![block2]);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, (block1_amount - pool_amount).unwrap(),);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // Create a delegation
    let pool_id = pool_ids.first().unwrap().0;
    let (delegation_id, delegation_tx) = wallet
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address.clone(), pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let (_, block3) = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx],
        Amount::ZERO,
        2,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(2), vec![block3]);

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert!(deleg_data.not_staked_yet);
    assert_eq!(deleg_data.last_nonce, None);
    assert_eq!(deleg_data.pool_id, pool_id);
    assert_eq!(&deleg_data.destination, address.as_object());
    let spend_destination = deleg_data.destination.clone();

    // Delegate some coins
    let delegation_stake_tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::DelegateStaking(delegation_amount, delegation_id)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let (_, block4) = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_stake_tx],
        Amount::ZERO,
        3,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(3), vec![block4]);

    let coin_balance_after_delegating = get_coin_balance(&wallet);
    assert_eq!(
        coin_balance_after_delegating,
        (block1_amount - pool_amount).and_then(|v| v - delegation_amount).unwrap(),
    );

    // Add unconfirmed tx that spends from delegations via multiple inputs
    let spend_from_delegation_tx = Transaction::new(
        0,
        vec![
            TxInput::from_account(
                AccountNonce::new(0),
                AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(1)),
            ),
            TxInput::from_account(
                AccountNonce::new(1),
                AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(1)),
            ),
            TxInput::from_account(
                AccountNonce::new(2),
                AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(1)),
            ),
        ],
        vec![],
    )
    .unwrap();

    let spend_from_delegation_ptx = PartiallySignedTransaction::new(
        spend_from_delegation_tx,
        vec![None; 3],
        vec![None; 3],
        vec![Some(spend_destination); 3],
        None,
        TxAdditionalInfo::new(),
    )
    .unwrap();

    let spend_from_delegation_signed_tx = wallet
        .sign_raw_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_ptx)
        .unwrap()
        .0
        .into_signed_tx()
        .unwrap();
    let spend_from_delegation_tx_id = spend_from_delegation_signed_tx.transaction().get_id();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            spend_from_delegation_signed_tx.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Check delegation after unconfirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(2)));

    // Create and submit tx with different tx id
    let withdraw_amount_2 = Amount::from_atoms(5);
    let spend_from_delegation_tx_confirmed = wallet2
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_2,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    let spend_from_delegation_confirmed_tx_id =
        spend_from_delegation_tx_confirmed.transaction().get_id();

    let (_, block5) = create_block(
        &chain_config,
        &mut wallet2,
        vec![spend_from_delegation_tx_confirmed],
        Amount::ZERO,
        4,
    );
    let block5_id = block5.get_id();
    scan_wallet(&mut wallet, BlockHeight::new(4), vec![block5]);

    // if confirmed tx is added conflicting txs must be removed from the output cache
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_2).unwrap()
    );

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_2).unwrap()
    );

    assert_eq!(
        *wallet
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_id)
            .unwrap()
            .state(),
        TxState::Conflicted(block5_id.into())
    );
    assert_eq!(
        *wallet
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_confirmed_tx_id)
            .unwrap()
            .state(),
        TxState::Confirmed(
            BlockHeight::new(5),
            chain_config.genesis_block().timestamp(),
            0
        )
    );

    // Abandon conflicting txs
    wallet
        .abandon_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_id)
        .unwrap();
    assert_eq!(
        *wallet
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_id)
            .unwrap()
            .state(),
        TxState::Abandoned
    );

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));
}

// Create a pool and a delegation with some share.
// Create a tx that spends from delegation account and add it as unconfirmed.
// Revert the latest block in the wallet.
// Create a tx via separate wallet that spends from the same delegation once. Submit the second tx in a block.
// Check that the first tx was not removed by reorg and is marked as conflicting and the state was properly reversed.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conflicting_delegation_account_with_reorg(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_unit_test_config());

    let mut wallet = create_wallet(chain_config.clone());
    let mut wallet2 = create_wallet(chain_config.clone());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    // Generate a new block which sends reward to the wallet
    let delegation_amount = Amount::from_atoms(rng.gen_range(10..100));
    let block1_amount = (chain_config.min_stake_pool_pledge() + delegation_amount).unwrap();
    let (_, block1) = create_block(&chain_config, &mut wallet, vec![], block1_amount, 0);
    scan_wallet(&mut wallet2, BlockHeight::new(0), vec![block1]);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert!(pool_ids.is_empty());

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, block1_amount);

    // Create a pool
    let pool_amount = chain_config.min_stake_pool_pledge();

    let stake_pool_transaction = wallet
        .create_stake_pool_tx(
            DEFAULT_ACCOUNT_INDEX,
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            StakePoolCreationArguments {
                amount: pool_amount,
                margin_ratio_per_thousand: PerThousand::new_from_rng(&mut rng),
                cost_per_block: Amount::ZERO,
                decommission_key: Destination::AnyoneCanSpend,
                staker_key: None,
                vrf_public_key: None,
            },
        )
        .unwrap();

    let (address, block2) = create_block(
        &chain_config,
        &mut wallet,
        vec![stake_pool_transaction.clone()],
        Amount::ZERO,
        1,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(1), vec![block2]);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, (block1_amount - pool_amount).unwrap(),);

    let pool_ids = wallet.get_pool_ids(DEFAULT_ACCOUNT_INDEX, WalletPoolsFilter::All).unwrap();
    assert_eq!(pool_ids.len(), 1);

    // Create a delegation
    let pool_id = pool_ids.first().unwrap().0;
    let (delegation_id, delegation_tx) = wallet
        .create_delegation(
            DEFAULT_ACCOUNT_INDEX,
            vec![make_create_delegation_output(address.clone(), pool_id)],
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();

    let (_, block3) = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_tx],
        Amount::ZERO,
        2,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(2), vec![block3]);

    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert!(deleg_data.not_staked_yet);
    assert_eq!(deleg_data.last_nonce, None);
    assert_eq!(deleg_data.pool_id, pool_id);
    assert_eq!(&deleg_data.destination, address.as_object());

    // Delegate some coins
    let delegation_stake_tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [TxOutput::DelegateStaking(delegation_amount, delegation_id)],
            SelectedInputs::Utxos(vec![]),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();

    let (_, block4) = create_block(
        &chain_config,
        &mut wallet,
        vec![delegation_stake_tx],
        Amount::ZERO,
        3,
    );
    scan_wallet(&mut wallet2, BlockHeight::new(3), vec![block4.clone()]);

    let coin_balance_after_delegating = get_coin_balance(&wallet);
    assert_eq!(
        coin_balance_after_delegating,
        (block1_amount - pool_amount).and_then(|v| v - delegation_amount).unwrap(),
    );

    // Create an empty block to disconnect later and trigger unconfirmed tx removal
    let (_, _) = create_block(&chain_config, &mut wallet, vec![], Amount::ZERO, 4);

    // Add unconfirmed tx that spends from delegations
    let spend_from_delegation_tx_1 = wallet
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            Amount::from_atoms(1),
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    let spend_from_delegation_tx_id_1 = spend_from_delegation_tx_1.transaction().get_id();

    wallet
        .add_account_unconfirmed_tx(
            DEFAULT_ACCOUNT_INDEX,
            spend_from_delegation_tx_1.clone(),
            &WalletEventsNoOp,
        )
        .unwrap();

    // Check delegation after unconfirmed tx status
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));

    // Reset empty block and unconfirmed tx
    scan_wallet(&mut wallet, BlockHeight::new(3), vec![block4]);

    // Create and submit tx with different tx id
    let withdraw_amount_2 = Amount::from_atoms(5);
    let spend_from_delegation_tx_2 = wallet2
        .create_transaction_to_addresses_from_delegation(
            DEFAULT_ACCOUNT_INDEX,
            address.clone(),
            withdraw_amount_2,
            delegation_id,
            delegation_amount,
            FeeRate::from_amount_per_kb(Amount::ZERO),
        )
        .unwrap();
    let spend_from_delegation_tx_id_2 = spend_from_delegation_tx_2.transaction().get_id();

    let (_, block5) = create_block(
        &chain_config,
        &mut wallet2,
        vec![spend_from_delegation_tx_2],
        Amount::ZERO,
        4,
    );
    let block5_id = block5.get_id();
    scan_wallet(&mut wallet, BlockHeight::new(4), vec![block5]);

    // if confirmed tx is added, conflicting txs must be removed from the output cache
    let mut delegations = wallet.get_delegations(DEFAULT_ACCOUNT_INDEX).unwrap().collect_vec();
    assert_eq!(delegations.len(), 1);
    let (deleg_id, deleg_data) = delegations.pop().unwrap();
    assert_eq!(*deleg_id, delegation_id);
    assert_eq!(deleg_data.last_nonce, Some(AccountNonce::new(0)));

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed.into(),
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_2).unwrap()
    );

    let coin_balance = get_balance_with(
        &wallet,
        Currency::Coin,
        UtxoState::Confirmed | UtxoState::Inactive,
        WithLocked::Any,
    );
    assert_eq!(
        coin_balance,
        (coin_balance_after_delegating + withdraw_amount_2).unwrap()
    );

    assert_eq!(
        *wallet
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_id_1)
            .unwrap()
            .state(),
        TxState::Conflicted(block5_id.into())
    );
    assert_eq!(
        *wallet
            .get_transaction(DEFAULT_ACCOUNT_INDEX, spend_from_delegation_tx_id_2)
            .unwrap()
            .state(),
        TxState::Confirmed(
            BlockHeight::new(5),
            chain_config.genesis_block().timestamp(),
            0
        )
    );
}

// Abandoning a tx should remove utxos from consumed
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn rollback_utxos_after_abandon(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = Arc::new(create_mainnet());

    let mut wallet = create_wallet(chain_config.clone());

    // Generate a new block which sends reward to the wallet
    let utxo_amount = Amount::from_atoms(rng.gen_range(100..10000));
    let reward_outputs = (0..10)
        .map(|idx| {
            let address = get_address(
                &chain_config,
                MNEMONIC,
                DEFAULT_ACCOUNT_INDEX,
                KeyPurpose::ReceiveFunds,
                idx.try_into().unwrap(),
            );
            make_address_output(address, utxo_amount)
        })
        .collect_vec();
    let block1 = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(reward_outputs),
    )
    .unwrap();
    scan_wallet(&mut wallet, BlockHeight::new(0), vec![block1]);

    let utxos = wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer.into(),
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .unwrap();

    // Spend some utxos in a tx
    let selected_utxos = utxos
        .iter()
        .map(|(outpoint, _)| outpoint)
        .take(rng.gen_range(1..utxos.len()))
        .cloned()
        .collect_vec();

    let address = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    let tx = wallet
        .create_transaction_to_addresses(
            DEFAULT_ACCOUNT_INDEX,
            [make_address_output(address, utxo_amount)],
            SelectedInputs::Utxos(selected_utxos.clone()),
            BTreeMap::new(),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            FeeRate::from_amount_per_kb(Amount::ZERO),
            TxAdditionalInfo::new(),
        )
        .unwrap();
    let tx_id = tx.transaction().get_id();

    wallet
        .add_account_unconfirmed_tx(DEFAULT_ACCOUNT_INDEX, tx, &WalletEventsNoOp)
        .unwrap();

    // Check that spent utxos are not available anymore
    let outpoints: Vec<_> = wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer.into(),
            UtxoStates::ALL,
            WithLocked::Any,
        )
        .unwrap()
        .iter()
        .map(|(u, _)| u.clone())
        .collect();
    assert!(selected_utxos.iter().all(|u| !outpoints.contains(u)));

    wallet.abandon_transaction(DEFAULT_ACCOUNT_INDEX, tx_id).unwrap();

    // Check that spend utxo are available again
    let outpoints: Vec<_> = wallet
        .get_utxos(
            DEFAULT_ACCOUNT_INDEX,
            UtxoType::Transfer.into(),
            UtxoStates::ALL,
            WithLocked::Any,
        )
        .unwrap()
        .iter()
        .map(|(u, _)| u.clone())
        .collect();
    assert!(selected_utxos.iter().all(|u| outpoints.contains(u)));
}

// Check that token ids are generated from the first input of the issuing transaction even
// in the TokenIdGenerationVersion::V1 case.
// Note:
// 1) In V1, token ids are generated from the first UTXO input of the issuing transaction,
// so this test basically checks that token issuing transactions always have a UTXO as their
// first input.
// 2) The token id generation consistency is only important around the fork height; without it
// it'd be possible for the wallet to generate an invalid transaction and/or get into an invalid
// state if it guesses the transaction's block height incorrectly.
// In general though there is no need for the issuing transaction to always have a UTXO as the first
// input. So, after the fork height plus 1000 (the max reorg depth) will have been passed, this
// test can be removed (even if the fork itself remains).
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_id_generation_v1_uses_first_tx_input(#[case] seed: Seed) {
    use common::chain::{self, TokenIdGenerationVersion};

    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(
        chain::config::Builder::new(ChainType::Mainnet)
            .chainstate_upgrades(
                common::chain::NetUpgrades::initialize(vec![(
                    BlockHeight::zero(),
                    ChainstateUpgradeBuilder::latest().build(),
                )])
                .unwrap(),
            )
            .build(),
    );

    let mut wallet = create_wallet_with_mnemonic(chain_config.clone(), MNEMONIC);

    let coin_balance = get_coin_balance(&wallet);
    assert_eq!(coin_balance, Amount::ZERO);

    let needed_balance = ((chain_config.fungible_token_issuance_fee()
        + chain_config.nft_issuance_fee(BlockHeight::zero()))
    .unwrap()
        + Amount::from_atoms(rng.gen_range(NETWORK_FEE * 2..NETWORK_FEE * 10)))
    .unwrap();

    let generated_blocks_count = {
        let min_blocks = rng.gen_range(1..5);
        let mut generated_blocks_count = 0;
        let mut cur_balance = Amount::ZERO;

        while generated_blocks_count < min_blocks || cur_balance < needed_balance {
            let block_amount = Amount::from_atoms(
                rng.gen_range(needed_balance.into_atoms() / 10..needed_balance.into_atoms()),
            );

            let _ = create_block(
                &chain_config,
                &mut wallet,
                vec![],
                block_amount,
                generated_blocks_count,
            );
            cur_balance = (cur_balance + block_amount).unwrap();
            generated_blocks_count += 1;
        }

        generated_blocks_count
    };

    let token_authority_and_destination = wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1;

    // Some sanity checks
    let best_block_height = wallet.get_best_block_for_account(DEFAULT_ACCOUNT_INDEX).unwrap().1;
    assert_eq!(best_block_height.into_int(), generated_blocks_count);

    let next_block_height = best_block_height.next_height();
    assert_eq!(
        chain_config
            .chainstate_upgrades()
            .version_at_height(next_block_height)
            .1
            .token_id_generation_version(),
        TokenIdGenerationVersion::V1
    );

    let coin_balance = get_coin_balance(&wallet);
    assert!(coin_balance >= needed_balance);

    // Fungible token
    {
        let token_issuance = TokenIssuanceV1 {
            token_ticker: "XXXX".as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "http://uri".as_bytes().to_vec(),
            total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
            authority: token_authority_and_destination.as_object().clone(),
            is_freezable: common::chain::tokens::IsTokenFreezable::No,
        };
        let (issued_token_id, token_issuance_transaction) = wallet
            .issue_new_token(
                DEFAULT_ACCOUNT_INDEX,
                TokenIssuance::V1(token_issuance.clone()),
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
            )
            .unwrap();

        let expected_token_id = TokenId::from_tx_input(&token_issuance_transaction.inputs()[0]);
        assert_eq!(issued_token_id, expected_token_id);
    }

    // NFT
    {
        let (issued_token_id, nft_issuance_transaction) = wallet
            .issue_new_nft(
                DEFAULT_ACCOUNT_INDEX,
                token_authority_and_destination.clone(),
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
                FeeRate::from_amount_per_kb(Amount::ZERO),
                FeeRate::from_amount_per_kb(Amount::ZERO),
            )
            .unwrap();

        let expected_token_id = TokenId::from_tx_input(&nft_issuance_transaction.inputs()[0]);
        assert_eq!(issued_token_id, expected_token_id);
    }
}
