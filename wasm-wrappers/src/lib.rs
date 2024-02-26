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

pub use bip39::{Language, Mnemonic};
use common::{
    address::{pubkeyhash::PublicKeyHash, traits::Addressable, Address},
    chain::{
        block::timestamp::BlockTimestamp,
        config::{Builder, ChainType, BIP44_PATH},
        output_value::OutputValue::Coin,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{IsTokenFreezable, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
        AccountNonce, AccountOutPoint, AccountSpending, ChainConfig, Destination, OutPointSourceId,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{amount::UnsignedIntType, per_thousand::PerThousand, Amount, BlockHeight, H256},
    size_estimation::{input_signature_size, tx_size_with_outputs},
};
use crypto::key::{
    extended::{ExtendedKeyKind, ExtendedPrivateKey},
    hdkd::{child_number::ChildNumber, derivable::Derivable, u31::U31},
    KeyKind, PrivateKey, PublicKey, Signature,
};
use error::Error;
use serialization::{Decode, DecodeAll, Encode};
use wasm_bindgen::prelude::*;

pub mod error;

#[wasm_bindgen]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl From<Network> for ChainType {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        }
    }
}

#[wasm_bindgen]
pub enum FreezableToken {
    No,
    Yes,
}

impl From<FreezableToken> for IsTokenFreezable {
    fn from(value: FreezableToken) -> Self {
        match value {
            FreezableToken::No => IsTokenFreezable::No,
            FreezableToken::Yes => IsTokenFreezable::Yes,
        }
    }
}

#[wasm_bindgen]
pub enum TotalSupply {
    Lockable,
    Unlimited,
    Fixed,
}

fn parse_token_total_supply(value: TotalSupply, amount: &str) -> Result<TokenTotalSupply, Error> {
    let supply = match value {
        TotalSupply::Lockable => TokenTotalSupply::Lockable,
        TotalSupply::Unlimited => TokenTotalSupply::Unlimited,
        TotalSupply::Fixed => TokenTotalSupply::Fixed(parse_amount(amount)?),
    };

    Ok(supply)
}

#[wasm_bindgen]
pub enum SourceId {
    Transaction,
    BlockReward,
}

#[wasm_bindgen]
pub enum SignatureHashType {
    ALL,
    NONE,
    SINGLE,
    ANYONECANPAY,
}

impl From<SignatureHashType> for SigHashType {
    fn from(value: SignatureHashType) -> Self {
        let value = match value {
            SignatureHashType::ALL => SigHashType::ALL,
            SignatureHashType::SINGLE => SigHashType::SINGLE,
            SignatureHashType::ANYONECANPAY => SigHashType::ANYONECANPAY,
            SignatureHashType::NONE => SigHashType::NONE,
        };

        SigHashType::try_from(value).expect("should not fail")
    }
}

#[wasm_bindgen]
pub fn make_private_key() -> Vec<u8> {
    let key = PrivateKey::new_from_entropy(KeyKind::Secp256k1Schnorr);
    key.0.encode()
}

/// Create the default account's extended private key for a given mnemonic
/// derivation path: 44'/mintlayer_coin_type'/0'
#[wasm_bindgen]
pub fn make_default_account_privkey(mnemonic: &str, network: Network) -> Result<Vec<u8>, Error> {
    let mnemonic = bip39::Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| Error::InvalidMnemonic)?;
    let seed = mnemonic.to_seed("");

    let root_key = ExtendedPrivateKey::new_master(&seed, ExtendedKeyKind::Secp256k1Schnorr)
        .expect("Should not fail to create a master key");

    let chain_config = Builder::new(network.into()).build();

    let account_index = U31::ZERO;
    let path = vec![
        BIP44_PATH,
        chain_config.bip44_coin_type(),
        ChildNumber::from_hardened(account_index),
    ];
    let account_path = path.try_into().expect("Path creation should not fail");
    let account_privkey = root_key
        .derive_absolute_path(&account_path)
        .expect("Should not fail to derive path");

    Ok(account_privkey.encode())
}

/// From an extended private key create a receiving private key for a given key index
/// derivation path: 44'/mintlayer_coin_type'/0'/0/key_index
#[wasm_bindgen]
pub fn make_receiving_address(private_key_bytes: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    const RECEIVE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(0).0);

    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;

    let receive_funds_pkey = account_privkey
        .derive_child(RECEIVE_FUNDS_INDEX)
        .expect("Should not fail to derive key");

    let private_key: PrivateKey = receive_funds_pkey
        .derive_child(ChildNumber::from_normal(
            U31::from_u32(key_index).ok_or(Error::InvalidKeyIndex)?,
        ))
        .expect("Should not fail to derive key")
        .private_key();

    Ok(private_key.encode())
}

/// From an extended private key create a change private key for a given key index
/// derivation path: 44'/mintlayer_coin_type'/0'/1/key_index
#[wasm_bindgen]
pub fn make_change_address(private_key_bytes: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    const CHANGE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(1).0);

    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;

    let change_funds_pkey = account_privkey
        .derive_child(CHANGE_FUNDS_INDEX)
        .expect("Should not fail to derive key");

    let private_key: PrivateKey = change_funds_pkey
        .derive_child(ChildNumber::from_normal(
            U31::from_u32(key_index).ok_or(Error::InvalidKeyIndex)?,
        ))
        .expect("Should not fail to derive key")
        .private_key();

    Ok(private_key.encode())
}

#[wasm_bindgen]
pub fn pubkey_to_string(public_key_bytes: &[u8], network: Network) -> Result<String, Error> {
    let public_key = PublicKey::decode_all(&mut &public_key_bytes[..])
        .map_err(|_| Error::InvalidPublicKeyEncoding)?;
    let chain_config = Builder::new(network.into()).build();

    let public_key_hash = PublicKeyHash::from(&public_key);

    Ok(
        Address::new(&chain_config, &Destination::PublicKeyHash(public_key_hash))
            .expect("Should not fail to create address")
            .get()
            .to_owned(),
    )
}

#[wasm_bindgen]
pub fn public_key_from_private_key(private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key = PrivateKey::decode_all(&mut &private_key[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;
    let public_key = PublicKey::from_private_key(&private_key);
    Ok(public_key.encode())
}

#[wasm_bindgen]
pub fn sign_message(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key = PrivateKey::decode_all(&mut &private_key[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;
    let signature = private_key.sign_message(message)?;
    Ok(signature.encode())
}

#[wasm_bindgen]
pub fn verify_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, Error> {
    let public_key =
        PublicKey::decode_all(&mut &public_key[..]).map_err(|_| Error::InvalidPublicKeyEncoding)?;
    let signature =
        Signature::decode_all(&mut &signature[..]).map_err(|_| Error::InvalidSignatureEncoding)?;
    let verifcation_result = public_key.verify_message(&signature, message);
    Ok(verifcation_result)
}

fn parse_amount(amount: &str) -> Result<Amount, Error> {
    amount
        .parse::<UnsignedIntType>()
        .ok()
        .map(Amount::from_atoms)
        .ok_or(Error::InvalidAmount)
}

fn parse_addressable<T: Addressable>(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<T, Error> {
    let addressable = Address::from_str(chain_config, address)
        .map_err(|_| Error::InvalidAddressable)?
        .decode_object(chain_config)
        .expect("already checked");
    Ok(addressable)
}

#[wasm_bindgen]
pub fn encode_output_transfer(
    amount: &str,
    address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = parse_amount(amount)?;
    let destination = parse_addressable::<Destination>(&chain_config, address)?;

    let output = TxOutput::Transfer(Coin(amount), destination);
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn staking_pool_spend_maturity_block_count(current_block_height: u64, network: Network) -> u64 {
    let chain_config = Builder::new(network.into()).build();
    chain_config
        .staking_pool_spend_maturity_block_count(BlockHeight::new(current_block_height))
        .to_int()
}

#[wasm_bindgen]
pub fn encode_lock_for_block_count(num: u64) -> Vec<u8> {
    let output = OutputTimeLock::ForBlockCount(num);
    output.encode()
}

#[wasm_bindgen]
pub fn encode_lock_for_seconds(num: u64) -> Vec<u8> {
    let output = OutputTimeLock::ForSeconds(num);
    output.encode()
}

#[wasm_bindgen]
pub fn encode_lock_until_time(num: u64) -> Vec<u8> {
    let output = OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(num));
    output.encode()
}

#[wasm_bindgen]
pub fn encode_lock_until_height(num: u64) -> Vec<u8> {
    let output = OutputTimeLock::UntilHeight(BlockHeight::new(num));
    output.encode()
}

#[wasm_bindgen]
pub fn encode_output_lock_then_transfer(
    amount: &str,
    address: &str,
    lock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = parse_amount(amount)?;
    let destination = parse_addressable::<Destination>(&chain_config, address)?;
    let lock = OutputTimeLock::decode_all(&mut &lock[..]).map_err(|_| Error::InvalidTimeLock)?;

    let output = TxOutput::LockThenTransfer(Coin(amount), destination, lock);
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn encode_output_burn(amount: &str) -> Result<Vec<u8>, Error> {
    let amount = parse_amount(amount)?;

    let output = TxOutput::Burn(Coin(amount));
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn encode_output_create_delegation(
    pool_id: &str,
    address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let destination = parse_addressable(&chain_config, address)?;
    let pool_id = parse_addressable(&chain_config, pool_id)?;

    let output = TxOutput::CreateDelegationId(destination, pool_id);
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn encode_output_delegate_staking(
    amount: &str,
    delegation_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = parse_amount(amount)?;
    let delegation_id = parse_addressable(&chain_config, delegation_id)?;

    let output = TxOutput::DelegateStaking(amount, delegation_id);
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn encode_stake_pool_data(
    value: &str,
    staker: &str,
    vrf_public_key: &str,
    decommission_key: &str,
    margin_ratio_per_thousand: u16,
    cost_per_block: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let value = parse_amount(value)?;
    let staker = parse_addressable(&chain_config, staker)?;
    let vrf_public_key = parse_addressable(&chain_config, vrf_public_key)?;
    let decommission_key = parse_addressable(&chain_config, decommission_key)?;
    let cost_per_block = parse_amount(cost_per_block)?;

    let pool_data = StakePoolData::new(
        value,
        staker,
        vrf_public_key,
        decommission_key,
        PerThousand::new(margin_ratio_per_thousand)
            .ok_or(Error::InvalidPerThousedns(margin_ratio_per_thousand))?,
        cost_per_block,
    );

    Ok(pool_data.encode())
}

#[wasm_bindgen]
pub fn encode_output_create_stake_pool(
    pool_id: &str,
    pool_data: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let pool_id = parse_addressable(&chain_config, pool_id)?;
    let pool_data =
        StakePoolData::decode_all(&mut &pool_data[..]).map_err(|_| Error::InvalidStakePoolData)?;

    let output = TxOutput::CreateStakePool(pool_id, Box::new(pool_data));
    Ok(output.encode())
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_output_issue_fungible_token(
    authority: &str,
    token_ticker: &[u8],
    metadata_uri: &[u8],
    number_of_decimals: u8,
    total_supply: TotalSupply,
    supply_amount: &str,
    is_token_freezable: FreezableToken,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let authority = parse_addressable(&chain_config, authority)?;
    let token_ticker = token_ticker.into();
    let metadata_uri = metadata_uri.into();
    let total_supply = parse_token_total_supply(total_supply, supply_amount)?;
    let is_freezable = is_token_freezable.into();

    let token_issuance = TokenIssuanceV1 {
        authority,
        token_ticker,
        metadata_uri,
        number_of_decimals,
        total_supply,
        is_freezable,
    };

    let output = TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(token_issuance)));
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn encode_output_data_deposit(data: &[u8]) -> Result<Vec<u8>, Error> {
    let output = TxOutput::DataDeposit(data.into());
    Ok(output.encode())
}

#[wasm_bindgen]
pub fn encode_outpoint_source_id(id: &[u8], source: SourceId) -> Vec<u8> {
    match source {
        SourceId::Transaction => OutPointSourceId::Transaction(H256::from_slice(id).into()),
        SourceId::BlockReward => OutPointSourceId::BlockReward(H256::from_slice(id).into()),
    }
    .encode()
}

#[wasm_bindgen]
pub fn encode_input_for_utxo(
    outpoint_source_id: &[u8],
    output_index: u32,
) -> Result<Vec<u8>, Error> {
    let outpoint_source_id = OutPointSourceId::decode_all(&mut &outpoint_source_id[..])
        .map_err(|_| Error::InvalidOutpointId)?;
    let input = TxInput::Utxo(UtxoOutPoint::new(outpoint_source_id, output_index));
    Ok(input.encode())
}

#[wasm_bindgen]
pub fn encode_input_for_account_outpoint(
    delegation_id: &str,
    amount: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = parse_amount(amount)?;
    let delegation_id = parse_addressable(&chain_config, delegation_id)?;
    let input = TxInput::Account(AccountOutPoint::new(
        AccountNonce::new(nonce),
        AccountSpending::DelegationBalance(delegation_id, amount),
    ));
    Ok(input.encode())
}

#[wasm_bindgen]
pub fn estimate_transaction_size(
    inputs: &[u8],
    mut opt_utxos: &[u8],
    mut outputs: &[u8],
) -> Result<usize, Error> {
    let mut tx_outputs = vec![];
    while !outputs.is_empty() {
        let output = TxOutput::decode(&mut outputs).map_err(|_| Error::InvalidOutput)?;
        tx_outputs.push(output);
    }

    let size = tx_size_with_outputs(&tx_outputs);
    let inputs_size = inputs.len();

    let mut total_size = size + inputs_size;

    while !opt_utxos.is_empty() {
        let utxo = Option::<TxOutput>::decode(&mut opt_utxos).map_err(|_| Error::InvalidInput)?;
        let signature_size = utxo
            .as_ref()
            .map(input_signature_size)
            .transpose()
            .map_err(|_| Error::InvalidInput)?
            .unwrap_or(0);

        total_size += signature_size;
    }

    Ok(total_size)
}

#[wasm_bindgen]
pub fn encode_transaction(
    mut inputs: &[u8],
    mut outputs: &[u8],
    flags: u64,
) -> Result<Vec<u8>, Error> {
    let mut tx_outputs = vec![];
    while !outputs.is_empty() {
        let output = TxOutput::decode(&mut outputs).map_err(|_| Error::InvalidOutput)?;
        tx_outputs.push(output);
    }

    let mut tx_inputs = vec![];
    while !inputs.is_empty() {
        let input = TxInput::decode(&mut inputs).map_err(|_| Error::InvalidInput)?;
        tx_inputs.push(input);
    }

    let tx = Transaction::new(flags as u128, tx_inputs, tx_outputs).expect("no error");
    Ok(tx.encode())
}

#[wasm_bindgen]
pub fn encode_witness_no_signature() -> Vec<u8> {
    InputWitness::NoSignature(None).encode()
}

#[wasm_bindgen]
pub fn encode_witness(
    sighashtype: SignatureHashType,
    private_key_bytes: &[u8],
    address: &str,
    transaction_bytes: &[u8],
    mut inputs: &[u8],
    input_num: u32,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key = PrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;

    let destination = parse_addressable::<Destination>(&chain_config, address)?;

    let tx = Transaction::decode_all(&mut &transaction_bytes[..])
        .map_err(|_| Error::InvalidTransaction)?;

    let mut input_utxos = vec![];
    while !inputs.is_empty() {
        let utxo = Option::<TxOutput>::decode(&mut inputs).map_err(|_| Error::InvalidInput)?;
        input_utxos.push(utxo);
    }

    let utxos = input_utxos.iter().map(Option::as_ref).collect::<Vec<_>>();

    let witness = StandardInputSignature::produce_uniparty_signature_for_input(
        &private_key,
        sighashtype.into(),
        destination,
        &tx,
        &utxos,
        input_num as usize,
    )
    .map(InputWitness::Standard)
    .map_err(|_| Error::InvalidWitness)?;

    Ok(witness.encode())
}

#[wasm_bindgen]
pub fn encode_signed_transaction(
    transaction_bytes: &[u8],
    mut signatures: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut tx_signatures = vec![];
    while !signatures.is_empty() {
        let signature = InputWitness::decode(&mut signatures).map_err(|_| Error::InvalidWitness)?;
        tx_signatures.push(signature);
    }

    let tx = Transaction::decode_all(&mut &transaction_bytes[..])
        .map_err(|_| Error::InvalidTransaction)?;

    let tx = SignedTransaction::new(tx, tx_signatures).map_err(|_| Error::InvalidWitnessCount)?;
    Ok(tx.encode())
}

#[cfg(test)]
mod tests {
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn sign_and_verify(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let key = make_private_key();
        assert_eq!(key.len(), 33);

        let public_key = public_key_from_private_key(&key).unwrap();

        let message_size = 1 + rng.gen::<usize>() % 10000;
        let message: Vec<u8> = (0..message_size).map(|_| rng.gen::<u8>()).collect();

        let signature = sign_message(&key, &message).unwrap();

        {
            // Valid reference signature
            let verification_result = verify_signature(&public_key, &signature, &message).unwrap();
            assert!(verification_result);
        }
        {
            // Tamper with the message
            let mut tampered_message = message.clone();
            let tamper_bit_index = rng.gen::<usize>() % message_size;
            tampered_message[tamper_bit_index] = tampered_message[tamper_bit_index].wrapping_add(1);
            let verification_result =
                verify_signature(&public_key, &signature, &tampered_message).unwrap();
            assert!(!verification_result);
        }
        {
            // Tamper with the signature
            let mut tampered_signature = signature.clone();
            // Ignore the first byte because the it is the key kind
            let tamper_bit_index = 1 + rng.gen::<usize>() % (signature.len() - 1);
            tampered_signature[tamper_bit_index] =
                tampered_signature[tamper_bit_index].wrapping_add(1);
            let verification_result =
                verify_signature(&public_key, &tampered_signature, &message).unwrap();
            assert!(!verification_result);
        }
        {
            // Wrong keys
            let private_key = make_private_key();
            let public_key = public_key_from_private_key(&private_key).unwrap();
            let verification_result = verify_signature(&public_key, &signature, &message).unwrap();
            assert!(!verification_result);
        }
    }
}
