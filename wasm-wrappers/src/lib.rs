// Copyright (c) 2021-2025 RBB S.r.l
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

//! WASM bindings.
//!
//! Note:
//! Some of the functions below have the parameter `current_block_height`. It's needed in cases
//! when the result of the function depends on whether a certain hard fork has already happened.
//! 1) Its value must be the height of the block into which the corresponding transaction has been
//!    (or is supposed to be) included.
//! 2) A wallet cannot reliably predict the block height at which the new transaction will be mined.
//!    This means that when the chain is around a fork height, it's possible for the wallet to
//!    create an invalid transaction if the prediction is incorrect.
//!    The most reliable approach would be for the wallet to become aware of hard forks, so that
//!    it can refuse creating new transactions when the chain is near a fork, asking the user
//!    to wait a certain number of blocks.
//!    Otherwise, the wallet should probably just use "the current tip height plus one"
//!    as `current_block_height`.

use std::{num::NonZeroU8, str::FromStr};

use bip39::Language;
use itertools::Itertools as _;
use wasm_bindgen::{prelude::*, JsValue};

use common::{
    address::{dehexify::dehexify_all_addresses, pubkeyhash::PublicKeyHash, Address},
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        config::{Builder, BIP44_PATH},
        htlc::HtlcSecret,
        make_delegation_id, make_order_id, make_pool_id, make_token_id,
        partially_signed_transaction::{self, PartiallySignedTransaction, PartiallySignedTransactionConsistencyCheck},
        signature::{
            inputsig::{
                arbitrary_message::{produce_message_challenge, ArbitraryMessageSignature},
                authorize_hashed_timelock_contract_spend::{
                    AuthorizedHashedTimelockContractSpend, AuthorizedHashedTimelockContractSpendTag,
                },
                classical_multisig::authorize_classical_multisig::{
                    sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                },
                htlc::produce_uniparty_signature_for_htlc_input,
                standard_signature::StandardInputSignature,
                InputWitness,
            },
            sighash::signature_hash,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        Destination, OutPointSourceId, SignedTransaction, SignedTransactionIntent, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, BlockHeight, Id, Idable, H256},
    size_estimation::{
        input_signature_size_from_destination, outputs_encoded_size,
        tx_size_with_num_inputs_and_outputs,
    },
};
use crypto::key::{
    extended::{ExtendedKeyKind, ExtendedPrivateKey, ExtendedPublicKey},
    hdkd::{child_number::ChildNumber, derivable::Derivable, u31::U31},
    KeyKind, PrivateKey, PublicKey, Signature,
};
use serialization::{json_encoded::JsonEncoded, Decode, DecodeAll, Encode};

use crate::{
    error::Error,
    sighash_input_commitments::{make_sighash_input_commitments, TxInputsAdditionalInfo},
    types::TxAdditionalInfo,
    types::{Amount, Network, SignatureHashType, SourceId},
    utils::{decode_raw_array, extract_htlc_spend, parse_addressable},
};

mod encode_input;
mod encode_output;
mod error;
mod internal;
mod sighash_input_commitments;
#[cfg(test)]
mod tests;
mod types;
mod utils;

const RECEIVE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(0).0);
const CHANGE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(1).0);

/// A utxo can either come from a transaction or a block reward.
/// Given a source id, whether from a block reward or transaction, this function
/// takes a generic id with it, and returns serialized binary data of the id
/// with the given source id.
#[wasm_bindgen]
pub fn encode_outpoint_source_id(id: &[u8], source: SourceId) -> Vec<u8> {
    match source {
        SourceId::Transaction => OutPointSourceId::Transaction(H256::from_slice(id).into()),
        SourceId::BlockReward => OutPointSourceId::BlockReward(H256::from_slice(id).into()),
    }
    .encode()
}

/// Generates a new, random private key from entropy
#[wasm_bindgen]
pub fn make_private_key() -> Vec<u8> {
    let key = PrivateKey::new_from_entropy(KeyKind::Secp256k1Schnorr);
    key.0.encode()
}

/// Create the default account's extended private key for a given mnemonic
/// derivation path: 44'/mintlayer_coin_type'/0'
#[wasm_bindgen]
pub fn make_default_account_privkey(mnemonic: &str, network: Network) -> Result<Vec<u8>, Error> {
    let mnemonic =
        bip39::Mnemonic::parse_in(Language::English, mnemonic).map_err(Error::InvalidMnemonic)?;
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
/// derivation path: current_derivation_path/0/key_index
#[wasm_bindgen]
pub fn make_receiving_address(private_key: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let private_key = derive(account_privkey, RECEIVE_FUNDS_INDEX, key_index)?.private_key();
    Ok(private_key.encode())
}

/// From an extended private key create a change private key for a given key index
/// derivation path: current_derivation_path/1/key_index
#[wasm_bindgen]
pub fn make_change_address(private_key: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let private_key = derive(account_privkey, CHANGE_FUNDS_INDEX, key_index)?.private_key();
    Ok(private_key.encode())
}

/// Given a public key (as bytes) and a network type (mainnet, testnet, etc),
/// return the address public key hash from that public key as an address
#[wasm_bindgen]
pub fn pubkey_to_pubkeyhash_address(public_key: &[u8], network: Network) -> Result<String, Error> {
    let public_key =
        PublicKey::decode_all(&mut &public_key[..]).map_err(Error::InvalidPublicKeyEncoding)?;
    let chain_config = Builder::new(network.into()).build();

    let public_key_hash = PublicKeyHash::from(&public_key);

    Ok(
        Address::new(&chain_config, Destination::PublicKeyHash(public_key_hash))
            .expect("Should not fail to create address")
            .to_string(),
    )
}

/// Given a private key, as bytes, return the bytes of the corresponding public key
#[wasm_bindgen]
pub fn public_key_from_private_key(private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key =
        PrivateKey::decode_all(&mut &private_key[..]).map_err(Error::InvalidPrivateKeyEncoding)?;
    let public_key = PublicKey::from_private_key(&private_key);
    Ok(public_key.encode())
}

/// Return the extended public key from an extended private key
#[wasm_bindgen]
pub fn extended_public_key_from_extended_private_key(private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let extended_private_key = ExtendedPrivateKey::decode_all(&mut &private_key[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let extended_public_key = extended_private_key.to_public_key();
    Ok(extended_public_key.encode())
}

/// From an extended public key create a receiving public key for a given key index
/// derivation path: current_derivation_path/0/key_index
#[wasm_bindgen]
pub fn make_receiving_address_public_key(
    extended_public_key: &[u8],
    key_index: u32,
) -> Result<Vec<u8>, Error> {
    let account_publickey = ExtendedPublicKey::decode_all(&mut &extended_public_key[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let public_key = derive(account_publickey, RECEIVE_FUNDS_INDEX, key_index)?.into_public_key();
    Ok(public_key.encode())
}

/// From an extended public key create a change public key for a given key index
/// derivation path: current_derivation_path/1/key_index
#[wasm_bindgen]
pub fn make_change_address_public_key(
    extended_public_key: &[u8],
    key_index: u32,
) -> Result<Vec<u8>, Error> {
    let account_publickey = ExtendedPublicKey::decode_all(&mut &extended_public_key[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let public_key = derive(account_publickey, CHANGE_FUNDS_INDEX, key_index)?.into_public_key();
    Ok(public_key.encode())
}

fn derive<D: Derivable>(
    derivable: D,
    child_number: ChildNumber,
    key_index: u32,
) -> Result<D, Error> {
    let res = derivable
        .derive_child(child_number)
        .expect("Should not fail to derive key")
        .derive_child(ChildNumber::from_normal(
            U31::from_u32(key_index).ok_or(Error::InvalidKeyIndexMsbBitSet)?,
        ))
        .expect("Should not fail to derive key");
    Ok(res)
}

/// Given a message and a private key, sign the message with the given private key
/// This kind of signature is to be used when signing spend requests, such as transaction
/// input witness.
#[wasm_bindgen]
pub fn sign_message_for_spending(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key =
        PrivateKey::decode_all(&mut &private_key[..]).map_err(Error::InvalidPrivateKeyEncoding)?;
    let signature = private_key
        .sign_message(message, &mut randomness::make_true_rng())
        .map_err(Error::SignMessageError)?;
    Ok(signature.encode())
}

/// Given a digital signature, a public key and a message. Verify that
/// the signature is produced by signing the message with the private key
/// that derived the given public key.
/// Note that this function is used for verifying messages related to spending,
/// such as transaction input witness.
#[wasm_bindgen]
pub fn verify_signature_for_spending(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, Error> {
    let public_key =
        PublicKey::decode_all(&mut &public_key[..]).map_err(Error::InvalidPublicKeyEncoding)?;
    let signature =
        Signature::decode_all(&mut &signature[..]).map_err(Error::InvalidSignatureEncoding)?;
    let verifcation_result = public_key.verify_message(&signature, message);
    Ok(verifcation_result)
}

/// Given a message and a private key, create and sign a challenge with the given private key.
/// This kind of signature is to be used when signing challenges.
#[wasm_bindgen]
pub fn sign_challenge(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key =
        PrivateKey::decode_all(&mut &private_key[..]).map_err(Error::InvalidPrivateKeyEncoding)?;

    let signature = ArbitraryMessageSignature::produce_uniparty_signature_as_pub_key_hash_spending(
        &private_key,
        message,
        &mut randomness::make_true_rng(),
    )
    .map_err(Error::ArbitraryMessageSigningError)?;
    Ok(signature.into_raw())
}

/// Given a signed challenge, an address and a message, verify that
/// the signature is produced by signing the message with the private key
/// that derived the given public key.
/// This function is used for verifying messages-related challenges.
///
/// Note: for signatures that were created by `sign_challenge`, the provided address must be
/// a 'pubkeyhash' address.
///
/// Note: currently this function never returns `false` - it either returns `true` or fails with an error.
// TODO: this has to be changed; the function should either just return `()` (but then it'll be inconsistent
// with `verify_signature_for_spending`, which returns a proper boolean) or return `verify_signature(...).is_ok()`
// (but then the caller will lose the information about the reason for the failure).
#[wasm_bindgen]
pub fn verify_challenge(
    address: &str,
    network: Network,
    signed_challenge: &[u8],
    message: &[u8],
) -> Result<bool, Error> {
    let chain_config = Builder::new(network.into()).build();
    let destination = parse_addressable(&chain_config, address)?;
    let message_challenge = produce_message_challenge(message);
    let sig = ArbitraryMessageSignature::from_data(signed_challenge.to_vec());
    sig.verify_signature(&chain_config, &destination, &message_challenge)
        .map_err(Error::ArbitraryMessageSignatureVerificationError)?;
    Ok(true)
}

/// Return the message that has to be signed to produce a signed transaction intent.
#[wasm_bindgen]
pub fn make_transaction_intent_message_to_sign(
    intent: &str,
    transaction_id: &str,
) -> Result<Vec<u8>, Error> {
    let transaction_id =
        Id::new(H256::from_str(transaction_id).map_err(Error::TransactionIdParseError)?);
    let message_to_sign = SignedTransactionIntent::get_message_to_sign(intent, &transaction_id);

    Ok(message_to_sign.into_bytes())
}

/// Return a `SignedTransactionIntent` object as bytes given the message and encoded signatures.
///
/// Note: to produce a valid signed intent one is expected to sign the corresponding message by private keys
/// corresponding to each input of the transaction.
///
/// Parameters:
/// `signed_message` - this must have been produced by `make_transaction_intent_message_to_sign`.
/// `signatures` - this should be an array of Uint8Array, each of them representing an individual signature
/// of `signed_message` produced by `sign_challenge` using the private key for the corresponding input destination
/// of the transaction. The number of signatures must be equal to the number of inputs in the transaction.
#[wasm_bindgen]
pub fn encode_signed_transaction_intent(
    signed_message: &[u8],
    signatures: Vec<js_sys::Uint8Array>,
) -> Result<Vec<u8>, Error> {
    let signed_message_str = String::from_utf8(signed_message.to_owned())
        .map_err(|_| Error::SignedTransactionIntentMessageIsNotAValidUtf8String)?;
    let signatures = signatures.iter().map(js_sys::Uint8Array::to_vec).collect_vec();

    let signed_intent =
        SignedTransactionIntent::from_components_unchecked(signed_message_str, signatures);

    Ok(signed_intent.encode())
}

/// Verify a signed transaction intent.
///
/// Parameters:
/// `expected_signed_message` - the message that is supposed to be signed; this must have been
/// produced by `make_transaction_intent_message_to_sign`.
/// `encoded_signed_intent` - the signed transaction intent produced by `encode_signed_transaction_intent`.
/// `input_destinations` - an array of addresses (strings), corresponding to the transaction's input destinations
/// (note that this function treats "pub key" and "pub key hash" addresses interchangeably, so it's ok to pass
/// one instead of the other).
/// `network` - the network being used (needed to decode the addresses).
#[wasm_bindgen]
pub fn verify_transaction_intent(
    expected_signed_message: &[u8],
    mut encoded_signed_intent: &[u8],
    input_destinations: Vec<String>,
    network: Network,
) -> Result<(), Error> {
    let expected_signed_message_str = String::from_utf8(expected_signed_message.to_owned())
        .map_err(|_| Error::SignedTransactionIntentMessageIsNotAValidUtf8String)?;
    let chain_config = Builder::new(network.into()).build();

    let signed_intent = SignedTransactionIntent::decode_all(&mut encoded_signed_intent)
        .map_err(Error::InvalidSignedTransactionIntentEncoding)?;

    let input_destinations = input_destinations
        .iter()
        .map(|addr| parse_addressable(&chain_config, addr))
        .collect::<Result<Vec<_>, _>>()?;

    signed_intent
        .verify(
            &chain_config,
            &input_destinations,
            &expected_signed_message_str,
        )
        .map_err(Error::SignedTransactionIntentVerificationError)?;

    Ok(())
}

/// Given the current block height and a network type (mainnet, testnet, etc),
/// this function returns the number of blocks, after which a pool that decommissioned,
/// will have its funds unlocked and available for spending.
/// The current block height information is used in case a network upgrade changed the value.
#[wasm_bindgen]
pub fn staking_pool_spend_maturity_block_count(current_block_height: u64, network: Network) -> u64 {
    let chain_config = Builder::new(network.into()).build();
    chain_config
        .staking_pool_spend_maturity_block_count(BlockHeight::new(current_block_height))
        .to_int()
}

/// Given a number of blocks, this function returns the output timelock
/// which is used in locked outputs to lock an output for a given number of blocks
/// since that output's transaction is included the blockchain
#[wasm_bindgen]
pub fn encode_lock_for_block_count(block_count: u64) -> Vec<u8> {
    let output = OutputTimeLock::ForBlockCount(block_count);
    output.encode()
}

/// Given a number of clock seconds, this function returns the output timelock
/// which is used in locked outputs to lock an output for a given number of seconds
/// since that output's transaction is included in the blockchain
#[wasm_bindgen]
pub fn encode_lock_for_seconds(total_seconds: u64) -> Vec<u8> {
    let output = OutputTimeLock::ForSeconds(total_seconds);
    output.encode()
}

/// Given a timestamp represented by as unix timestamp, i.e., number of seconds since unix epoch,
/// this function returns the output timelock which is used in locked outputs to lock an output
/// until the given timestamp
#[wasm_bindgen]
pub fn encode_lock_until_time(timestamp_since_epoch_in_seconds: u64) -> Vec<u8> {
    let output = OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(
        timestamp_since_epoch_in_seconds,
    ));
    output.encode()
}

/// Given a block height, this function returns the output timelock which is used in
/// locked outputs to lock an output until that block height is reached.
#[wasm_bindgen]
pub fn encode_lock_until_height(block_height: u64) -> Vec<u8> {
    let output = OutputTimeLock::UntilHeight(BlockHeight::new(block_height));
    output.encode()
}

/// This function returns the staking pool data needed to create a staking pool in an output as bytes,
/// given its parameters and the network type (testnet, mainnet, etc).
#[wasm_bindgen]
pub fn encode_stake_pool_data(
    value: Amount,
    staker: &str,
    vrf_public_key: &str,
    decommission_key: &str,
    margin_ratio_per_thousand: u16,
    cost_per_block: Amount,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let value = value.as_internal_amount()?;
    let staker = parse_addressable(&chain_config, staker)?;
    let vrf_public_key = parse_addressable(&chain_config, vrf_public_key)?;
    let decommission_key = parse_addressable(&chain_config, decommission_key)?;
    let cost_per_block = cost_per_block.as_internal_amount()?;

    let pool_data = StakePoolData::new(
        value,
        staker,
        vrf_public_key,
        decommission_key,
        PerThousand::new(margin_ratio_per_thousand)
            .ok_or(Error::InvalidPerThousand(margin_ratio_per_thousand))?,
        cost_per_block,
    );

    Ok(pool_data.encode())
}

/// Returns the fee that needs to be paid by a transaction for issuing a new fungible token
#[wasm_bindgen]
pub fn fungible_token_issuance_fee(_current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(chain_config.fungible_token_issuance_fee())
}

/// Given the current block height and a network type (mainnet, testnet, etc),
/// this will return the fee that needs to be paid by a transaction for issuing a new NFT
/// The current block height information is used in case a network upgrade changed the value.
#[wasm_bindgen]
pub fn nft_issuance_fee(current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(
        chain_config.nft_issuance_fee(BlockHeight::new(current_block_height)),
    )
}

/// Given the current block height and a network type (mainnet, testnet, etc),
/// this will return the fee that needs to be paid by a transaction for changing the total supply of a token
/// by either minting or unminting tokens
/// The current block height information is used in case a network upgrade changed the value.
#[wasm_bindgen]
pub fn token_supply_change_fee(current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(
        chain_config.token_supply_change_fee(BlockHeight::new(current_block_height)),
    )
}

/// Given the current block height and a network type (mainnet, testnet, etc),
/// this will return the fee that needs to be paid by a transaction for freezing/unfreezing a token
/// The current block height information is used in case a network upgrade changed the value.
#[wasm_bindgen]
pub fn token_freeze_fee(current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(
        chain_config.token_freeze_fee(BlockHeight::new(current_block_height)),
    )
}

/// Given the current block height and a network type (mainnet, testnet, etc),
/// this will return the fee that needs to be paid by a transaction for changing the authority of a token
/// The current block height information is used in case a network upgrade changed the value.
#[wasm_bindgen]
pub fn token_change_authority_fee(current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(
        chain_config.token_change_authority_fee(BlockHeight::new(current_block_height)),
    )
}

/// Returns the Fungible/NFT Token ID for the given inputs of a transaction
#[wasm_bindgen]
pub fn get_token_id(
    inputs: &[u8],
    current_block_height: u64,
    network: Network,
) -> Result<String, Error> {
    let chain_config = Builder::new(network.into()).build();

    let inputs = decode_raw_array::<TxInput>(inputs).map_err(Error::InvalidInputEncoding)?;

    let token_id = make_token_id(
        &chain_config,
        BlockHeight::new(current_block_height),
        &inputs,
    )?;

    Ok(Address::new(&chain_config, token_id)
        .expect("Should not fail to create address")
        .to_string())
}

/// Returns the Order ID for the given inputs of a transaction
#[wasm_bindgen]
pub fn get_order_id(inputs: &[u8], network: Network) -> Result<String, Error> {
    let chain_config = Builder::new(network.into()).build();

    let inputs = decode_raw_array::<TxInput>(inputs).map_err(Error::InvalidInputEncoding)?;

    let token_id = make_order_id(&inputs)?;

    Ok(Address::new(&chain_config, token_id)
        .expect("Should not fail to create address")
        .to_string())
}

/// Returns the Delegation ID for the given inputs of a transaction
#[wasm_bindgen]
pub fn get_delegation_id(inputs: &[u8], network: Network) -> Result<String, Error> {
    let chain_config = Builder::new(network.into()).build();

    let inputs = decode_raw_array::<TxInput>(inputs).map_err(Error::InvalidInputEncoding)?;

    let token_id = make_delegation_id(&inputs)?;

    Ok(Address::new(&chain_config, token_id)
        .expect("Should not fail to create address")
        .to_string())
}

/// Returns the Pool ID for the given inputs of a transaction
#[wasm_bindgen]
pub fn get_pool_id(inputs: &[u8], network: Network) -> Result<String, Error> {
    let chain_config = Builder::new(network.into()).build();

    let inputs = decode_raw_array::<TxInput>(inputs).map_err(Error::InvalidInputEncoding)?;

    let token_id = make_pool_id(&inputs)?;

    Ok(Address::new(&chain_config, token_id)
        .expect("Should not fail to create address")
        .to_string())
}

/// Returns the fee that needs to be paid by a transaction for issuing a data deposit
#[wasm_bindgen]
pub fn data_deposit_fee(current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(
        chain_config.data_deposit_fee(BlockHeight::new(current_block_height)),
    )
}

/// Given a signed transaction and input outpoint that spends an htlc utxo, extract a secret that is
/// encoded in the corresponding input signature
#[wasm_bindgen]
pub fn extract_htlc_secret(
    signed_tx: &[u8],
    strict_byte_size: bool,
    htlc_outpoint_source_id: &[u8],
    htlc_output_index: u32,
) -> Result<Vec<u8>, Error> {
    let outpoint_source_id = OutPointSourceId::decode_all(&mut &htlc_outpoint_source_id[..])
        .map_err(Error::InvalidOutpointIdEncoding)?;
    let htlc_utxo_outpoint = UtxoOutPoint::new(outpoint_source_id, htlc_output_index);

    let tx = if strict_byte_size {
        SignedTransaction::decode_all(&mut &signed_tx[..])
            .map_err(Error::InvalidTransactionEncoding)?
    } else {
        SignedTransaction::decode(&mut &signed_tx[..]).map_err(Error::InvalidTransactionEncoding)?
    };

    let htlc_position = tx
        .transaction()
        .inputs()
        .iter()
        .position(|input| match input {
            TxInput::Utxo(outpoint) => *outpoint == htlc_utxo_outpoint,
            TxInput::Account(_)
            | TxInput::AccountCommand(_, _)
            | TxInput::OrderAccountCommand(_) => false,
        })
        .ok_or(Error::NoInputOutpointFound)?;

    let (htlc_spend, _) =
        extract_htlc_spend(tx.signatures().get(htlc_position).ok_or(Error::InvalidWitnessCount)?)?;

    match htlc_spend {
        AuthorizedHashedTimelockContractSpend::Secret(secret, _) => Ok(secret.encode()),
        AuthorizedHashedTimelockContractSpend::Multisig(_) => Err(Error::UnexpectedHtlcSpendType(
            AuthorizedHashedTimelockContractSpendTag::Multisig,
        )),
    }
}

/// Given the inputs, along each input's destination that can spend that input
/// (e.g. If we are spending a UTXO in input number 1 and it is owned by address mtc1xxxx, then it is mtc1xxxx in element number 2 in the vector/list.
/// for Account inputs that spend from a delegation it is the owning address of that delegation,
/// and in the case of AccountCommand inputs which change a token it is the token's authority destination)
/// and the outputs, estimate the transaction size.
/// ScriptHash and ClassicMultisig destinations are not supported.
#[wasm_bindgen]
pub fn estimate_transaction_size(
    inputs: &[u8],
    input_utxos_destinations: Vec<String>,
    outputs: &[u8],
    network: Network,
) -> Result<usize, Error> {
    let chain_config = Builder::new(network.into()).build();
    let outputs = decode_raw_array::<TxOutput>(outputs).map_err(Error::InvalidOutputEncoding)?;

    let size = tx_size_with_num_inputs_and_outputs(outputs.len(), input_utxos_destinations.len())
        .map_err(Error::TransactionSizeEstimationError)?
        + outputs_encoded_size(outputs.as_slice());
    let inputs_size = inputs.len();

    let mut total_size = size + inputs_size;

    for destination in input_utxos_destinations {
        let destination = parse_addressable(&chain_config, &destination)?;
        let signature_size =
            input_signature_size_from_destination(&destination, Option::<&_>::None)
                .map_err(Error::TransactionSizeEstimationError)?;

        total_size += signature_size;
    }

    Ok(total_size)
}

/// Given inputs as bytes, outputs as bytes, and flags settings, this function returns
/// the transaction that contains them all, as bytes.
#[wasm_bindgen]
pub fn encode_transaction(inputs: &[u8], outputs: &[u8], flags: u64) -> Result<Vec<u8>, Error> {
    let inputs = decode_raw_array::<TxInput>(inputs).map_err(Error::InvalidInputEncoding)?;
    let outputs = decode_raw_array::<TxOutput>(outputs).map_err(Error::InvalidOutputEncoding)?;

    let tx = Transaction::new(flags as u128, inputs, outputs).expect("no error");
    Ok(tx.encode())
}

/// Decodes a signed transaction from its binary encoding into a JavaScript object.
#[wasm_bindgen]
pub fn decode_signed_transaction_to_js(
    transaction: &[u8],
    network: Network,
) -> Result<JsValue, Error> {
    let chain_config = Builder::new(network.into()).build();
    let tx = SignedTransaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let str = JsonEncoded::new(&tx).to_string();
    let str = dehexify_all_addresses(&chain_config, &str);

    js_sys::JSON::parse(&str).map_err(Error::JsonParseError)
}

/// Encode an input witness of the variant that contains no signature.
#[wasm_bindgen]
pub fn encode_witness_no_signature() -> Vec<u8> {
    InputWitness::NoSignature(None).encode()
}

/// Sign the specified input of the transaction and encode the signature as InputWitness.
///
/// `input_utxos` must be formed as follows: for each transaction input, emit byte 0 if it's a non-UTXO input,
/// otherwise emit 1 followed by the corresponding transaction output encoded via the appropriate "encode_output_"
/// function.
///
/// `additional_info` must contain the following:
/// 1) for each `ProduceBlockFromStake` input of the transaction, the pool info for the pool referenced by that input;
/// 2) for each `FillOrder` and `ConcludeOrder` input of the transaction, the order info for the order referenced by
///    that input.
/// Note:
/// - It doesn't matter which input witness is currently being encoded. E.g. even if you are encoding a witness
///   for some UTXO-based input but another input of the same transaction is `FillOrder`, you have to include the order
///   info when encoding the witness for the UTXO-based input too.
/// - After a certain hard fork, the produced signature will "commit" to the provided additional info, i.e. the info
///   will become a part of what is being signed. So, passing invalid additional info will result in an invalid signature
///   (with one small caveat: for `FillOrder` we only commit to order's initial balances and not the current ones;
///   so if you only have `FillOrder` inputs, you can technically pass bogus values for the current balances and
///   the resulting signature will still be valid; though it's better to avoid doing this).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encode_witness(
    sighashtype: SignatureHashType,
    private_key: &[u8],
    input_owner_destination: &str,
    transaction: &[u8],
    input_utxos: &[u8],
    input_index: u32,
    additional_info: TxAdditionalInfo,
    current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key =
        PrivateKey::decode_all(&mut &private_key[..]).map_err(Error::InvalidPrivateKeyEncoding)?;

    let destination = parse_addressable(&chain_config, input_owner_destination)?;

    let tx = Transaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let input_utxos = decode_raw_array::<Option<TxOutput>>(input_utxos)
        .map_err(Error::InvalidInputUtxoEncoding)?;

    let input_infos =
        TxInputsAdditionalInfo::from_tx_additional_info(&chain_config, &additional_info)?;

    let input_commitments = make_sighash_input_commitments(
        tx.inputs(),
        &input_utxos,
        &input_infos,
        &chain_config,
        BlockHeight::new(current_block_height),
    )?;

    let witness = StandardInputSignature::produce_uniparty_signature_for_input(
        &private_key,
        sighashtype.into(),
        destination,
        &tx,
        &input_commitments,
        input_index as usize,
        &mut randomness::make_true_rng(),
    )
    .map(InputWitness::Standard)
    .map_err(Error::InputSigningError)?;

    Ok(witness.encode())
}

/// Given a private key, inputs and an input number to sign, and the destination that owns that output (through the utxo),
/// and a network type (mainnet, testnet, etc), and an htlc secret this function returns a witness to be used in a signed transaction, as bytes.
///
/// `input_utxos` and `additional_info` have the same format and requirements as in `encode_witness`.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_witness_htlc_secret(
    sighashtype: SignatureHashType,
    private_key: &[u8],
    input_owner_destination: &str,
    transaction: &[u8],
    input_utxos: &[u8],
    input_index: u32,
    secret: &[u8],
    additional_info: TxAdditionalInfo,
    current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key =
        PrivateKey::decode_all(&mut &private_key[..]).map_err(Error::InvalidPrivateKeyEncoding)?;

    let destination = parse_addressable(&chain_config, input_owner_destination)?;

    let tx = Transaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let input_utxos = decode_raw_array::<Option<TxOutput>>(input_utxos)
        .map_err(Error::InvalidInputUtxoEncoding)?;

    let input_infos =
        TxInputsAdditionalInfo::from_tx_additional_info(&chain_config, &additional_info)?;

    let input_commitments = make_sighash_input_commitments(
        tx.inputs(),
        &input_utxos,
        &input_infos,
        &chain_config,
        BlockHeight::new(current_block_height),
    )?;

    let secret =
        HtlcSecret::decode_all(&mut &secret[..]).map_err(Error::InvalidHtlcSecretEncoding)?;

    let witness = produce_uniparty_signature_for_htlc_input(
        &private_key,
        sighashtype.into(),
        destination,
        &tx,
        &input_commitments,
        input_index as usize,
        secret,
        &mut randomness::make_true_rng(),
    )
    .map(InputWitness::Standard)
    .map_err(Error::InputSigningError)?;

    Ok(witness.encode())
}

/// Given an arbitrary number of public keys as bytes, number of minimum required signatures, and a network type, this function returns
/// the multisig challenge, as bytes.
#[wasm_bindgen]
pub fn encode_multisig_challenge(
    public_keys: &[u8],
    min_required_signatures: u8,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let min_sigs =
        NonZeroU8::new(min_required_signatures).ok_or(Error::ZeroMultisigRequiredSigs)?;

    let public_keys =
        decode_raw_array::<PublicKey>(public_keys).map_err(Error::InvalidPublicKeyEncoding)?;

    let challenge = ClassicMultisigChallenge::new(&chain_config, min_sigs, public_keys)
        .map_err(Error::MultisigChallengeCreationError)?;

    Ok(challenge.encode())
}

/// Produce a multisig address given a multisig challenge.
#[wasm_bindgen]
pub fn multisig_challenge_to_address(
    multisig_challenge: &[u8],
    network: Network,
) -> Result<String, Error> {
    let chain_config = Builder::new(network.into()).build();

    let challenge = ClassicMultisigChallenge::decode_all(&mut &multisig_challenge[..])
        .map_err(Error::InvalidMultisigChallengeEncoding)?;

    let pkh: PublicKeyHash = (&challenge).into();
    let destination = Destination::ClassicMultisig(pkh);
    let address = Address::new(&chain_config, destination)
        .expect("Should not fail to create address")
        .to_string();

    Ok(address)
}

/// Given a private key, inputs and an input number to sign, and multisig challenge,
/// and a network type (mainnet, testnet, etc), this function returns a witness to be used in a signed transaction, as bytes.
///
/// `key_index` parameter is an index of the public key in the challenge corresponding to the specified private key.
/// `input_witness` parameter can be either empty or a result of previous calls to this function.
///
/// `input_utxos` and `additional_info` have the same format and requirements as in `encode_witness`.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_witness_htlc_multisig(
    sighashtype: SignatureHashType,
    private_key: &[u8],
    key_index: u8,
    input_witness: &[u8],
    multisig_challenge: &[u8],
    transaction: &[u8],
    input_utxos: &[u8],
    input_index: u32,
    additional_info: TxAdditionalInfo,
    current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key =
        PrivateKey::decode_all(&mut &private_key[..]).map_err(Error::InvalidPrivateKeyEncoding)?;

    let tx = Transaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let input_utxos = decode_raw_array::<Option<TxOutput>>(input_utxos)
        .map_err(Error::InvalidInputUtxoEncoding)?;

    let input_infos =
        TxInputsAdditionalInfo::from_tx_additional_info(&chain_config, &additional_info)?;

    let input_commitments = make_sighash_input_commitments(
        tx.inputs(),
        &input_utxos,
        &input_infos,
        &chain_config,
        BlockHeight::new(current_block_height),
    )?;

    let sighashtype = sighashtype.into();
    let sighash = signature_hash(sighashtype, &tx, &input_commitments, input_index as usize)
        .map_err(Error::SighashCalculationError)?;

    let mut rng = randomness::make_true_rng();
    let challenge = ClassicMultisigChallenge::decode_all(&mut &multisig_challenge[..])
        .map_err(Error::InvalidMultisigChallengeEncoding)?;
    let authorization = if !input_witness.is_empty() {
        let input_witness = InputWitness::decode_all(&mut &input_witness[..])
            .map_err(Error::InvalidWitnessEncoding)?;
        let (htlc_spend, _) = extract_htlc_spend(&input_witness)?;

        match htlc_spend {
            AuthorizedHashedTimelockContractSpend::Secret(_, _) => {
                return Err(Error::UnexpectedHtlcSpendType(
                    AuthorizedHashedTimelockContractSpendTag::Secret,
                ));
            }
            AuthorizedHashedTimelockContractSpend::Multisig(raw_signature) => {
                AuthorizedClassicalMultisigSpend::from_data(&raw_signature)
                    .map_err(Error::MultisigSpendCreationError)?
            }
        }
    } else {
        AuthorizedClassicalMultisigSpend::new_empty(challenge.clone())
    };

    let authorization = sign_classical_multisig_spending(
        &chain_config,
        key_index,
        &private_key,
        &challenge,
        &sighash,
        authorization,
        &mut rng,
    )
    .map_err(Error::MultisigSigningError)?
    .take();

    let raw_signature =
        AuthorizedHashedTimelockContractSpend::Multisig(authorization.encode()).encode();
    let witness = InputWitness::Standard(StandardInputSignature::new(sighashtype, raw_signature));

    Ok(witness.encode())
}

/// Given an unsigned transaction and signatures, this function returns a SignedTransaction object as bytes.
#[wasm_bindgen]
pub fn encode_signed_transaction(transaction: &[u8], signatures: &[u8]) -> Result<Vec<u8>, Error> {
    let signatures =
        decode_raw_array::<InputWitness>(signatures).map_err(Error::InvalidWitnessEncoding)?;

    let tx = Transaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let tx = SignedTransaction::new(tx, signatures).map_err(Error::TransactionCreationError)?;
    Ok(tx.encode())
}

/// Return a PartiallySignedTransaction object as bytes.
///
/// `transaction` is an encoded `Transaction` (which can be produced via `encode_transaction`).
/// 
/// `signatures`, `input_utxos`, `input_destinations` and `htlc_secrets` are encoded lists of
/// optional objects of the corresponding type. To produce such a list, iterate over your
/// original list of optional objects and then:
/// 1) emit byte 0 if the current object is `None`;
/// 2) otherwise emit 1 followed by the object in its encoded form.
/// 
/// Each individual object in each of the lists corresponds to the transaction input with the same
/// index and its meaning is as follows:
///   1) `signatures` - the signature for the input;
///   2) `input_utxos`- the utxo for the input (if it's utxo-based);
///   3) `input_destinations` - the destination (address) corresponding to the input, this determines
///      the key(s) with which the input has to be signed. Note that for utxo-based inputs the
///      corresponding destination can usually be extracted from the utxo itself (the exception
///      being the `ProduceBlockFromStake` utxo, which doesn't contain the pool's decommission key).
///      However, PartiallySignedTransaction requires that *all* input destinations are provided
///      explicitly anyway.
///   4) `htlc_secrets` - if the input is an HTLC one and if the transaction is spending the HTLC,
///      this should be the HTLC secret. Otherwise it should be `None`.
/// 
///   The number of items in each list must be equal to the number of transaction inputs.
/// 
/// `additional_info` has the same meaning as in `encode_witness`.
#[wasm_bindgen]
pub fn encode_partially_signed_transaction(
    transaction: &[u8],
    signatures: &[u8],
    input_utxos: &[u8],
    input_destinations: &[u8],
    htlc_secrets: &[u8],
    additional_info: TxAdditionalInfo,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let signatures = decode_raw_array::<Option<InputWitness>>(signatures)
        .map_err(Error::InvalidWitnessEncoding)?;

    let tx = Transaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let input_utxos = decode_raw_array::<Option<TxOutput>>(input_utxos)
        .map_err(Error::InvalidInputUtxoEncoding)?;

    let input_destinations = decode_raw_array::<Option<Destination>>(input_destinations)
        .map_err(Error::InvalidDestinationEncoding)?;

    let htlc_secrets = decode_raw_array::<Option<HtlcSecret>>(htlc_secrets)
        .map_err(Error::InvalidHtlcSecretEncoding)?;

    let additional_info =
        TxInputsAdditionalInfo::from_tx_additional_info(&chain_config, &additional_info)?;

    let ptx_additional_info = {
        let mut ptx_additional_info = partially_signed_transaction::TxAdditionalInfo::new();

        for (order_id, order_info) in additional_info.order_info {
            ptx_additional_info.add_order_info(
                order_id,
                partially_signed_transaction::OrderAdditionalInfo {
                    initially_asked: order_info.initially_asked,
                    initially_given: order_info.initially_given,
                    ask_balance: order_info.ask_balance,
                    give_balance: order_info.give_balance,
                },
            );
        }

        for (pool_id, pool_info) in additional_info.pool_info {
            ptx_additional_info.add_pool_info(
                pool_id,
                partially_signed_transaction::PoolAdditionalInfo {
                    staker_balance: pool_info.staker_balance,
                },
            );
        }

        ptx_additional_info
    };

    let tx = PartiallySignedTransaction::new(
        tx,
        signatures,
        input_utxos,
        input_destinations,
        Some(htlc_secrets),
        ptx_additional_info,
        PartiallySignedTransactionConsistencyCheck::AdditionalInfoWithoutTokenInfos,
    )
    .map_err(Error::PartiallySignedTransactionCreationError)?;
    Ok(tx.encode())
}

/// Convert the specified string address into a Destination object, encoded as bytes.
#[wasm_bindgen]
pub fn encode_destination(address: &str, network: Network) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let destination = parse_addressable::<Destination>(&chain_config, address)?;

    Ok(destination.encode())
}

/// Given a `Transaction` encoded in bytes (not a signed transaction, but a signed transaction is tolerated by ignoring the extra bytes, by choice)
/// this function will return the transaction id.
///
/// The second parameter, the boolean, is provided as means of asserting that the given bytes exactly match a `Transaction` object.
/// When set to `true`, the bytes provided must exactly match a single `Transaction` object.
/// When set to `false`, extra bytes can exist, but will be ignored.
/// This is useful when the provided bytes are of a `SignedTransaction` instead of a `Transaction`,
/// since the signatures are appended at the end of the `Transaction` object as a vector to create a `SignedTransaction`.
/// It is recommended to use a strict `Transaction` size and set the second parameter to `true`.
#[wasm_bindgen]
pub fn get_transaction_id(transaction: &[u8], strict_byte_size: bool) -> Result<String, Error> {
    let tx = if strict_byte_size {
        Transaction::decode_all(&mut &transaction[..]).map_err(Error::InvalidTransactionEncoding)?
    } else {
        Transaction::decode(&mut &transaction[..]).map_err(Error::InvalidTransactionEncoding)?
    };
    let tx_id = tx.get_id();

    Ok(format!("{:x}", tx_id))
}

/// Calculate the "effective balance" of a pool, given the total pool balance and pledge by the pool owner/staker.
/// The effective balance is how the influence of a pool is calculated due to its balance.
#[wasm_bindgen]
pub fn effective_pool_balance(
    network: Network,
    pledge_amount: Amount,
    pool_balance: Amount,
) -> Result<Amount, Error> {
    let chain_config = Builder::new(network.into()).build();

    let pledge_amount = pledge_amount.as_internal_amount()?;
    let pool_balance = pool_balance.as_internal_amount()?;
    let final_supply = chain_config.final_supply().ok_or(Error::FinalSupplyMissingInChainConfig)?;
    let final_supply = final_supply.to_amount_atoms();

    let effective_balance =
        consensus::calculate_effective_pool_balance(pledge_amount, pool_balance, final_supply)
            .map_err(Error::EffectiveBalanceCalculationFailed)?;

    Ok(Amount::from_internal_amount(effective_balance))
}
