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
use gloo_utils::format::JsValueSerdeExt as _;
use wasm_bindgen::prelude::*;

use common::{
    address::{pubkeyhash::PublicKeyHash, traits::Addressable, Address},
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        config::{Builder, ChainType, BIP44_PATH},
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        make_token_id,
        output_value::OutputValue::{self, Coin, TokenV1},
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
                InputWitness, InputWitnessTag,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0,
            TokenCreator, TokenIssuance, TokenIssuanceV1, TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, ChainConfig, Destination,
        OrderData, OutPointSourceId, SignedTransaction, SignedTransactionIntent, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{
        self, amount::UnsignedIntType, per_thousand::PerThousand, BlockHeight, Id, Idable, H256,
    },
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
use error::Error;
use serialization::{Decode, DecodeAll, Encode};

pub mod error;

const RECEIVE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(0).0);
const CHANGE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(1).0);

#[wasm_bindgen]
/// Amount type abstraction. The amount type is stored in a string
/// since JavaScript number type cannot fit 128-bit integers.
/// The amount is given as an integer in units of "atoms".
/// Atoms are the smallest, indivisible amount of a coin or token.
pub struct Amount {
    atoms: String,
}

#[wasm_bindgen]
impl Amount {
    #[wasm_bindgen]
    pub fn from_atoms(atoms: String) -> Self {
        Self { atoms }
    }

    #[wasm_bindgen]
    pub fn atoms(self) -> String {
        self.atoms
    }

    fn as_internal_amount(&self) -> Result<primitives::Amount, Error> {
        UnsignedIntType::from_str(&self.atoms)
            .ok()
            .map(primitives::Amount::from_atoms)
            .ok_or_else(|| Error::AtomsAmountParseError {
                atoms: self.atoms.clone(),
            })
    }

    fn from_internal_amount(amount: primitives::Amount) -> Self {
        Self {
            atoms: amount.into_atoms().to_string(),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Copy, Clone)]
/// The network, for which an operation to be done. Mainnet, testnet, etc.
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

/// Indicates whether a token can be frozen
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

/// Indicates whether a token can be unfrozen once frozen
#[wasm_bindgen]
pub enum TokenUnfreezable {
    No,
    Yes,
}

impl From<TokenUnfreezable> for IsTokenUnfreezable {
    fn from(value: TokenUnfreezable) -> Self {
        match value {
            TokenUnfreezable::No => IsTokenUnfreezable::No,
            TokenUnfreezable::Yes => IsTokenUnfreezable::Yes,
        }
    }
}

/// The token supply of a specific token, set on issuance
#[wasm_bindgen]
pub enum TotalSupply {
    /// Can be issued with no limit, but then can be locked to have a fixed supply.
    Lockable,
    /// Unlimited supply, no limits except for numeric limits due to u128
    Unlimited,
    /// On issuance, the total number of coins is fixed
    Fixed,
}

fn parse_token_total_supply(
    value: TotalSupply,
    amount: Option<Amount>,
) -> Result<TokenTotalSupply, Error> {
    let supply = match value {
        TotalSupply::Lockable => TokenTotalSupply::Lockable,
        TotalSupply::Unlimited => TokenTotalSupply::Unlimited,
        TotalSupply::Fixed => TokenTotalSupply::Fixed(
            amount.ok_or(Error::FixedTotalSupplyButNoAmount)?.as_internal_amount()?,
        ),
    };

    Ok(supply)
}

/// A utxo can either come from a transaction or a block reward. This enum signifies that.
#[wasm_bindgen]
pub enum SourceId {
    Transaction,
    BlockReward,
}

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

/// The part of the transaction that will be committed in the signature. Similar to bitcoin's sighash.
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
pub fn make_receiving_address(private_key_bytes: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let private_key = derive(account_privkey, RECEIVE_FUNDS_INDEX, key_index)?.private_key();
    Ok(private_key.encode())
}

/// From an extended private key create a change private key for a given key index
/// derivation path: current_derivation_path/1/key_index
#[wasm_bindgen]
pub fn make_change_address(private_key_bytes: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let private_key = derive(account_privkey, CHANGE_FUNDS_INDEX, key_index)?.private_key();
    Ok(private_key.encode())
}

/// Given a public key (as bytes) and a network type (mainnet, testnet, etc),
/// return the address public key hash from that public key as an address
#[wasm_bindgen]
pub fn pubkey_to_pubkeyhash_address(
    public_key_bytes: &[u8],
    network: Network,
) -> Result<String, Error> {
    let public_key = PublicKey::decode_all(&mut &public_key_bytes[..])
        .map_err(Error::InvalidPublicKeyEncoding)?;
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
pub fn extended_public_key_from_extended_private_key(
    private_key_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    let extended_private_key = ExtendedPrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let extended_public_key = extended_private_key.to_public_key();
    Ok(extended_public_key.encode())
}

/// From an extended public key create a receiving public key for a given key index
/// derivation path: current_derivation_path/0/key_index
#[wasm_bindgen]
pub fn make_receiving_address_public_key(
    extended_public_key_bytes: &[u8],
    key_index: u32,
) -> Result<Vec<u8>, Error> {
    let account_publickey = ExtendedPublicKey::decode_all(&mut &extended_public_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;
    let public_key = derive(account_publickey, RECEIVE_FUNDS_INDEX, key_index)?.into_public_key();
    Ok(public_key.encode())
}

/// From an extended public key create a change public key for a given key index
/// derivation path: current_derivation_path/1/key_index
#[wasm_bindgen]
pub fn make_change_address_public_key(
    extended_public_key_bytes: &[u8],
    key_index: u32,
) -> Result<Vec<u8>, Error> {
    let account_publickey = ExtendedPublicKey::decode_all(&mut &extended_public_key_bytes[..])
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
        .sign_message(message, randomness::make_true_rng())
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
        randomness::make_true_rng(),
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

fn parse_addressable<T: Addressable>(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<T, Error> {
    let addressable = Address::from_string(chain_config, address)
        .map_err(|error| Error::AddressableParseError {
            addressable: address.to_owned(),
            error,
        })?
        .into_object();
    Ok(addressable)
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
/// `signatures` - this should be an array of arrays of bytes, each of them representing an individual signature
/// of `signed_message` produced by `sign_challenge` using the private key for the corresponding input destination
/// of the transaction. The number of signatures must be equal to the number of inputs in the transaction.
#[wasm_bindgen]
pub fn encode_signed_transaction_intent(
    signed_message: &[u8],
    // Note: we could also accept it as `Vec<JsValue>` where the inner JsValue would represent `Vec<u8>`.
    // But such "semi-structured" approach doesn't make much sense (and accepting `Vec<Vec<u8>>` directly is not allowed).
    signatures: &JsValue,
) -> Result<Vec<u8>, Error> {
    let signed_message_str = String::from_utf8(signed_message.to_owned())
        .map_err(|_| Error::SignedTransactionIntentMessageIsNotAValidUtf8String)?;
    let signatures: Vec<Vec<u8>> =
        signatures.into_serde().map_err(|err| Error::JsValueNotArrayOfArraysOfBytes {
            error: err.to_string(),
        })?;

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

/// Given a destination address, an amount and a network type (mainnet, testnet, etc), this function
/// creates an output of type Transfer, and returns it as bytes.
#[wasm_bindgen]
pub fn encode_output_transfer(
    amount: Amount,
    address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;

    let output = TxOutput::Transfer(Coin(amount), destination);
    Ok(output.encode())
}

/// Given a destination address, an amount, token ID (in address form) and a network type (mainnet, testnet, etc), this function
/// creates an output of type Transfer for tokens, and returns it as bytes.
#[wasm_bindgen]
pub fn encode_output_token_transfer(
    amount: Amount,
    address: &str,
    token_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;
    let token = parse_addressable(&chain_config, token_id)?;

    let output = TxOutput::Transfer(TokenV1(token, amount), destination);
    Ok(output.encode())
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

/// Given a valid receiving address, and a locking rule as bytes (available in this file),
/// and a network type (mainnet, testnet, etc), this function creates an output of type
/// LockThenTransfer with the parameters provided.
#[wasm_bindgen]
pub fn encode_output_lock_then_transfer(
    amount: Amount,
    address: &str,
    lock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;
    let lock =
        OutputTimeLock::decode_all(&mut &lock[..]).map_err(Error::InvalidTimeLockEncoding)?;

    let output = TxOutput::LockThenTransfer(Coin(amount), destination, lock);
    Ok(output.encode())
}

/// Given a valid receiving address, token ID (in address form), a locking rule as bytes (available in this file),
/// and a network type (mainnet, testnet, etc), this function creates an output of type
/// LockThenTransfer with the parameters provided.
#[wasm_bindgen]
pub fn encode_output_token_lock_then_transfer(
    amount: Amount,
    address: &str,
    token_id: &str,
    lock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;
    let lock =
        OutputTimeLock::decode_all(&mut &lock[..]).map_err(Error::InvalidTimeLockEncoding)?;
    let token = parse_addressable(&chain_config, token_id)?;

    let output = TxOutput::LockThenTransfer(TokenV1(token, amount), destination, lock);
    Ok(output.encode())
}

/// Given an amount, this function creates an output (as bytes) to burn a given amount of coins
#[wasm_bindgen]
pub fn encode_output_coin_burn(amount: Amount) -> Result<Vec<u8>, Error> {
    let amount = amount.as_internal_amount()?;

    let output = TxOutput::Burn(Coin(amount));
    Ok(output.encode())
}

/// Given an amount, token ID (in address form) and network type (mainnet, testnet, etc),
/// this function creates an output (as bytes) to burn a given amount of tokens
#[wasm_bindgen]
pub fn encode_output_token_burn(
    amount: Amount,
    token_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let token = parse_addressable(&chain_config, token_id)?;

    let output = TxOutput::Burn(TokenV1(token, amount));
    Ok(output.encode())
}

/// Given a pool id as string, an owner address and a network type (mainnet, testnet, etc),
/// this function returns an output (as bytes) to create a delegation to the given pool.
/// The owner address is the address that is authorized to withdraw from that delegation.
#[wasm_bindgen]
pub fn encode_output_create_delegation(
    pool_id: &str,
    owner_address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let destination = parse_addressable(&chain_config, owner_address)?;
    let pool_id = parse_addressable(&chain_config, pool_id)?;

    let output = TxOutput::CreateDelegationId(destination, pool_id);
    Ok(output.encode())
}

/// Given a delegation id (as string, in address form), an amount and a network type (mainnet, testnet, etc),
/// this function returns an output (as bytes) that would delegate coins to be staked in the specified delegation id.
#[wasm_bindgen]
pub fn encode_output_delegate_staking(
    amount: Amount,
    delegation_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let delegation_id = parse_addressable(&chain_config, delegation_id)?;

    let output = TxOutput::DelegateStaking(amount, delegation_id);
    Ok(output.encode())
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

/// Given a pool id, staking data as bytes and the network type (mainnet, testnet, etc),
/// this function returns an output that creates that staking pool.
/// Note that the pool id is mandated to be taken from the hash of the first input.
/// It is not arbitrary.
#[wasm_bindgen]
pub fn encode_output_create_stake_pool(
    pool_id: &str,
    pool_data: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let pool_id = parse_addressable(&chain_config, pool_id)?;
    let pool_data = StakePoolData::decode_all(&mut &pool_data[..])
        .map_err(Error::InvalidStakePoolDataEncoding)?;

    let output = TxOutput::CreateStakePool(pool_id, Box::new(pool_data));
    Ok(output.encode())
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

/// Given the parameters needed to issue a fungible token, and a network type (mainnet, testnet, etc),
/// this function creates an output that issues that token.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_output_issue_fungible_token(
    authority: &str,
    token_ticker: &str,
    metadata_uri: &str,
    number_of_decimals: u8,
    total_supply: TotalSupply,
    supply_amount: Option<Amount>,
    is_token_freezable: FreezableToken,
    _current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let authority = parse_addressable(&chain_config, authority)?;
    let token_ticker = token_ticker.into();
    let metadata_uri = metadata_uri.into();
    let total_supply = parse_token_total_supply(total_supply, supply_amount)?;
    let is_freezable = is_token_freezable.into();

    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        authority,
        token_ticker,
        metadata_uri,
        number_of_decimals,
        total_supply,
        is_freezable,
    });

    tx_verifier::check_tokens_issuance(&chain_config, &token_issuance)
        .map_err(Error::InvalidTokenParameters)?;

    let output = TxOutput::IssueFungibleToken(Box::new(token_issuance));
    Ok(output.encode())
}

/// Returns the Fungible/NFT Token ID for the given inputs of a transaction
#[wasm_bindgen]
pub fn get_token_id(
    mut inputs: &[u8],
    current_block_height: u64,
    network: Network,
) -> Result<String, Error> {
    let chain_config = Builder::new(network.into()).build();

    let mut tx_inputs = vec![];
    while !inputs.is_empty() {
        let input = TxInput::decode(&mut inputs).map_err(Error::InvalidInputEncoding)?;
        tx_inputs.push(input);
    }

    let token_id = make_token_id(
        &chain_config,
        BlockHeight::new(current_block_height),
        &tx_inputs,
    )?;

    Ok(Address::new(&chain_config, token_id)
        .expect("Should not fail to create address")
        .to_string())
}

/// Given the parameters needed to issue an NFT, and a network type (mainnet, testnet, etc),
/// this function creates an output that issues that NFT.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_output_issue_nft(
    token_id: &str,
    authority: &str,
    name: &str,
    ticker: &str,
    description: &str,
    media_hash: &[u8],
    creator: Option<Vec<u8>>,
    media_uri: Option<String>,
    icon_uri: Option<String>,
    additional_metadata_uri: Option<String>,
    _current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let authority = parse_addressable(&chain_config, authority)?;
    let name = name.into();
    let ticker = ticker.into();
    let media_uri = media_uri.map(Into::into).into();
    let icon_uri = icon_uri.map(Into::into).into();
    let media_hash = media_hash.into();
    let additional_metadata_uri = additional_metadata_uri.map(Into::into).into();
    let creator = creator
        .map(|pk| PublicKey::decode_all(&mut pk.as_slice()))
        .transpose()
        .map_err(Error::InvalidNftCreatorPublicKey)?
        .map(|public_key| TokenCreator { public_key });

    let nft_issuance = NftIssuanceV0 {
        metadata: Metadata {
            media_hash,
            media_uri,
            ticker,
            additional_metadata_uri,
            description: description.into(),
            name,
            icon_uri,
            creator,
        },
    };

    tx_verifier::check_nft_issuance_data(&chain_config, &nft_issuance)
        .map_err(Error::InvalidTokenParameters)?;

    let output = TxOutput::IssueNft(token_id, Box::new(NftIssuance::V0(nft_issuance)), authority);
    Ok(output.encode())
}

/// Given data to be deposited in the blockchain, this function provides the output that deposits this data
#[wasm_bindgen]
pub fn encode_output_data_deposit(data: &[u8]) -> Result<Vec<u8>, Error> {
    let output = TxOutput::DataDeposit(data.into());
    Ok(output.encode())
}

/// Returns the fee that needs to be paid by a transaction for issuing a data deposit
#[wasm_bindgen]
pub fn data_deposit_fee(current_block_height: u64, network: Network) -> Amount {
    let chain_config = Builder::new(network.into()).build();
    Amount::from_internal_amount(
        chain_config.data_deposit_fee(BlockHeight::new(current_block_height)),
    )
}

fn parse_output_value(
    chain_config: &ChainConfig,
    amount: &Amount,
    token_id: Option<String>,
) -> Result<OutputValue, Error> {
    let amount = amount.as_internal_amount()?;
    match token_id {
        Some(token_id) => {
            let token_id = parse_addressable(chain_config, &token_id)?;
            Ok(OutputValue::TokenV1(token_id, amount))
        }
        None => Ok(OutputValue::Coin(amount)),
    }
}

/// Given the parameters needed to create hash timelock contract, and a network type (mainnet, testnet, etc),
/// this function creates an output.
#[wasm_bindgen]
pub fn encode_output_htlc(
    amount: Amount,
    token_id: Option<String>,
    secret_hash: &str,
    spend_address: &str,
    refund_address: &str,
    refund_timelock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let output_value = parse_output_value(&chain_config, &amount, token_id)?;
    let refund_timelock = OutputTimeLock::decode_all(&mut &refund_timelock[..])
        .map_err(Error::InvalidTimeLockEncoding)?;
    let secret_hash =
        HtlcSecretHash::from_str(secret_hash).map_err(Error::HtlcSecretHashParseError)?;

    let spend_key = parse_addressable(&chain_config, spend_address)?;
    let refund_key = parse_addressable(&chain_config, refund_address)?;

    let htlc = HashedTimelockContract {
        secret_hash,
        spend_key,
        refund_timelock,
        refund_key,
    };
    let output = TxOutput::Htlc(output_value, Box::new(htlc));
    Ok(output.encode())
}

/// Given a signed transaction and input outpoint that spends an htlc utxo, extract a secret that is
/// encoded in the corresponding input signature
#[wasm_bindgen]
pub fn extract_htlc_secret(
    signed_tx_bytes: &[u8],
    strict_byte_size: bool,
    htlc_outpoint_source_id: &[u8],
    htlc_output_index: u32,
) -> Result<Vec<u8>, Error> {
    let outpoint_source_id = OutPointSourceId::decode_all(&mut &htlc_outpoint_source_id[..])
        .map_err(Error::InvalidOutpointIdEncoding)?;
    let htlc_utxo_outpoint = UtxoOutPoint::new(outpoint_source_id, htlc_output_index);

    let tx = if strict_byte_size {
        SignedTransaction::decode_all(&mut &signed_tx_bytes[..])
            .map_err(Error::InvalidTransactionEncoding)?
    } else {
        SignedTransaction::decode(&mut &signed_tx_bytes[..])
            .map_err(Error::InvalidTransactionEncoding)?
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

    match tx.signatures().get(htlc_position).ok_or(Error::InvalidWitnessCount)? {
        InputWitness::NoSignature(_) => {
            Err(Error::UnexpectedWitnessType(InputWitnessTag::NoSignature))
        }
        InputWitness::Standard(sig) => {
            let htlc_spend = AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())
                .map_err(Error::HtlcSpendCreationError)?;
            match htlc_spend {
                AuthorizedHashedTimelockContractSpend::Secret(secret, _) => Ok(secret.encode()),
                AuthorizedHashedTimelockContractSpend::Multisig(_) => {
                    Err(Error::UnexpectedHtlcSpendType(
                        AuthorizedHashedTimelockContractSpendTag::Multisig,
                    ))
                }
            }
        }
    }
}

/// Given an output source id as bytes, and an output index, together representing a utxo,
/// this function returns the input that puts them together, as bytes.
#[wasm_bindgen]
pub fn encode_input_for_utxo(
    outpoint_source_id: &[u8],
    output_index: u32,
) -> Result<Vec<u8>, Error> {
    let outpoint_source_id = OutPointSourceId::decode_all(&mut &outpoint_source_id[..])
        .map_err(Error::InvalidOutpointIdEncoding)?;
    let input = TxInput::Utxo(UtxoOutPoint::new(outpoint_source_id, output_index));
    Ok(input.encode())
}

/// Given a delegation id, an amount and a network type (mainnet, testnet, etc), this function
/// creates an input that withdraws from a delegation.
/// A nonce is needed because this spends from an account. The nonce must be in sequence for everything in that account.
#[wasm_bindgen]
pub fn encode_input_for_withdraw_from_delegation(
    delegation_id: &str,
    amount: Amount,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let delegation_id = parse_addressable(&chain_config, delegation_id)?;
    let input = TxInput::Account(AccountOutPoint::new(
        AccountNonce::new(nonce),
        AccountSpending::DelegationBalance(delegation_id, amount),
    ));
    Ok(input.encode())
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
    mut outputs: &[u8],
    network: Network,
) -> Result<usize, Error> {
    let chain_config = Builder::new(network.into()).build();
    let mut tx_outputs = vec![];
    while !outputs.is_empty() {
        let output = TxOutput::decode(&mut outputs).map_err(Error::InvalidOutputEncoding)?;
        tx_outputs.push(output);
    }

    let size =
        tx_size_with_num_inputs_and_outputs(tx_outputs.len(), input_utxos_destinations.len())
            + outputs_encoded_size(tx_outputs.as_slice());
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
pub fn encode_transaction(
    mut inputs: &[u8],
    mut outputs: &[u8],
    flags: u64,
) -> Result<Vec<u8>, Error> {
    let mut tx_outputs = vec![];
    while !outputs.is_empty() {
        let output = TxOutput::decode(&mut outputs).map_err(Error::InvalidOutputEncoding)?;
        tx_outputs.push(output);
    }

    let mut tx_inputs = vec![];
    while !inputs.is_empty() {
        let input = TxInput::decode(&mut inputs).map_err(Error::InvalidInputEncoding)?;
        tx_inputs.push(input);
    }

    let tx = Transaction::new(flags as u128, tx_inputs, tx_outputs).expect("no error");
    Ok(tx.encode())
}

/// Encode an input witness of the variant that contains no signature.
#[wasm_bindgen]
pub fn encode_witness_no_signature() -> Vec<u8> {
    InputWitness::NoSignature(None).encode()
}

/// Given a private key, inputs and an input number to sign, and the destination that owns that output (through the utxo),
/// and a network type (mainnet, testnet, etc), this function returns a witness to be used in a signed transaction, as bytes.
#[wasm_bindgen]
pub fn encode_witness(
    sighashtype: SignatureHashType,
    private_key_bytes: &[u8],
    input_owner_destination: &str,
    transaction_bytes: &[u8],
    mut inputs: &[u8],
    input_num: u32,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key = PrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;

    let destination = parse_addressable(&chain_config, input_owner_destination)?;

    let tx = Transaction::decode_all(&mut &transaction_bytes[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let mut input_utxos = vec![];
    while !inputs.is_empty() {
        let utxo = Option::<TxOutput>::decode(&mut inputs).map_err(Error::InvalidInputEncoding)?;
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
        randomness::make_true_rng(),
    )
    .map(InputWitness::Standard)
    .map_err(Error::InputSigningError)?;

    Ok(witness.encode())
}

/// Given a private key, inputs and an input number to sign, and the destination that owns that output (through the utxo),
/// and a network type (mainnet, testnet, etc), and an htlc secret this function returns a witness to be used in a signed transaction, as bytes.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_witness_htlc_secret(
    sighashtype: SignatureHashType,
    private_key_bytes: &[u8],
    input_owner_destination: &str,
    transaction_bytes: &[u8],
    mut inputs: &[u8],
    input_num: u32,
    mut secret: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key = PrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;

    let destination = parse_addressable(&chain_config, input_owner_destination)?;

    let tx = Transaction::decode_all(&mut &transaction_bytes[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let mut input_utxos = vec![];
    while !inputs.is_empty() {
        let utxo = Option::<TxOutput>::decode(&mut inputs).map_err(Error::InvalidInputEncoding)?;
        input_utxos.push(utxo);
    }

    let utxos = input_utxos.iter().map(Option::as_ref).collect::<Vec<_>>();

    let secret = HtlcSecret::decode_all(&mut secret).map_err(Error::InvalidHtlcSecretEncoding)?;

    let witness = produce_uniparty_signature_for_htlc_input(
        &private_key,
        sighashtype.into(),
        destination,
        &tx,
        &utxos,
        input_num as usize,
        secret,
        randomness::make_true_rng(),
    )
    .map(InputWitness::Standard)
    .map_err(Error::InputSigningError)?;

    Ok(witness.encode())
}

/// Given an arbitrary number of public keys as bytes, number of minimum required signatures, and a network type, this function returns
/// the multisig challenge, as bytes.
#[wasm_bindgen]
pub fn encode_multisig_challenge(
    mut public_keys_bytes: &[u8],
    min_required_signatures: u8,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let min_sigs =
        NonZeroU8::new(min_required_signatures).ok_or(Error::ZeroMultisigRequiredSigs)?;

    let mut public_keys = vec![];
    while !public_keys_bytes.is_empty() {
        let public_key =
            PublicKey::decode(&mut public_keys_bytes).map_err(Error::InvalidPublicKeyEncoding)?;
        public_keys.push(public_key);
    }

    let challenge = ClassicMultisigChallenge::new(&chain_config, min_sigs, public_keys)
        .map_err(Error::MultisigChallengeCreationError)?;

    Ok(challenge.encode())
}

/// Given a private key, inputs and an input number to sign, and multisig challenge,
/// and a network type (mainnet, testnet, etc), this function returns a witness to be used in a signed transaction, as bytes.
///
/// `key_index` parameter is an index of a public key in the challenge, against which is the signature produces from private key is to be verified.
/// `input_witness` parameter can be either empty or a result of previous calls to this function.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_witness_htlc_multisig(
    sighashtype: SignatureHashType,
    private_key_bytes: &[u8],
    key_index: u8,
    mut input_witness: &[u8],
    mut multisig_challenge: &[u8],
    transaction_bytes: &[u8],
    mut utxos: &[u8],
    input_num: u32,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();

    let private_key = PrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(Error::InvalidPrivateKeyEncoding)?;

    let tx = Transaction::decode_all(&mut &transaction_bytes[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let mut input_utxos = vec![];
    while !utxos.is_empty() {
        let utxo = Option::<TxOutput>::decode(&mut utxos).map_err(Error::InvalidInputEncoding)?;
        input_utxos.push(utxo);
    }

    let utxos = input_utxos.iter().map(Option::as_ref).collect::<Vec<_>>();
    let sighashtype = sighashtype.into();
    let sighash = signature_hash(sighashtype, &tx, &utxos, input_num as usize)
        .map_err(Error::SighashCalculationError)?;

    let mut rng = randomness::make_true_rng();
    let challenge = ClassicMultisigChallenge::decode_all(&mut multisig_challenge)
        .map_err(Error::InvalidMultisigChallengeEncoding)?;
    let authorization = if !input_witness.is_empty() {
        let input_witness =
            InputWitness::decode_all(&mut input_witness).map_err(Error::InvalidWitnessEncoding)?;

        match input_witness {
            InputWitness::NoSignature(_) => {
                return Err(Error::UnexpectedWitnessType(InputWitnessTag::NoSignature))
            }
            InputWitness::Standard(sig) => {
                let htlc_spend =
                    AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())
                        .map_err(Error::HtlcSpendCreationError)?;
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
pub fn encode_signed_transaction(
    transaction_bytes: &[u8],
    mut signatures: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut tx_signatures = vec![];
    while !signatures.is_empty() {
        let signature =
            InputWitness::decode(&mut signatures).map_err(Error::InvalidWitnessEncoding)?;
        tx_signatures.push(signature);
    }

    let tx = Transaction::decode_all(&mut &transaction_bytes[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let tx = SignedTransaction::new(tx, tx_signatures).map_err(Error::TransactionCreationError)?;
    Ok(tx.encode())
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
pub fn get_transaction_id(
    transaction_bytes: &[u8],
    strict_byte_size: bool,
) -> Result<String, Error> {
    let tx = if strict_byte_size {
        Transaction::decode_all(&mut &transaction_bytes[..])
            .map_err(Error::InvalidTransactionEncoding)?
    } else {
        Transaction::decode(&mut &transaction_bytes[..])
            .map_err(Error::InvalidTransactionEncoding)?
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

/// Given a token_id, an amount of tokens to mint and nonce return an encoded mint tokens input
#[wasm_bindgen]
pub fn encode_input_for_mint_tokens(
    token_id: &str,
    amount: Amount,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let amount = amount.as_internal_amount()?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::MintTokens(token_id, amount),
    );
    Ok(input.encode())
}

/// Given a token_id and nonce return an encoded unmint tokens input
#[wasm_bindgen]
pub fn encode_input_for_unmint_tokens(
    token_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::UnmintTokens(token_id),
    );
    Ok(input.encode())
}

/// Given a token_id and nonce return an encoded lock_token_supply input
#[wasm_bindgen]
pub fn encode_input_for_lock_token_supply(
    token_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::LockTokenSupply(token_id),
    );
    Ok(input.encode())
}

/// Given a token_id, is token unfreezable and nonce return an encoded freeze token input
#[wasm_bindgen]
pub fn encode_input_for_freeze_token(
    token_id: &str,
    is_token_unfreezable: TokenUnfreezable,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::FreezeToken(token_id, is_token_unfreezable.into()),
    );
    Ok(input.encode())
}

/// Given a token_id and nonce return an encoded unfreeze token input
#[wasm_bindgen]
pub fn encode_input_for_unfreeze_token(
    token_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::UnfreezeToken(token_id),
    );
    Ok(input.encode())
}

/// Given a token_id, new authority destination and nonce return an encoded change token authority input
#[wasm_bindgen]
pub fn encode_input_for_change_token_authority(
    token_id: &str,
    new_authority: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let new_authority = parse_addressable(&chain_config, new_authority)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::ChangeTokenAuthority(token_id, new_authority),
    );
    Ok(input.encode())
}

/// Given a token_id, new metadata uri and nonce return an encoded change token metadata uri input
#[wasm_bindgen]
pub fn encode_input_for_change_token_metadata_uri(
    token_id: &str,
    new_metadata_uri: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::ChangeTokenMetadataUri(token_id, new_metadata_uri.into()),
    );
    Ok(input.encode())
}

/// Given ask and give amounts and a conclude key create output that creates an order.
///
/// 'ask_token_id': the parameter represents a Token if it's Some and coins otherwise.
/// 'give_token_id': the parameter represents a Token if it's Some and coins otherwise.
#[wasm_bindgen]
pub fn encode_create_order_output(
    ask_amount: Amount,
    ask_token_id: Option<String>,
    give_amount: Amount,
    give_token_id: Option<String>,
    conclude_address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let ask = parse_output_value(&chain_config, &ask_amount, ask_token_id)?;
    let give = parse_output_value(&chain_config, &give_amount, give_token_id)?;
    let conclude_key = parse_addressable(&chain_config, conclude_address)?;

    let order = OrderData::new(conclude_key, ask, give);
    let output = TxOutput::CreateOrder(Box::new(order));
    Ok(output.encode())
}

/// Given an amount to fill an order (which is described in terms of ask currency) and a destination
/// for result outputs create an input that fills the order.
#[wasm_bindgen]
pub fn encode_input_for_fill_order(
    order_id: &str,
    fill_amount: Amount,
    destination: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let order_id = parse_addressable(&chain_config, order_id)?;
    let fill_amount = fill_amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, destination)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::FillOrder(order_id, fill_amount, destination),
    );
    Ok(input.encode())
}

/// Given an order id create an input that concludes the order.
#[wasm_bindgen]
pub fn encode_input_for_conclude_order(
    order_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let order_id = parse_addressable(&chain_config, order_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::ConcludeOrder(order_id),
    );
    Ok(input.encode())
}

#[cfg(test)]
mod tests {
    use randomness::Rng;
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

        let signature = sign_message_for_spending(&key, &message).unwrap();

        {
            // Valid reference signature
            let verification_result =
                verify_signature_for_spending(&public_key, &signature, &message).unwrap();
            assert!(verification_result);
        }
        {
            // Tamper with the message
            let mut tampered_message = message.clone();
            let tamper_bit_index = rng.gen::<usize>() % message_size;
            tampered_message[tamper_bit_index] = tampered_message[tamper_bit_index].wrapping_add(1);
            let verification_result =
                verify_signature_for_spending(&public_key, &signature, &tampered_message).unwrap();
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
                verify_signature_for_spending(&public_key, &tampered_signature, &message).unwrap();
            assert!(!verification_result);
        }
        {
            // Wrong keys
            let private_key = make_private_key();
            let public_key = public_key_from_private_key(&private_key).unwrap();
            let verification_result =
                verify_signature_for_spending(&public_key, &signature, &message).unwrap();
            assert!(!verification_result);
        }
    }

    #[test]
    fn transaction_get_id() {
        let expected_tx_id = "35a7938c2a2aad5ae324e7d0536de245bf9e439169aa3c16f1492be117e5d0e0";
        let tx_hex = "0100040000ff5d9a94390ee97208d31aa5c3b5ddbd8df9d308069df2ebf5283f7ce3e4261401000000080340f9924e4da0af7dc8c5be71a9c9e05962c7bf4ef96127fde7a7b4e1469e48620f0080e03779c31102000365807e3b4147cb978b78715e60606092f89dc769586e98456850bd3b449c87b400203015e9ef9fc142569e0f966bc0188464fa712a841e14002e0fe952a076a26c01e539c5f0ceba927ab8f8f55f274af739ce4eef3700000b00204aa9d10100000b409e4c355d010199e4ec3a5b176140ef9cd58c7d3579fdb0ecb21a";
        let tx_signed_hex = "0100040000ff5d9a94390ee97208d31aa5c3b5ddbd8df9d308069df2ebf5283f7ce3e4261401000000080340f9924e4da0af7dc8c5be71a9c9e05962c7bf4ef96127fde7a7b4e1469e48620f0080e03779c31102000365807e3b4147cb978b78715e60606092f89dc769586e98456850bd3b449c87b400203015e9ef9fc142569e0f966bc0188464fa712a841e14002e0fe952a076a26c01e539c5f0ceba927ab8f8f55f274af739ce4eef3700000b00204aa9d10100000b409e4c355d010199e4ec3a5b176140ef9cd58c7d3579fdb0ecb21a0401018d010002eddd003bfb6333123e682abe6923da1d38faa4f0e0d9e2ee42d5aa46c152a34800a749a30c8c9c33696ce407fc145ebc9824e17b778d0d9ccc8129be52f37b74160e60f6689ac2f481071e1a63d9cf0f6eab84c2703b5e9f229cd8188ce092edd4";

        let tx_bin = hex::decode(tx_hex).unwrap();
        let tx_signed_bin = hex::decode(tx_signed_hex).unwrap();

        assert_eq!(get_transaction_id(&tx_bin, true).unwrap(), expected_tx_id);
        assert_eq!(get_transaction_id(&tx_bin, false).unwrap(), expected_tx_id);

        get_transaction_id(&tx_signed_bin, true).unwrap_err();
        assert_eq!(
            get_transaction_id(&tx_signed_bin, false).unwrap(),
            expected_tx_id
        );
    }
}
