// Copyright (c) 2024 RBB S.r.l
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

//! Common code used by Trezor firmware with no-std

#![no_std]

mod input_commitments;

use num_derive::FromPrimitive;
use parity_scale_codec::{Decode, Encode};
use strum::{EnumDiscriminants, EnumIter};

// Note: below we have a bunch of numeric enums (most of which are implicitly generated via `strum_discriminants`,
// but IsTokenFreezable is also one of them) that are used in the communication between the rust and the python parts
// of the firmware, which means that their values must coincide with certain protobuf-generated types.
// This is rather fragile.
// TODO:
// 1) The values of the implicitly generated "Tag" enums should NOT be relied upon. The main purpose of a tag is to make
// sure that all variants of the parent enum are handled by tests. If we need enums that correspond to the protobuf-generated values,
// they must be separate enums.
// The same is true for IsTokenFreezable - though we can assign specific values to its variants, it's probably better
// to have a separate enum for firmware-specific purposes.
// 2) Having these enums for the rust-python communication in the firmware is redundant, because the protobuf-generated
// values could be used directly (though they are still a bit useful, because they'll force a compilation error on the rust side
// whenever an enum gets more variants).
// Note however that re-using protobuf-generated values in the firmware may be problematic because in the general case
// the generated code relies on the std lib, while the firmware requires no-std. But technically it should still be
// achievable by isolating the primitive enums that are needed by the firmware (and which don't need std) from the rest.
// 3) Normally, these enums should be in the firmware repo. The only reason for keeping them in the core repo is that
// here it's easier to test that they indeed have the required values. But they and their tests should probably live in
// a separate module, so that they are not confused with the "normal" enums.

pub use input_commitments::*;

/// Specifies which parts of the transaction a signature commits to.
///
/// The values of the flags are the same as in Bitcoin.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Ord, PartialOrd, Encode, Decode)]
pub struct SigHashType(u8);

impl SigHashType {
    pub const ALL: u8 = 0x01;
    pub const NONE: u8 = 0x02;
    pub const SINGLE: u8 = 0x03;
    pub const ANYONECANPAY: u8 = 0x80;

    pub const MASK_OUT: u8 = 0x7f;
    pub const MASK_IN: u8 = 0x80;

    pub fn get(&self) -> u8 {
        self.0
    }
}

type UnsignedIntType = u128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Amount {
    #[codec(compact)]
    atoms: UnsignedIntType,
}

impl Amount {
    pub const MAX: Self = Self::from_atoms(UnsignedIntType::MAX);
    pub const ZERO: Self = Self::from_atoms(0);

    pub const fn from_atoms(v: UnsignedIntType) -> Self {
        Amount { atoms: v }
    }

    pub const fn into_atoms(&self) -> UnsignedIntType {
        self.atoms
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        bytes
            .try_into()
            .ok()
            .map(|b| Self::from_atoms(UnsignedIntType::from_be_bytes(b)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OutputValue {
    Coin(Amount),
    TokenV0,
    TokenV1(H256, Amount),
}

// Note: OutputTimeLockTag is used in the communication between the rust and python parts of the firmware,
// which expects its values to be the same as in the protobuf-generated MintlayerOutputTimeLockType.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, EnumDiscriminants)]
#[strum_discriminants(name(OutputTimeLockTag), derive(EnumIter, FromPrimitive))]
pub enum OutputTimeLock {
    #[codec(index = 0)]
    UntilHeight(#[codec(compact)] u64),
    #[codec(index = 1)]
    UntilTime(#[codec(compact)] u64),
    #[codec(index = 2)]
    ForBlockCount(#[codec(compact)] u64),
    #[codec(index = 3)]
    ForSeconds(#[codec(compact)] u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct StakePoolData {
    pub pledge: Amount,
    pub staker: Destination,
    pub vrf_public_key: VRFPublicKeyHolder,
    pub decommission_key: Destination,
    pub margin_ratio_per_thousand: u16,
    pub cost_per_block: Amount,
}

const HASH_SIZE: usize = 20;
const PK_SIZE: usize = 33;
const VRF_PK_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct PublicKeyHash(pub [u8; HASH_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct PublicKey(pub [u8; PK_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct VRFPublicKey(pub [u8; VRF_PK_SIZE]);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub enum VRFPublicKeyHolder {
    #[codec(index = 0)]
    Schnorrkel(VRFPublicKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub enum PublicKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(PublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    #[codec(index = 0)]
    AnyoneCanSpend, /* zero verification; used primarily for testing. Never use this for real
                     * money */
    #[codec(index = 1)]
    PublicKeyHash(PublicKeyHash),
    #[codec(index = 2)]
    PublicKey(PublicKeyHolder),
    #[codec(index = 3)]
    ScriptHash(H256),
    #[codec(index = 4)]
    ClassicMultisig(PublicKeyHash),
}

#[derive(Encode, Decode)]
pub enum TokenIssuance {
    #[codec(index = 1)]
    V1(TokenIssuanceV1),
}

// Note: IsTokenFreezable is used in the communication between the rust and python parts of the firmware,
// where it's constructed from int representation of a boolean flag "is_freezable" (so, No must be zero and Yes must be 1).
//
// Also note that this is not the case for the `IsTokenUnfreezable` enum defined below - though
// it is also used in the communication between rust and python parts of the firmware, it's passed
// in its encoded form, so its values are not relied upon.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, EnumIter, FromPrimitive)]
pub enum IsTokenFreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

// Note: TokenTotalSupplyTag is used in the communication between the rust and python parts of the firmware,
// which expects its values to be the same as in the protobuf-generated MintlayerTokenTotalSupplyType.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, EnumDiscriminants)]
#[strum_discriminants(name(TokenTotalSupplyTag), derive(EnumIter, FromPrimitive))]
pub enum TokenTotalSupply {
    #[codec(index = 0)]
    Fixed(Amount), // fixed to a certain amount
    #[codec(index = 1)]
    Lockable, // not known in advance but can be locked once at some point in time
    #[codec(index = 2)]
    Unlimited, // limited only by the Amount data type
}

#[derive(Encode, Decode)]
pub struct TokenIssuanceV1 {
    pub token_ticker: parity_scale_codec::alloc::vec::Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub total_supply: TokenTotalSupply,
    pub authority: Destination,
    pub is_freezable: IsTokenFreezable,
}

#[derive(Encode, Decode)]
pub enum NftIssuance {
    #[codec(index = 0)]
    V0(NftIssuanceV0),
}

#[derive(Encode, Decode)]
pub struct NftIssuanceV0 {
    pub metadata: Metadata,
}

#[derive(Encode, Decode)]
pub struct Metadata {
    pub creator: Option<PublicKeyHolder>,
    pub name: parity_scale_codec::alloc::vec::Vec<u8>,
    pub description: parity_scale_codec::alloc::vec::Vec<u8>,
    pub ticker: parity_scale_codec::alloc::vec::Vec<u8>,
    pub icon_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub additional_metadata_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub media_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub media_hash: parity_scale_codec::alloc::vec::Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct OrderData {
    /// The key that can authorize conclusion of an order
    pub conclude_key: Destination,
    /// `Ask` and `give` fields represent amounts of currencies
    /// that an order maker wants to exchange.
    /// E.g. Creator of an order asks for 5 coins and gives 10 tokens in
    /// exchange.
    pub ask: OutputValue,
    pub give: OutputValue,
}

#[derive(Encode, Decode)]
pub enum TxOutput {
    /// Transfer an output, giving the provided Destination the authority to
    /// spend it (no conditions)
    #[codec(index = 0)]
    Transfer(OutputValue, Destination),
    /// Same as Transfer, but with the condition that an output can only be
    /// specified after some point in time.
    #[codec(index = 1)]
    LockThenTransfer(OutputValue, Destination, OutputTimeLock),
    /// Burn an amount (whether coin or token)
    #[codec(index = 2)]
    Burn(OutputValue),
    /// Output type that is used to create a stake pool
    #[codec(index = 3)]
    CreateStakePool(H256, StakePoolData),
    /// Output type that represents spending of a stake pool output in a block
    /// reward in order to produce a block
    #[codec(index = 4)]
    ProduceBlockFromStake(Destination, H256),
    /// Create a delegation; takes the owner destination (address authorized to
    /// withdraw from the delegation) and a pool id
    #[codec(index = 5)]
    CreateDelegationId(Destination, H256),
    /// Transfer an amount to a delegation that was previously created for
    /// staking
    #[codec(index = 6)]
    DelegateStaking(Amount, H256),
    #[codec(index = 7)]
    IssueFungibleToken(TokenIssuance),
    #[codec(index = 8)]
    IssueNft(H256, NftIssuance, Destination),
    #[codec(index = 9)]
    DataDeposit(parity_scale_codec::alloc::vec::Vec<u8>),
    #[codec(index = 10)]
    Htlc(OutputValue, HashedTimelockContract),
    #[codec(index = 11)]
    CreateOrder(OrderData),
}

#[derive(Encode, Decode)]
pub struct HashedTimelockContract {
    // can be spent either by a specific address that knows the secret
    pub secret_hash: HtlcSecretHash,
    pub spend_key: Destination,

    // or by a multisig after timelock expires making it possible to refund
    pub refund_timelock: OutputTimeLock,
    pub refund_key: Destination,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Encode, Decode)]
pub struct H256(pub [u8; 32]);

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Encode, Decode)]
pub struct HtlcSecretHash(pub [u8; 20]);

// Note: OutPointSourceIdTag is used in the communication between the rust and python parts of the firmware,
// which expects its values to be the same as in the protobuf-generated MintlayerUtxoType.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Ord, PartialOrd, EnumDiscriminants)]
#[strum_discriminants(name(OutPointSourceIdTag), derive(EnumIter, FromPrimitive))]
pub enum OutPointSourceId {
    #[codec(index = 0)]
    Transaction(H256),
    #[codec(index = 1)]
    BlockReward(H256),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Ord, PartialOrd)]
pub struct UtxoOutPoint {
    id: OutPointSourceId,
    index: u32,
}

impl UtxoOutPoint {
    pub fn new(outpoint_source_id: OutPointSourceId, output_index: u32) -> Self {
        UtxoOutPoint {
            id: outpoint_source_id,
            index: output_index,
        }
    }

    pub fn source_id(&self) -> OutPointSourceId {
        self.id.clone()
    }

    pub fn output_index(&self) -> u32 {
        self.index
    }
}

#[derive(Encode)]
pub enum AccountSpending {
    #[codec(index = 0)]
    DelegationBalance(H256, Amount),
}

#[derive(Encode)]
pub struct AccountOutPoint {
    #[codec(compact)]
    pub nonce: u64,
    pub account: AccountSpending,
}

#[derive(Encode, Decode)]
pub enum IsTokenUnfreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

type OrderId = H256;
type TokenId = H256;

// Note: AccountCommandTag is used in the communication between the rust and python parts of the firmware,
// which expects its values to be the same as in the protobuf-generated MintlayerAccountCommandType.
#[derive(Encode, EnumDiscriminants)]
#[strum_discriminants(name(AccountCommandTag), derive(EnumIter, FromPrimitive))]
pub enum AccountCommand {
    // Create certain amount of tokens and add them to circulating supply
    #[codec(index = 0)]
    MintTokens(TokenId, Amount),
    // Take tokens out of circulation. Not the same as Burn because unminting means that certain
    // amount of tokens is no longer supported by underlying fiat currency, which can only be
    // done by the authority.
    #[codec(index = 1)]
    UnmintTokens(TokenId),
    // After supply is locked tokens cannot be minted or unminted ever again.
    // Works only for Lockable tokens supply.
    #[codec(index = 2)]
    LockTokenSupply(TokenId),
    // Freezing token forbids any operation with all the tokens (except for optional unfreeze)
    #[codec(index = 3)]
    FreezeToken(TokenId, IsTokenUnfreezable),
    // By unfreezing token all operations are available for the tokens again
    #[codec(index = 4)]
    UnfreezeToken(TokenId),
    // Change the authority who can authorize operations for a token
    #[codec(index = 5)]
    ChangeTokenAuthority(TokenId, Destination),
    #[codec(index = 6)]
    ConcludeOrder(OrderId),
    #[codec(index = 7)]
    FillOrder(OrderId, Amount, Destination),
    // Change token metadata uri
    #[codec(index = 8)]
    ChangeTokenMetadataUri(TokenId, parity_scale_codec::alloc::vec::Vec<u8>),
}

#[derive(Encode, EnumDiscriminants)]
#[strum_discriminants(name(OrderAccountCommandTag), derive(EnumIter))]
pub enum OrderAccountCommand {
    // Satisfy an order completely or partially.
    // The second element is the fill amount in the order's "ask" currency.
    #[codec(index = 0)]
    FillOrder(OrderId, Amount),
    // Freeze an order which effectively forbids any fill operations.
    // Frozen order can only be concluded.
    // Only the address specified as `conclude_key` can authorize this command.
    #[codec(index = 1)]
    FreezeOrder(OrderId),
    // Close an order and withdraw all remaining funds from both give and ask balances.
    // Only the address specified as `conclude_key` can authorize this command.
    #[codec(index = 2)]
    ConcludeOrder(OrderId),
}

#[derive(Encode)]
pub enum TxInput {
    #[codec(index = 0)]
    Utxo(UtxoOutPoint),
    #[codec(index = 1)]
    Account(AccountOutPoint),
    #[codec(index = 2)]
    AccountCommand(#[codec(compact)] u64, AccountCommand),
    #[codec(index = 3)]
    OrderAccountCommand(OrderAccountCommand),
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
use std::prelude::v1::*;

#[cfg(test)]
mod tests;
