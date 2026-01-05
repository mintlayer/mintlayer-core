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

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        htlc::HashedTimelockContract,
        output_value::OutputValue,
        signature::sighash::input_commitments::SighashInputCommitment,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, NftIssuance, TokenId, TokenIssuance,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, DelegationId, Destination,
        GenBlock, OrderAccountCommand, OrderData, OrderId, OutPointSourceId, PoolId, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Id, H256},
};
use crypto::{
    key::{secp256k1::Secp256k1PublicKey, KeyKind, PublicKey},
    vrf::{SchnorrkelPublicKey, VRFKeyKind, VRFPublicKey},
};
use script::Script;

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum PrimitivesConvertersError {
    #[error("Tokens V0 are not supported")]
    UnsupportedTokenV0,
}

// Custom "TryFrom" trait to work around the Rust's orphan rule.
pub trait TryConvertFrom<T>: Sized {
    fn try_convert_from(value: T) -> Result<Self, PrimitivesConvertersError>;
}

// Custom "TryInto" trait to work around the Rust's orphan rule.
pub trait TryConvertInto<T> {
    fn try_convert_into(self) -> Result<T, PrimitivesConvertersError>;
}

impl<From, To> TryConvertInto<To> for From
where
    To: TryConvertFrom<From>,
{
    fn try_convert_into(self) -> Result<To, PrimitivesConvertersError> {
        <To as TryConvertFrom<From>>::try_convert_from(self)
    }
}

impl TryConvertFrom<H256> for ml_primitives::H256 {
    fn try_convert_from(value: H256) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self(value.0))
    }
}

impl TryConvertFrom<AccountNonce> for ml_primitives::AccountNonce {
    fn try_convert_from(value: AccountNonce) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self(value.value()))
    }
}

impl TryConvertFrom<OutPointSourceId> for ml_primitives::OutPointSourceId {
    fn try_convert_from(value: OutPointSourceId) -> Result<Self, PrimitivesConvertersError> {
        match value {
            OutPointSourceId::Transaction(tx_id) => {
                Ok(Self::Transaction(tx_id.try_convert_into()?))
            }
            OutPointSourceId::BlockReward(block_id) => {
                Ok(Self::BlockReward(block_id.try_convert_into()?))
            }
        }
    }
}

impl TryConvertFrom<UtxoOutPoint> for ml_primitives::UtxoOutPoint {
    fn try_convert_from(value: UtxoOutPoint) -> Result<Self, PrimitivesConvertersError> {
        Ok(ml_primitives::UtxoOutPoint::new(
            value.source_id().try_convert_into()?,
            value.output_index(),
        ))
    }
}

impl TryConvertFrom<Amount> for ml_primitives::Amount {
    fn try_convert_from(value: Amount) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::from_atoms(value.into_atoms()))
    }
}

impl TryConvertFrom<AccountSpending> for ml_primitives::AccountSpending {
    fn try_convert_from(value: AccountSpending) -> Result<Self, PrimitivesConvertersError> {
        match value {
            AccountSpending::DelegationBalance(delegation_id, amount) => {
                Ok(Self::DelegationBalance(
                    delegation_id.try_convert_into()?,
                    amount.try_convert_into()?,
                ))
            }
        }
    }
}

impl TryConvertFrom<AccountOutPoint> for ml_primitives::AccountOutPoint {
    fn try_convert_from(value: AccountOutPoint) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self {
            nonce: ml_primitives::AccountNonce(value.nonce().value()),
            spending: value.account().clone().try_convert_into()?,
        })
    }
}

impl TryConvertFrom<IsTokenUnfreezable> for ml_primitives::IsTokenUnfreezable {
    fn try_convert_from(value: IsTokenUnfreezable) -> Result<Self, PrimitivesConvertersError> {
        match value {
            IsTokenUnfreezable::No => Ok(Self::No),
            IsTokenUnfreezable::Yes => Ok(Self::Yes),
        }
    }
}

impl TryConvertFrom<PublicKey> for ml_primitives::PublicKey {
    fn try_convert_from(value: PublicKey) -> Result<Self, PrimitivesConvertersError> {
        match value.kind() {
            KeyKind::Secp256k1Schnorr => {
                let key: Secp256k1PublicKey = value.try_into().unwrap();
                Ok(ml_primitives::PublicKey::Secp256k1Schnorr(
                    ml_primitives::Secp256k1PublicKey(key.as_bytes()),
                ))
            }
        }
    }
}

impl TryConvertFrom<PublicKeyHash> for ml_primitives::PublicKeyHash {
    fn try_convert_from(value: PublicKeyHash) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self(value.0))
    }
}

impl TryConvertFrom<Destination> for ml_primitives::Destination {
    fn try_convert_from(value: Destination) -> Result<Self, PrimitivesConvertersError> {
        match value {
            Destination::AnyoneCanSpend => Ok(Self::AnyoneCanSpend),
            Destination::PublicKey(pk) => Ok(Self::PublicKey(pk.try_convert_into()?)),
            Destination::ScriptHash(script_id) => {
                Ok(Self::ScriptHash(script_id.try_convert_into()?))
            }
            Destination::PublicKeyHash(pkh) => Ok(Self::PublicKeyHash(pkh.try_convert_into()?)),
            Destination::ClassicMultisig(pkh) => Ok(Self::ClassicMultisig(pkh.try_convert_into()?)),
        }
    }
}

impl TryConvertFrom<AccountCommand> for ml_primitives::AccountCommand {
    fn try_convert_from(value: AccountCommand) -> Result<Self, PrimitivesConvertersError> {
        match value {
            AccountCommand::MintTokens(token_id, amount) => Ok(Self::MintTokens(
                token_id.try_convert_into()?,
                amount.try_convert_into()?,
            )),
            AccountCommand::UnmintTokens(token_id) => {
                Ok(Self::UnmintTokens(token_id.try_convert_into()?))
            }
            AccountCommand::LockTokenSupply(token_id) => {
                Ok(Self::LockTokenSupply(token_id.try_convert_into()?))
            }
            AccountCommand::FreezeToken(token_id, is_unfreezable) => Ok(Self::FreezeToken(
                token_id.try_convert_into()?,
                is_unfreezable.try_convert_into()?,
            )),
            AccountCommand::UnfreezeToken(token_id) => {
                Ok(Self::UnfreezeToken(token_id.try_convert_into()?))
            }
            AccountCommand::ChangeTokenAuthority(token_id, dest) => Ok(Self::ChangeTokenAuthority(
                token_id.try_convert_into()?,
                dest.try_convert_into()?,
            )),
            AccountCommand::ConcludeOrder(order_id) => {
                Ok(Self::ConcludeOrder(order_id.try_convert_into()?))
            }
            AccountCommand::FillOrder(order_id, amount, dest) => Ok(Self::FillOrder(
                order_id.try_convert_into()?,
                amount.try_convert_into()?,
                dest.try_convert_into()?,
            )),
            AccountCommand::ChangeTokenMetadataUri(token_id, uri) => Ok(
                Self::ChangeTokenMetadataUri(token_id.try_convert_into()?, uri),
            ),
        }
    }
}

impl TryConvertFrom<OrderAccountCommand> for ml_primitives::OrderAccountCommand {
    fn try_convert_from(value: OrderAccountCommand) -> Result<Self, PrimitivesConvertersError> {
        match value {
            OrderAccountCommand::FillOrder(order_id, amount) => Ok(Self::FillOrder(
                order_id.try_convert_into()?,
                amount.try_convert_into()?,
            )),
            OrderAccountCommand::FreezeOrder(order_id) => {
                Ok(Self::FreezeOrder(order_id.try_convert_into()?))
            }
            OrderAccountCommand::ConcludeOrder(order_id) => {
                Ok(Self::ConcludeOrder(order_id.try_convert_into()?))
            }
        }
    }
}

impl TryConvertFrom<TxInput> for ml_primitives::TxInput {
    fn try_convert_from(value: TxInput) -> Result<Self, PrimitivesConvertersError> {
        match value {
            TxInput::Utxo(utxo) => Ok(Self::Utxo(utxo.try_convert_into()?)),
            TxInput::Account(acc) => Ok(Self::Account(acc.try_convert_into()?)),
            TxInput::AccountCommand(nonce, command) => Ok(Self::AccountCommand(
                ml_primitives::AccountNonce(nonce.value()),
                command.try_convert_into()?,
            )),
            TxInput::OrderAccountCommand(command) => {
                Ok(Self::OrderAccountCommand(command.try_convert_into()?))
            }
        }
    }
}

impl TryConvertFrom<OutputValue> for ml_primitives::OutputValue {
    fn try_convert_from(value: OutputValue) -> Result<Self, PrimitivesConvertersError> {
        match value {
            OutputValue::Coin(amount) => Ok(Self::Coin(amount.try_convert_into()?)),
            // Replaced panic with Error
            OutputValue::TokenV0(_) => Err(PrimitivesConvertersError::UnsupportedTokenV0),
            OutputValue::TokenV1(token_id, amount) => Ok(Self::TokenV1(
                token_id.try_convert_into()?,
                amount.try_convert_into()?,
            )),
        }
    }
}

impl TryConvertFrom<OutputTimeLock> for ml_primitives::OutputTimeLock {
    fn try_convert_from(value: OutputTimeLock) -> Result<Self, PrimitivesConvertersError> {
        match value {
            OutputTimeLock::UntilHeight(height) => Ok(Self::UntilHeight(
                ml_primitives::BlockHeight(height.into_int()),
            )),
            OutputTimeLock::UntilTime(time) => Ok(Self::UntilTime(ml_primitives::BlockTimestamp(
                ml_primitives::SecondsCount(time.as_int_seconds()),
            ))),
            OutputTimeLock::ForSeconds(secs) => {
                Ok(Self::ForSeconds(ml_primitives::SecondsCount(secs)))
            }
            OutputTimeLock::ForBlockCount(blocks) => {
                Ok(Self::ForBlockCount(ml_primitives::BlocksCount(blocks)))
            }
        }
    }
}

impl TryConvertFrom<HashedTimelockContract> for ml_primitives::HashedTimelockContract {
    fn try_convert_from(value: HashedTimelockContract) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self {
            secret_hash: ml_primitives::HtlcSecretHash(value.secret_hash.0),
            spend_key: value.spend_key.try_convert_into()?,
            refund_timelock: value.refund_timelock.try_convert_into()?,
            refund_key: value.refund_key.try_convert_into()?,
        })
    }
}

impl TryConvertFrom<OrderData> for ml_primitives::OrderData {
    fn try_convert_from(value: OrderData) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self {
            conclude_key: value.conclude_key().clone().try_convert_into()?,
            ask: value.ask().clone().try_convert_into()?,
            give: value.give().clone().try_convert_into()?,
        })
    }
}

impl TryConvertFrom<VRFPublicKey> for ml_primitives::VrfPublicKey {
    fn try_convert_from(value: VRFPublicKey) -> Result<Self, PrimitivesConvertersError> {
        match value.kind() {
            VRFKeyKind::Schnorrkel => {
                let key: SchnorrkelPublicKey = value.try_into().unwrap();

                Ok(ml_primitives::VrfPublicKey::Schnorrkel(
                    ml_primitives::SchnorrkelPublicKey(key.as_bytes()),
                ))
            }
        }
    }
}

impl TryConvertFrom<StakePoolData> for ml_primitives::StakePoolData {
    fn try_convert_from(value: StakePoolData) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self {
            pledge: value.pledge().try_convert_into()?,
            staker: value.staker().clone().try_convert_into()?,
            vrf_public_key: value.vrf_public_key().clone().try_convert_into()?,
            decommission_key: value.decommission_key().clone().try_convert_into()?,
            margin_ratio_per_thousand: ml_primitives::PerThousand(
                value.margin_ratio_per_thousand().value(),
            ),
            cost_per_block: value.cost_per_block().try_convert_into()?,
        })
    }
}

impl TryConvertFrom<NftIssuance> for ml_primitives::NftIssuance {
    fn try_convert_from(value: NftIssuance) -> Result<Self, PrimitivesConvertersError> {
        match value {
            NftIssuance::V0(data) => Ok(Self::V0(ml_primitives::NftIssuanceV0 {
                creator: data
                    .metadata
                    .creator
                    .map(|c| c.public_key.try_convert_into())
                    .transpose()?,
                name: data.metadata.name,
                description: data.metadata.description,
                ticker: data.metadata.ticker,
                icon_uri: data.metadata.icon_uri.as_ref().clone().map_or(Vec::new(), Into::into),
                additional_metadata_uri: data
                    .metadata
                    .additional_metadata_uri
                    .as_ref()
                    .clone()
                    .map_or(Vec::new(), Into::into),
                media_uri: data.metadata.media_uri.as_ref().clone().map_or(Vec::new(), Into::into),
                media_hash: data.metadata.media_hash,
            })),
        }
    }
}

impl TryConvertFrom<TokenTotalSupply> for ml_primitives::TokenTotalSupply {
    fn try_convert_from(value: TokenTotalSupply) -> Result<Self, PrimitivesConvertersError> {
        match value {
            TokenTotalSupply::Lockable => Ok(Self::Lockable),
            TokenTotalSupply::Unlimited => Ok(Self::Unlimited),
            TokenTotalSupply::Fixed(amount) => Ok(Self::Fixed(amount.try_convert_into()?)),
        }
    }
}

impl TryConvertFrom<IsTokenFreezable> for ml_primitives::IsTokenFreezable {
    fn try_convert_from(value: IsTokenFreezable) -> Result<Self, PrimitivesConvertersError> {
        match value {
            IsTokenFreezable::No => Ok(Self::No),
            IsTokenFreezable::Yes => Ok(Self::Yes),
        }
    }
}

impl TryConvertFrom<TokenIssuance> for ml_primitives::TokenIssuance {
    fn try_convert_from(value: TokenIssuance) -> Result<Self, PrimitivesConvertersError> {
        match value {
            TokenIssuance::V1(data) => Ok(Self::V1(ml_primitives::TokenIssuanceV1 {
                token_ticker: data.token_ticker,
                number_of_decimals: data.number_of_decimals,
                metadata_uri: data.metadata_uri,
                total_supply: data.total_supply.try_convert_into()?,
                authority: data.authority.try_convert_into()?,
                is_freezable: data.is_freezable.try_convert_into()?,
            })),
        }
    }
}

impl TryConvertFrom<TxOutput> for ml_primitives::TxOutput {
    fn try_convert_from(value: TxOutput) -> Result<Self, PrimitivesConvertersError> {
        match value {
            TxOutput::Transfer(value, dest) => Ok(Self::Transfer(
                value.try_convert_into()?,
                dest.try_convert_into()?,
            )),
            TxOutput::LockThenTransfer(value, dest, lock) => Ok(Self::LockThenTransfer(
                value.try_convert_into()?,
                dest.try_convert_into()?,
                lock.try_convert_into()?,
            )),
            TxOutput::Burn(amount) => Ok(Self::Burn(amount.try_convert_into()?)),
            TxOutput::DataDeposit(data) => Ok(Self::DataDeposit(data)),
            TxOutput::CreateDelegationId(dest, pool_id) => Ok(Self::CreateDelegationId(
                dest.try_convert_into()?,
                pool_id.try_convert_into()?,
            )),
            TxOutput::DelegateStaking(amount, delegation_id) => Ok(Self::DelegateStaking(
                amount.try_convert_into()?,
                delegation_id.try_convert_into()?,
            )),
            TxOutput::ProduceBlockFromStake(dest, pool_id) => Ok(Self::ProduceBlockFromStake(
                dest.try_convert_into()?,
                pool_id.try_convert_into()?,
            )),
            TxOutput::Htlc(value, lock) => Ok(Self::Htlc(
                value.try_convert_into()?,
                (*lock).try_convert_into()?,
            )),
            TxOutput::CreateOrder(data) => Ok(Self::CreateOrder((*data).try_convert_into()?)),
            TxOutput::CreateStakePool(pool_id, data) => Ok(Self::CreateStakePool(
                pool_id.try_convert_into()?,
                (*data).try_convert_into()?,
            )),
            TxOutput::IssueNft(token_id, data, dest) => Ok(Self::IssueNft(
                token_id.try_convert_into()?,
                (*data).try_convert_into()?,
                dest.try_convert_into()?,
            )),
            TxOutput::IssueFungibleToken(data) => {
                Ok(Self::IssueFungibleToken((*data).try_convert_into()?))
            }
        }
    }
}

impl TryConvertFrom<SighashInputCommitment<'_>> for ml_primitives::SighashInputCommitment {
    fn try_convert_from(value: SighashInputCommitment) -> Result<Self, PrimitivesConvertersError> {
        type ChainComm<'a> = SighashInputCommitment<'a>;

        match value {
            ChainComm::None => Ok(ml_primitives::SighashInputCommitment::None),
            ChainComm::Utxo(utxo) => Ok(ml_primitives::SighashInputCommitment::Utxo(
                utxo.into_owned().try_convert_into()?,
            )),
            ChainComm::ProduceBlockFromStakeUtxo {
                utxo,
                staker_balance,
            } => Ok(
                ml_primitives::SighashInputCommitment::ProduceBlockFromStakeUtxo {
                    utxo: utxo.into_owned().try_convert_into()?,
                    staker_balance: staker_balance.try_convert_into()?,
                },
            ),
            ChainComm::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            } => Ok(
                ml_primitives::SighashInputCommitment::FillOrderAccountCommand {
                    initially_asked: initially_asked.try_convert_into()?,
                    initially_given: initially_given.try_convert_into()?,
                },
            ),
            ChainComm::ConcludeOrderAccountCommand {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            } => Ok(
                ml_primitives::SighashInputCommitment::ConcludeOrderAccountCommand {
                    initially_asked: initially_asked.try_convert_into()?,
                    initially_given: initially_given.try_convert_into()?,
                    ask_balance: ask_balance.try_convert_into()?,
                    give_balance: give_balance.try_convert_into()?,
                },
            ),
        }
    }
}

impl TryConvertFrom<Id<GenBlock>> for ml_primitives::GenBlockId {
    fn try_convert_from(value: Id<GenBlock>) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<Id<Transaction>> for ml_primitives::TransactionId {
    fn try_convert_from(value: Id<Transaction>) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<OrderId> for ml_primitives::OrderId {
    fn try_convert_from(value: OrderId) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<PoolId> for ml_primitives::PoolId {
    fn try_convert_from(value: PoolId) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<DelegationId> for ml_primitives::DelegationId {
    fn try_convert_from(value: DelegationId) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<TokenId> for ml_primitives::TokenId {
    fn try_convert_from(value: TokenId) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<Id<Script>> for ml_primitives::ScriptId {
    fn try_convert_from(value: Id<Script>) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self::new(value.to_hash().try_convert_into()?))
    }
}

impl TryConvertFrom<PerThousand> for ml_primitives::PerThousand {
    fn try_convert_from(value: PerThousand) -> Result<Self, PrimitivesConvertersError> {
        Ok(Self(value.value()))
    }
}
