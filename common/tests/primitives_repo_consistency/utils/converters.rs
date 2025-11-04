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

use common::{
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

// Custom "From" trait to work around the Rust's orphan rule.
pub trait ConvertFrom<T> {
    fn convert_from(value: T) -> Self;
}

// Custom "Into" trait to work around the Rust's orphan rule.
pub trait ConvertInto<T> {
    fn convert_into(self) -> T;
}

impl<From, To> ConvertInto<To> for From
where
    To: ConvertFrom<From>,
{
    fn convert_into(self) -> To {
        <To as ConvertFrom<From>>::convert_from(self)
    }
}

impl ConvertFrom<H256> for ml_primitives::H256 {
    fn convert_from(value: H256) -> Self {
        Self(value.0)
    }
}

impl ConvertFrom<AccountNonce> for ml_primitives::AccountNonce {
    fn convert_from(value: AccountNonce) -> Self {
        Self(value.value())
    }
}

impl ConvertFrom<OutPointSourceId> for ml_primitives::OutPointSourceId {
    fn convert_from(value: OutPointSourceId) -> Self {
        match value {
            OutPointSourceId::Transaction(tx_id) => Self::Transaction(tx_id.convert_into()),
            OutPointSourceId::BlockReward(block_id) => Self::BlockReward(block_id.convert_into()),
        }
    }
}

impl ConvertFrom<UtxoOutPoint> for ml_primitives::UtxoOutPoint {
    fn convert_from(value: UtxoOutPoint) -> Self {
        ml_primitives::UtxoOutPoint::new(value.source_id().convert_into(), value.output_index())
    }
}

impl ConvertFrom<Amount> for ml_primitives::Amount {
    fn convert_from(value: Amount) -> Self {
        Self::from_atoms(value.into_atoms())
    }
}

impl ConvertFrom<AccountSpending> for ml_primitives::AccountSpending {
    fn convert_from(value: AccountSpending) -> Self {
        match value {
            AccountSpending::DelegationBalance(delegation_id, amount) => {
                Self::DelegationBalance(delegation_id.convert_into(), amount.convert_into())
            }
        }
    }
}

impl ConvertFrom<AccountOutPoint> for ml_primitives::AccountOutPoint {
    fn convert_from(value: AccountOutPoint) -> Self {
        Self {
            nonce: ml_primitives::AccountNonce(value.nonce().value()),
            spending: value.account().clone().convert_into(),
        }
    }
}

impl ConvertFrom<IsTokenUnfreezable> for ml_primitives::IsTokenUnfreezable {
    fn convert_from(value: IsTokenUnfreezable) -> Self {
        match value {
            IsTokenUnfreezable::No => Self::No,
            IsTokenUnfreezable::Yes => Self::Yes,
        }
    }
}

impl ConvertFrom<PublicKey> for ml_primitives::PublicKey {
    fn convert_from(value: PublicKey) -> Self {
        match value.kind() {
            KeyKind::Secp256k1Schnorr => {
                let key: Secp256k1PublicKey = value.try_into().unwrap();
                ml_primitives::PublicKey::Secp256k1Schnorr(ml_primitives::Secp256k1PublicKey(
                    key.as_bytes(),
                ))
            }
        }
    }
}

impl ConvertFrom<PublicKeyHash> for ml_primitives::PublicKeyHash {
    fn convert_from(value: PublicKeyHash) -> Self {
        Self(value.0)
    }
}

impl ConvertFrom<Destination> for ml_primitives::Destination {
    fn convert_from(value: Destination) -> Self {
        match value {
            Destination::AnyoneCanSpend => Self::AnyoneCanSpend,
            Destination::PublicKey(pk) => Self::PublicKey(pk.convert_into()),
            Destination::ScriptHash(script_id) => Self::ScriptHash(script_id.convert_into()),
            Destination::PublicKeyHash(pkh) => Self::PublicKeyHash(pkh.convert_into()),
            Destination::ClassicMultisig(pkh) => Self::ClassicMultisig(pkh.convert_into()),
        }
    }
}

impl ConvertFrom<AccountCommand> for ml_primitives::AccountCommand {
    fn convert_from(value: AccountCommand) -> Self {
        match value {
            AccountCommand::MintTokens(token_id, amount) => {
                Self::MintTokens(token_id.convert_into(), amount.convert_into())
            }
            AccountCommand::UnmintTokens(token_id) => Self::UnmintTokens(token_id.convert_into()),
            AccountCommand::LockTokenSupply(token_id) => {
                Self::LockTokenSupply(token_id.convert_into())
            }
            AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                Self::FreezeToken(token_id.convert_into(), is_unfreezable.convert_into())
            }
            AccountCommand::UnfreezeToken(token_id) => Self::UnfreezeToken(token_id.convert_into()),
            AccountCommand::ChangeTokenAuthority(token_id, dest) => {
                Self::ChangeTokenAuthority(token_id.convert_into(), dest.convert_into())
            }
            AccountCommand::ConcludeOrder(order_id) => Self::ConcludeOrder(order_id.convert_into()),
            AccountCommand::FillOrder(order_id, amount, dest) => Self::FillOrder(
                order_id.convert_into(),
                amount.convert_into(),
                dest.convert_into(),
            ),
            AccountCommand::ChangeTokenMetadataUri(token_id, uri) => {
                Self::ChangeTokenMetadataUri(token_id.convert_into(), uri)
            }
        }
    }
}

impl ConvertFrom<OrderAccountCommand> for ml_primitives::OrderAccountCommand {
    fn convert_from(value: OrderAccountCommand) -> Self {
        match value {
            OrderAccountCommand::FillOrder(order_id, amount) => {
                Self::FillOrder(order_id.convert_into(), amount.convert_into())
            }
            OrderAccountCommand::FreezeOrder(order_id) => {
                Self::FreezeOrder(order_id.convert_into())
            }
            OrderAccountCommand::ConcludeOrder(order_id) => {
                Self::ConcludeOrder(order_id.convert_into())
            }
        }
    }
}

impl ConvertFrom<TxInput> for ml_primitives::TxInput {
    fn convert_from(value: TxInput) -> Self {
        match value {
            TxInput::Utxo(utxo) => Self::Utxo(utxo.convert_into()),
            TxInput::Account(acc) => Self::Account(acc.convert_into()),
            TxInput::AccountCommand(nonce, command) => Self::AccountCommand(
                ml_primitives::AccountNonce(nonce.value()),
                command.convert_into(),
            ),
            TxInput::OrderAccountCommand(command) => {
                Self::OrderAccountCommand(command.convert_into())
            }
        }
    }
}

impl ConvertFrom<OutputValue> for ml_primitives::OutputValue {
    fn convert_from(value: OutputValue) -> Self {
        match value {
            OutputValue::Coin(amount) => Self::Coin(amount.convert_into()),
            OutputValue::TokenV0(_) => panic!("Makers are not supposed to create V0 tokens"),
            OutputValue::TokenV1(token_id, amount) => {
                Self::TokenV1(token_id.convert_into(), amount.convert_into())
            }
        }
    }
}

impl ConvertFrom<OutputTimeLock> for ml_primitives::OutputTimeLock {
    fn convert_from(value: OutputTimeLock) -> Self {
        match value {
            OutputTimeLock::UntilHeight(height) => {
                Self::UntilHeight(ml_primitives::BlockHeight(height.into_int()))
            }
            OutputTimeLock::UntilTime(time) => Self::UntilTime(ml_primitives::BlockTimestamp(
                ml_primitives::SecondsCount(time.as_int_seconds()),
            )),
            OutputTimeLock::ForSeconds(secs) => Self::ForSeconds(ml_primitives::SecondsCount(secs)),
            OutputTimeLock::ForBlockCount(blocks) => {
                Self::ForBlockCount(ml_primitives::BlocksCount(blocks))
            }
        }
    }
}

impl ConvertFrom<HashedTimelockContract> for ml_primitives::HashedTimelockContract {
    fn convert_from(value: HashedTimelockContract) -> Self {
        Self {
            secret_hash: ml_primitives::HtlcSecretHash(value.secret_hash.0),
            spend_key: value.spend_key.convert_into(),
            refund_timelock: value.refund_timelock.convert_into(),
            refund_key: value.refund_key.convert_into(),
        }
    }
}

impl ConvertFrom<OrderData> for ml_primitives::OrderData {
    fn convert_from(value: OrderData) -> Self {
        Self {
            conclude_key: value.conclude_key().clone().convert_into(),
            ask: value.ask().clone().convert_into(),
            give: value.give().clone().convert_into(),
        }
    }
}

impl ConvertFrom<VRFPublicKey> for ml_primitives::VrfPublicKey {
    fn convert_from(value: VRFPublicKey) -> Self {
        match value.kind() {
            VRFKeyKind::Schnorrkel => {
                let key: SchnorrkelPublicKey = value.try_into().unwrap();

                ml_primitives::VrfPublicKey::Schnorrkel(ml_primitives::SchnorrkelPublicKey(
                    key.as_bytes(),
                ))
            }
        }
    }
}

impl ConvertFrom<StakePoolData> for ml_primitives::StakePoolData {
    fn convert_from(value: StakePoolData) -> Self {
        Self {
            pledge: value.pledge().convert_into(),
            staker: value.staker().clone().convert_into(),
            vrf_public_key: value.vrf_public_key().clone().convert_into(),
            decommission_key: value.decommission_key().clone().convert_into(),
            margin_ratio_per_thousand: ml_primitives::PerThousand(
                value.margin_ratio_per_thousand().value(),
            ),
            cost_per_block: value.cost_per_block().convert_into(),
        }
    }
}

impl ConvertFrom<NftIssuance> for ml_primitives::NftIssuance {
    fn convert_from(value: NftIssuance) -> Self {
        match value {
            NftIssuance::V0(data) => Self::V0(ml_primitives::NftIssuanceV0 {
                creator: data.metadata.creator.map(|c| c.public_key.convert_into()),
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
            }),
        }
    }
}

impl ConvertFrom<TokenTotalSupply> for ml_primitives::TokenTotalSupply {
    fn convert_from(value: TokenTotalSupply) -> Self {
        match value {
            TokenTotalSupply::Lockable => Self::Lockable,
            TokenTotalSupply::Unlimited => Self::Unlimited,
            TokenTotalSupply::Fixed(amount) => Self::Fixed(amount.convert_into()),
        }
    }
}

impl ConvertFrom<IsTokenFreezable> for ml_primitives::IsTokenFreezable {
    fn convert_from(value: IsTokenFreezable) -> Self {
        match value {
            IsTokenFreezable::No => Self::No,
            IsTokenFreezable::Yes => Self::Yes,
        }
    }
}

impl ConvertFrom<TokenIssuance> for ml_primitives::TokenIssuance {
    fn convert_from(value: TokenIssuance) -> Self {
        match value {
            TokenIssuance::V1(data) => Self::V1(ml_primitives::TokenIssuanceV1 {
                token_ticker: data.token_ticker,
                number_of_decimals: data.number_of_decimals,
                metadata_uri: data.metadata_uri,
                total_supply: data.total_supply.convert_into(),
                authority: data.authority.convert_into(),
                is_freezable: data.is_freezable.convert_into(),
            }),
        }
    }
}

impl ConvertFrom<TxOutput> for ml_primitives::TxOutput {
    fn convert_from(value: TxOutput) -> Self {
        match value {
            TxOutput::Transfer(value, dest) => {
                Self::Transfer(value.convert_into(), dest.convert_into())
            }
            TxOutput::LockThenTransfer(value, dest, lock) => Self::LockThenTransfer(
                value.convert_into(),
                dest.convert_into(),
                lock.convert_into(),
            ),
            TxOutput::Burn(amount) => Self::Burn(amount.convert_into()),
            TxOutput::DataDeposit(data) => Self::DataDeposit(data),
            TxOutput::CreateDelegationId(dest, pool_id) => {
                Self::CreateDelegationId(dest.convert_into(), pool_id.convert_into())
            }
            TxOutput::DelegateStaking(amount, delegation_id) => {
                Self::DelegateStaking(amount.convert_into(), delegation_id.convert_into())
            }
            TxOutput::ProduceBlockFromStake(dest, pool_id) => {
                Self::ProduceBlockFromStake(dest.convert_into(), pool_id.convert_into())
            }
            TxOutput::Htlc(value, lock) => Self::Htlc(value.convert_into(), (*lock).convert_into()),
            TxOutput::CreateOrder(data) => Self::CreateOrder((*data).convert_into()),
            TxOutput::CreateStakePool(pool_id, data) => {
                Self::CreateStakePool(pool_id.convert_into(), (*data).convert_into())
            }
            TxOutput::IssueNft(token_id, data, dest) => Self::IssueNft(
                token_id.convert_into(),
                (*data).convert_into(),
                dest.convert_into(),
            ),
            TxOutput::IssueFungibleToken(data) => Self::IssueFungibleToken((*data).convert_into()),
        }
    }
}

impl ConvertFrom<SighashInputCommitment<'_>> for ml_primitives::SighashInputCommitment {
    fn convert_from(value: SighashInputCommitment) -> Self {
        type ChainComm<'a> = SighashInputCommitment<'a>;

        match value {
            ChainComm::None => ml_primitives::SighashInputCommitment::None,
            ChainComm::Utxo(utxo) => {
                ml_primitives::SighashInputCommitment::Utxo(utxo.into_owned().convert_into())
            }
            ChainComm::ProduceBlockFromStakeUtxo {
                utxo,
                staker_balance,
            } => ml_primitives::SighashInputCommitment::ProduceBlockFromStakeUtxo {
                utxo: utxo.into_owned().convert_into(),
                staker_balance: staker_balance.convert_into(),
            },
            ChainComm::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            } => ml_primitives::SighashInputCommitment::FillOrderAccountCommand {
                initially_asked: initially_asked.convert_into(),
                initially_given: initially_given.convert_into(),
            },
            ChainComm::ConcludeOrderAccountCommand {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            } => ml_primitives::SighashInputCommitment::ConcludeOrderAccountCommand {
                initially_asked: initially_asked.convert_into(),
                initially_given: initially_given.convert_into(),
                ask_balance: ask_balance.convert_into(),
                give_balance: give_balance.convert_into(),
            },
        }
    }
}

impl ConvertFrom<Id<GenBlock>> for ml_primitives::GenBlockId {
    fn convert_from(value: Id<GenBlock>) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<Id<Transaction>> for ml_primitives::TransactionId {
    fn convert_from(value: Id<Transaction>) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<OrderId> for ml_primitives::OrderId {
    fn convert_from(value: OrderId) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<PoolId> for ml_primitives::PoolId {
    fn convert_from(value: PoolId) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<DelegationId> for ml_primitives::DelegationId {
    fn convert_from(value: DelegationId) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<TokenId> for ml_primitives::TokenId {
    fn convert_from(value: TokenId) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<Id<Script>> for ml_primitives::ScriptId {
    fn convert_from(value: Id<Script>) -> Self {
        Self::new(value.to_hash().convert_into())
    }
}

impl ConvertFrom<PerThousand> for ml_primitives::PerThousand {
    fn convert_from(value: PerThousand) -> Self {
        Self(value.value())
    }
}
