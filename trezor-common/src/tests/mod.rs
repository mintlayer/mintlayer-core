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

use std::{borrow::Cow, boxed::Box, println, vec::Vec};

use num_traits::FromPrimitive as _;
use rstest::rstest;
use strum::IntoEnumIterator;

use common::{
    chain::{self},
    primitives,
};
use crypto::key::KeyKind;
use parity_scale_codec::{DecodeAll, Encode};

use test_utils::random::{make_seedable_rng, CryptoRng, IteratorRandom, Rng, Seed};

use crate::IsTokenFreezable;

impl From<primitives::H256> for crate::H256 {
    fn from(value: primitives::H256) -> Self {
        Self(value.0)
    }
}

impl From<chain::OutPointSourceId> for crate::OutPointSourceId {
    fn from(value: chain::OutPointSourceId) -> Self {
        match value {
            chain::OutPointSourceId::Transaction(tx) => Self::Transaction(tx.to_hash().into()),
            chain::OutPointSourceId::BlockReward(tx) => Self::BlockReward(tx.to_hash().into()),
        }
    }
}

impl From<chain::UtxoOutPoint> for crate::UtxoOutPoint {
    fn from(value: chain::UtxoOutPoint) -> Self {
        Self {
            id: value.source_id().into(),
            index: value.output_index(),
        }
    }
}

impl From<primitives::Amount> for crate::Amount {
    fn from(value: primitives::Amount) -> Self {
        Self::from_atoms(value.into_atoms())
    }
}

impl From<chain::AccountSpending> for crate::AccountSpending {
    fn from(value: chain::AccountSpending) -> Self {
        match value {
            chain::AccountSpending::DelegationBalance(delegation_id, amount) => {
                Self::DelegationBalance(delegation_id.to_hash().into(), amount.into())
            }
        }
    }
}

impl From<chain::AccountOutPoint> for crate::AccountOutPoint {
    fn from(value: chain::AccountOutPoint) -> Self {
        Self {
            nonce: value.nonce().value(),
            account: value.account().clone().into(),
        }
    }
}

impl From<chain::tokens::IsTokenUnfreezable> for crate::IsTokenUnfreezable {
    fn from(value: chain::tokens::IsTokenUnfreezable) -> Self {
        match value {
            chain::tokens::IsTokenUnfreezable::No => Self::No,
            chain::tokens::IsTokenUnfreezable::Yes => Self::Yes,
        }
    }
}

impl From<crypto::key::PublicKey> for crate::PublicKeyHolder {
    fn from(value: crypto::key::PublicKey) -> Self {
        crate::PublicKeyHolder::decode_all(&mut value.encode().as_slice()).unwrap()
    }
}

impl From<common::address::pubkeyhash::PublicKeyHash> for crate::PublicKeyHash {
    fn from(value: common::address::pubkeyhash::PublicKeyHash) -> Self {
        Self(value.0)
    }
}

impl From<common::chain::Destination> for crate::Destination {
    fn from(value: common::chain::Destination) -> Self {
        match value {
            chain::Destination::AnyoneCanSpend => Self::AnyoneCanSpend,
            chain::Destination::PublicKey(pk) => Self::PublicKey(pk.into()),
            chain::Destination::ScriptHash(id) => Self::ScriptHash(id.to_hash().into()),
            chain::Destination::PublicKeyHash(pkh) => Self::PublicKeyHash(pkh.into()),
            chain::Destination::ClassicMultisig(pkh) => Self::ClassicMultisig(pkh.into()),
        }
    }
}

impl From<chain::AccountCommand> for crate::AccountCommand {
    fn from(value: chain::AccountCommand) -> Self {
        match value {
            chain::AccountCommand::MintTokens(token_id, amount) => {
                Self::MintTokens(token_id.to_hash().into(), amount.into())
            }
            chain::AccountCommand::UnmintTokens(token_id) => {
                Self::UnmintTokens(token_id.to_hash().into())
            }
            chain::AccountCommand::LockTokenSupply(token_id) => {
                Self::LockTokenSupply(token_id.to_hash().into())
            }
            chain::AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                Self::FreezeToken(token_id.to_hash().into(), is_unfreezable.into())
            }
            chain::AccountCommand::UnfreezeToken(token_id) => {
                Self::UnfreezeToken(token_id.to_hash().into())
            }
            chain::AccountCommand::ChangeTokenAuthority(token_id, dest) => {
                Self::ChangeTokenAuthority(token_id.to_hash().into(), dest.into())
            }
            chain::AccountCommand::ConcludeOrder(order_id) => {
                Self::ConcludeOrder(order_id.to_hash().into())
            }
            chain::AccountCommand::FillOrder(order_id, amount, dest) => {
                Self::FillOrder(order_id.to_hash().into(), amount.into(), dest.into())
            }
            chain::AccountCommand::ChangeTokenMetadataUri(token_id, uri) => {
                Self::ChangeTokenMetadataUri(token_id.to_hash().into(), uri)
            }
        }
    }
}

impl From<chain::OrderAccountCommand> for crate::OrderAccountCommand {
    fn from(value: chain::OrderAccountCommand) -> Self {
        match value {
            chain::OrderAccountCommand::FillOrder(order_id, amount) => {
                Self::FillOrder(order_id.to_hash().into(), amount.into())
            }
            chain::OrderAccountCommand::FreezeOrder(order_id) => {
                Self::FreezeOrder(order_id.to_hash().into())
            }
            chain::OrderAccountCommand::ConcludeOrder(order_id) => {
                Self::ConcludeOrder(order_id.to_hash().into())
            }
        }
    }
}

impl From<chain::TxInput> for crate::TxInput {
    fn from(value: chain::TxInput) -> Self {
        match value {
            chain::TxInput::Utxo(utxo) => Self::Utxo(utxo.into()),
            chain::TxInput::Account(acc) => Self::Account(acc.into()),
            chain::TxInput::AccountCommand(nonce, command) => {
                Self::AccountCommand(nonce.value(), command.into())
            }
            chain::TxInput::OrderAccountCommand(command) => {
                Self::OrderAccountCommand(command.into())
            }
        }
    }
}

impl From<chain::output_value::OutputValue> for crate::OutputValue {
    fn from(value: chain::output_value::OutputValue) -> Self {
        match value {
            chain::output_value::OutputValue::Coin(amount) => Self::Coin(amount.into()),
            chain::output_value::OutputValue::TokenV0(_) => panic!("unsupported V0"),
            chain::output_value::OutputValue::TokenV1(token_id, amount) => {
                Self::TokenV1(token_id.to_hash().into(), amount.into())
            }
        }
    }
}

impl From<chain::timelock::OutputTimeLock> for crate::OutputTimeLock {
    fn from(value: chain::timelock::OutputTimeLock) -> Self {
        match value {
            chain::timelock::OutputTimeLock::UntilHeight(x) => Self::UntilHeight(x.into_int()),
            chain::timelock::OutputTimeLock::UntilTime(x) => Self::UntilTime(x.as_int_seconds()),
            chain::timelock::OutputTimeLock::ForSeconds(x) => Self::ForSeconds(x),
            chain::timelock::OutputTimeLock::ForBlockCount(x) => Self::ForBlockCount(x),
        }
    }
}

impl From<chain::htlc::HashedTimelockContract> for crate::HashedTimelockContract {
    fn from(value: chain::htlc::HashedTimelockContract) -> Self {
        Self {
            secret_hash: crate::HtlcSecretHash(value.secret_hash.0),
            spend_key: value.spend_key.into(),
            refund_timelock: value.refund_timelock.into(),
            refund_key: value.refund_key.into(),
        }
    }
}

impl From<chain::OrderData> for crate::OrderData {
    fn from(value: chain::OrderData) -> Self {
        Self {
            conclude_key: value.conclude_key().clone().into(),
            ask: value.ask().clone().into(),
            give: value.give().clone().into(),
        }
    }
}

impl From<&crypto::vrf::VRFPublicKey> for crate::VRFPublicKeyHolder {
    fn from(value: &crypto::vrf::VRFPublicKey) -> Self {
        Self::decode_all(&mut value.encode().as_slice()).unwrap()
    }
}

impl From<chain::stakelock::StakePoolData> for crate::StakePoolData {
    fn from(value: chain::stakelock::StakePoolData) -> Self {
        Self {
            pledge: value.pledge().into(),
            staker: value.staker().clone().into(),
            vrf_public_key: value.vrf_public_key().into(),
            decommission_key: value.decommission_key().clone().into(),
            margin_ratio_per_thousand: value.margin_ratio_per_thousand().value(),
            cost_per_block: value.cost_per_block().into(),
        }
    }
}

impl From<chain::tokens::NftIssuance> for crate::NftIssuance {
    fn from(value: chain::tokens::NftIssuance) -> Self {
        match value {
            chain::tokens::NftIssuance::V0(data) => Self::V0(crate::NftIssuanceV0 {
                metadata: crate::Metadata {
                    creator: data.metadata.creator.map(|c| c.public_key.into()),
                    name: data.metadata.name,
                    description: data.metadata.description,
                    ticker: data.metadata.ticker,
                    icon_uri: data
                        .metadata
                        .icon_uri
                        .as_ref()
                        .clone()
                        .map_or(Vec::new(), Into::into),
                    additional_metadata_uri: data
                        .metadata
                        .additional_metadata_uri
                        .as_ref()
                        .clone()
                        .map_or(Vec::new(), Into::into),
                    media_uri: data
                        .metadata
                        .media_uri
                        .as_ref()
                        .clone()
                        .map_or(Vec::new(), Into::into),
                    media_hash: data.metadata.media_hash,
                },
            }),
        }
    }
}

impl From<chain::tokens::TokenTotalSupply> for crate::TokenTotalSupply {
    fn from(value: chain::tokens::TokenTotalSupply) -> Self {
        match value {
            chain::tokens::TokenTotalSupply::Lockable => Self::Lockable,
            chain::tokens::TokenTotalSupply::Unlimited => Self::Unlimited,
            chain::tokens::TokenTotalSupply::Fixed(amount) => Self::Fixed(amount.into()),
        }
    }
}

impl From<chain::tokens::IsTokenFreezable> for crate::IsTokenFreezable {
    fn from(value: chain::tokens::IsTokenFreezable) -> Self {
        match value {
            chain::tokens::IsTokenFreezable::No => Self::No,
            chain::tokens::IsTokenFreezable::Yes => Self::Yes,
        }
    }
}

impl From<chain::tokens::TokenIssuance> for crate::TokenIssuance {
    fn from(value: chain::tokens::TokenIssuance) -> Self {
        match value {
            chain::tokens::TokenIssuance::V1(data) => Self::V1(crate::TokenIssuanceV1 {
                token_ticker: data.token_ticker,
                number_of_decimals: data.number_of_decimals,
                metadata_uri: data.metadata_uri,
                total_supply: data.total_supply.into(),
                authority: data.authority.into(),
                is_freezable: data.is_freezable.into(),
            }),
        }
    }
}

impl From<chain::TxOutput> for crate::TxOutput {
    fn from(value: chain::TxOutput) -> Self {
        match value {
            chain::TxOutput::Transfer(value, dest) => Self::Transfer(value.into(), dest.into()),
            chain::TxOutput::LockThenTransfer(value, dest, lock) => {
                Self::LockThenTransfer(value.into(), dest.into(), lock.into())
            }
            chain::TxOutput::Burn(amount) => Self::Burn(amount.into()),
            chain::TxOutput::DataDeposit(data) => Self::DataDeposit(data),
            chain::TxOutput::CreateDelegationId(dest, pool_id) => {
                Self::CreateDelegationId(dest.into(), pool_id.to_hash().into())
            }
            chain::TxOutput::DelegateStaking(amount, delegation_id) => {
                Self::DelegateStaking(amount.into(), delegation_id.to_hash().into())
            }
            chain::TxOutput::ProduceBlockFromStake(dest, pool_id) => {
                Self::ProduceBlockFromStake(dest.into(), pool_id.to_hash().into())
            }
            chain::TxOutput::Htlc(value, lock) => Self::Htlc(value.into(), (*lock).into()),
            chain::TxOutput::CreateOrder(data) => Self::CreateOrder((*data).into()),
            chain::TxOutput::CreateStakePool(pool_id, data) => {
                Self::CreateStakePool(pool_id.to_hash().into(), (*data).into())
            }
            chain::TxOutput::IssueNft(token_id, data, dest) => {
                Self::IssueNft(token_id.to_hash().into(), (*data).into(), dest.into())
            }
            chain::TxOutput::IssueFungibleToken(data) => Self::IssueFungibleToken((*data).into()),
        }
    }
}

impl From<chain::signature::sighash::input_commitments::SighashInputCommitment<'_>>
    for crate::SighashInputCommitment
{
    fn from(value: chain::signature::sighash::input_commitments::SighashInputCommitment) -> Self {
        type ChainComm<'a> =
            chain::signature::sighash::input_commitments::SighashInputCommitment<'a>;

        match value {
            ChainComm::None => crate::SighashInputCommitment::None,
            ChainComm::Utxo(utxo) => crate::SighashInputCommitment::Utxo(utxo.into_owned().into()),
            ChainComm::ProduceBlockFromStakeUtxo {
                utxo,
                staker_balance,
            } => crate::SighashInputCommitment::ProduceBlockFromStakeUtxo {
                utxo: utxo.into_owned().into(),
                staker_balance: staker_balance.into(),
            },
            ChainComm::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            } => crate::SighashInputCommitment::FillOrderAccountCommand {
                initially_asked: initially_asked.into(),
                initially_given: initially_given.into(),
            },
            ChainComm::ConcludeOrderAccountCommand {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            } => crate::SighashInputCommitment::ConcludeOrderAccountCommand {
                initially_asked: initially_asked.into(),
                initially_given: initially_given.into(),
                ask_balance: ask_balance.into(),
                give_balance: give_balance.into(),
            },
        }
    }
}

fn make_random_destination(rng: &mut (impl Rng + CryptoRng)) -> chain::Destination {
    match chain::DestinationTag::iter().choose(rng).unwrap() {
        chain::DestinationTag::AnyoneCanSpend => chain::Destination::AnyoneCanSpend,
        chain::DestinationTag::PublicKey => chain::Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1,
        ),
        chain::DestinationTag::ScriptHash => {
            chain::Destination::ScriptHash(primitives::H256(rng.gen()).into())
        }
        chain::DestinationTag::ClassicMultisig => chain::Destination::ClassicMultisig(
            (&crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1).into(),
        ),
        chain::DestinationTag::PublicKeyHash => chain::Destination::PublicKeyHash(
            (&crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1).into(),
        ),
    }
}

fn make_random_bytes(rng: &mut (impl Rng + CryptoRng)) -> Vec<u8> {
    (0..rng.gen_range(1..10)).map(|_| rng.gen()).collect()
}

fn make_random_account_command(rng: &mut (impl Rng + CryptoRng)) -> chain::AccountCommand {
    match crate::AccountCommandTag::iter().choose(rng).unwrap() {
        crate::AccountCommandTag::MintTokens => chain::AccountCommand::MintTokens(
            primitives::H256(rng.gen()).into(),
            primitives::Amount::from_atoms(rng.gen()),
        ),
        crate::AccountCommandTag::UnmintTokens => {
            chain::AccountCommand::UnmintTokens(primitives::H256(rng.gen()).into())
        }
        crate::AccountCommandTag::LockTokenSupply => {
            chain::AccountCommand::LockTokenSupply(primitives::H256(rng.gen()).into())
        }
        crate::AccountCommandTag::FreezeToken => chain::AccountCommand::FreezeToken(
            primitives::H256(rng.gen()).into(),
            if rng.gen::<bool>() {
                chain::tokens::IsTokenUnfreezable::Yes
            } else {
                chain::tokens::IsTokenUnfreezable::No
            },
        ),
        crate::AccountCommandTag::UnfreezeToken => {
            chain::AccountCommand::UnfreezeToken(primitives::H256(rng.gen()).into())
        }
        crate::AccountCommandTag::ChangeTokenAuthority => {
            chain::AccountCommand::ChangeTokenAuthority(
                primitives::H256(rng.gen()).into(),
                make_random_destination(rng),
            )
        }
        crate::AccountCommandTag::ConcludeOrder => {
            chain::AccountCommand::ConcludeOrder(primitives::H256(rng.gen()).into())
        }
        crate::AccountCommandTag::FillOrder => chain::AccountCommand::FillOrder(
            primitives::H256(rng.gen()).into(),
            primitives::Amount::from_atoms(rng.gen()),
            make_random_destination(rng),
        ),
        crate::AccountCommandTag::ChangeTokenMetadataUri => {
            chain::AccountCommand::ChangeTokenMetadataUri(
                primitives::H256(rng.gen()).into(),
                make_random_bytes(rng),
            )
        }
    }
}

fn make_random_input(rng: &mut (impl Rng + CryptoRng)) -> chain::TxInput {
    match rng.gen_range(0..=2) {
        0 => chain::TxInput::Utxo(chain::UtxoOutPoint::new(
            chain::OutPointSourceId::Transaction(primitives::H256(rng.gen()).into()),
            rng.gen(),
        )),
        1 => chain::TxInput::Account(chain::AccountOutPoint::new(
            chain::AccountNonce::new(rng.gen()),
            chain::AccountSpending::DelegationBalance(
                primitives::H256(rng.gen()).into(),
                primitives::Amount::from_atoms(rng.gen()),
            ),
        )),
        _ => chain::TxInput::AccountCommand(
            chain::AccountNonce::new(rng.gen()),
            make_random_account_command(rng),
        ),
    }
}

fn make_random_value(rng: &mut (impl Rng + CryptoRng)) -> chain::output_value::OutputValue {
    if rng.gen::<bool>() {
        chain::output_value::OutputValue::Coin(primitives::Amount::from_atoms(rng.gen()))
    } else {
        chain::output_value::OutputValue::TokenV1(
            primitives::H256(rng.gen()).into(),
            primitives::Amount::from_atoms(rng.gen()),
        )
    }
}

fn make_random_lock(rng: &mut (impl Rng + CryptoRng)) -> chain::timelock::OutputTimeLock {
    match crate::OutputTimeLockTag::iter().choose(rng).unwrap() {
        crate::OutputTimeLockTag::UntilHeight => {
            chain::timelock::OutputTimeLock::UntilHeight(primitives::BlockHeight::new(rng.gen()))
        }
        crate::OutputTimeLockTag::UntilTime => chain::timelock::OutputTimeLock::UntilTime(
            chain::block::timestamp::BlockTimestamp::from_int_seconds(rng.gen()),
        ),
        crate::OutputTimeLockTag::ForSeconds => {
            chain::timelock::OutputTimeLock::ForSeconds(rng.gen())
        }
        crate::OutputTimeLockTag::ForBlockCount => {
            chain::timelock::OutputTimeLock::ForBlockCount(rng.gen())
        }
    }
}

fn make_random_token_total_supply(
    rng: &mut (impl Rng + CryptoRng),
) -> chain::tokens::TokenTotalSupply {
    match crate::TokenTotalSupplyTag::iter().choose(rng).unwrap() {
        crate::TokenTotalSupplyTag::Unlimited => chain::tokens::TokenTotalSupply::Unlimited,
        crate::TokenTotalSupplyTag::Lockable => chain::tokens::TokenTotalSupply::Lockable,
        crate::TokenTotalSupplyTag::Fixed => {
            chain::tokens::TokenTotalSupply::Fixed(primitives::Amount::from_atoms(rng.gen()))
        }
    }
}

fn make_random_output(rng: &mut (impl Rng + CryptoRng)) -> chain::TxOutput {
    match chain::TxOutputTag::iter().choose(rng).unwrap() {
        chain::TxOutputTag::Transfer => {
            chain::TxOutput::Transfer(make_random_value(rng), make_random_destination(rng))
        }
        chain::TxOutputTag::LockThenTransfer => chain::TxOutput::LockThenTransfer(
            make_random_value(rng),
            make_random_destination(rng),
            make_random_lock(rng),
        ),
        chain::TxOutputTag::Burn => chain::TxOutput::Burn(make_random_value(rng)),
        chain::TxOutputTag::CreateStakePool => chain::TxOutput::CreateStakePool(
            primitives::H256(rng.gen()).into(),
            Box::new(chain::stakelock::StakePoolData::new(
                primitives::Amount::from_atoms(rng.gen()),
                make_random_destination(rng),
                crypto::vrf::VRFPrivateKey::new_from_rng(rng, crypto::vrf::VRFKeyKind::Schnorrkel)
                    .1,
                make_random_destination(rng),
                primitives::per_thousand::PerThousand::new_from_rng(rng),
                primitives::Amount::from_atoms(rng.gen()),
            )),
        ),
        chain::TxOutputTag::ProduceBlockFromStake => chain::TxOutput::ProduceBlockFromStake(
            make_random_destination(rng),
            primitives::H256(rng.gen()).into(),
        ),
        chain::TxOutputTag::CreateDelegationId => chain::TxOutput::CreateDelegationId(
            make_random_destination(rng),
            primitives::H256(rng.gen()).into(),
        ),
        chain::TxOutputTag::DelegateStaking => chain::TxOutput::DelegateStaking(
            primitives::Amount::from_atoms(rng.gen()),
            primitives::H256(rng.gen()).into(),
        ),
        chain::TxOutputTag::IssueFungibleToken => chain::TxOutput::IssueFungibleToken(Box::new(
            chain::tokens::TokenIssuance::V1(chain::tokens::TokenIssuanceV1 {
                token_ticker: make_random_bytes(rng),
                number_of_decimals: rng.gen(),
                metadata_uri: make_random_bytes(rng),
                total_supply: make_random_token_total_supply(rng),
                authority: make_random_destination(rng),
                is_freezable: if rng.gen::<bool>() {
                    chain::tokens::IsTokenFreezable::Yes
                } else {
                    chain::tokens::IsTokenFreezable::No
                },
            }),
        )),
        chain::TxOutputTag::IssueNft => chain::TxOutput::IssueNft(
            primitives::H256(rng.gen()).into(),
            Box::new(chain::tokens::NftIssuance::V0(
                chain::tokens::NftIssuanceV0 {
                    metadata: chain::tokens::Metadata {
                        creator: if rng.gen::<bool>() {
                            Some(chain::tokens::TokenCreator {
                                public_key: crypto::key::PrivateKey::new_from_rng(
                                    rng,
                                    KeyKind::Secp256k1Schnorr,
                                )
                                .1,
                            })
                        } else {
                            None
                        },
                        name: make_random_bytes(rng),
                        description: make_random_bytes(rng),
                        ticker: make_random_bytes(rng),
                        icon_uri: if rng.gen::<bool>() {
                            Some(make_random_bytes(rng)).into()
                        } else {
                            None.into()
                        },
                        additional_metadata_uri: if rng.gen::<bool>() {
                            Some(make_random_bytes(rng)).into()
                        } else {
                            None.into()
                        },
                        media_uri: if rng.gen::<bool>() {
                            Some(make_random_bytes(rng)).into()
                        } else {
                            None.into()
                        },
                        media_hash: make_random_bytes(rng),
                    },
                },
            )),
            make_random_destination(rng),
        ),
        chain::TxOutputTag::DataDeposit => chain::TxOutput::DataDeposit(make_random_bytes(rng)),
        chain::TxOutputTag::Htlc => chain::TxOutput::Htlc(
            make_random_value(rng),
            Box::new(chain::htlc::HashedTimelockContract {
                secret_hash: chain::htlc::HtlcSecretHash(rng.gen()),
                spend_key: make_random_destination(rng),
                refund_timelock: make_random_lock(rng),
                refund_key: make_random_destination(rng),
            }),
        ),
        chain::TxOutputTag::CreateOrder => {
            chain::TxOutput::CreateOrder(Box::new(chain::OrderData::new(
                make_random_destination(rng),
                make_random_value(rng),
                make_random_value(rng),
            )))
        }
    }
}

fn make_random_input_commitment_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: chain::signature::sighash::input_commitments::SighashInputCommitmentTag,
) -> chain::signature::sighash::input_commitments::SighashInputCommitment<'static> {
    type ChainCommTag = chain::signature::sighash::input_commitments::SighashInputCommitmentTag;
    type ChainComm = chain::signature::sighash::input_commitments::SighashInputCommitment<'static>;

    match tag {
        ChainCommTag::None => ChainComm::None,
        ChainCommTag::Utxo => ChainComm::Utxo(Cow::Owned(make_random_output(rng))),
        ChainCommTag::ProduceBlockFromStakeUtxo => ChainComm::ProduceBlockFromStakeUtxo {
            utxo: Cow::Owned(make_random_output(rng)),
            staker_balance: primitives::Amount::from_atoms(rng.gen()),
        },
        ChainCommTag::FillOrderAccountCommand => ChainComm::FillOrderAccountCommand {
            initially_asked: make_random_value(rng),
            initially_given: make_random_value(rng),
        },
        ChainCommTag::ConcludeOrderAccountCommand => ChainComm::ConcludeOrderAccountCommand {
            initially_asked: make_random_value(rng),
            initially_given: make_random_value(rng),
            ask_balance: primitives::Amount::from_atoms(rng.gen()),
            give_balance: primitives::Amount::from_atoms(rng.gen()),
        },
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_input_encodings(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..1000 {
        let inp = make_random_input(&mut rng);

        let simple_inp: crate::TxInput = inp.clone().into();

        assert_eq!(inp.encode(), simple_inp.encode());

        let decoded_simple_inp =
            chain::TxInput::decode_all(&mut simple_inp.encode().as_slice()).unwrap();
        assert_eq!(decoded_simple_inp, inp);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_output_encodings(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..1000 {
        let out = make_random_output(&mut rng);

        let simple_out: crate::TxOutput = out.clone().into();

        assert_eq!(out.encode(), simple_out.encode());

        let decoded_simple_out =
            chain::TxOutput::decode_all(&mut simple_out.encode().as_slice()).unwrap();
        assert_eq!(decoded_simple_out, out);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_input_commitment_encodings(#[case] seed: Seed) {
    type Tag = chain::signature::sighash::input_commitments::SighashInputCommitmentTag;

    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in Tag::iter() {
            let chain_commitment = make_random_input_commitment_for_tag(&mut rng, tag);
            let crate_commitment: crate::SighashInputCommitment = chain_commitment.clone().into();

            assert_eq!(chain_commitment.encode(), crate_commitment.encode());
        }
    }
}

#[test]
fn check_total_supply_tag_values() {
    for tag in crate::TokenTotalSupplyTag::iter() {
        match tag {
            crate::TokenTotalSupplyTag::Fixed => {
                assert_eq!(
                    crate::TokenTotalSupplyTag::from_u32(
                        trezor_client::protos::MintlayerTokenTotalSupplyType::FIXED as u32
                    ),
                    Some(tag)
                );
            }
            crate::TokenTotalSupplyTag::Lockable => {
                assert_eq!(
                    crate::TokenTotalSupplyTag::from_u32(
                        trezor_client::protos::MintlayerTokenTotalSupplyType::LOCKABLE as u32
                    ),
                    Some(tag)
                );
            }
            crate::TokenTotalSupplyTag::Unlimited => {
                assert_eq!(
                    crate::TokenTotalSupplyTag::from_u32(
                        trezor_client::protos::MintlayerTokenTotalSupplyType::UNLIMITED as u32
                    ),
                    Some(tag)
                );
            }
        }
    }
}

#[test]
fn check_account_command_tag_values() {
    for tag in crate::AccountCommandTag::iter() {
        match tag {
            crate::AccountCommandTag::MintTokens => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::MINT_TOKENS as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::UnmintTokens => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::UNMINT_TOKENS as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::FreezeToken => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::FREEZE_TOKEN as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::UnfreezeToken => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::UNFREEZE_TOKEN as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::FillOrder => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::FILL_ORDER as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::ConcludeOrder => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::CONCLUDE_ORDER as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::ChangeTokenAuthority => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::CHANGE_TOKEN_AUTHORITY
                            as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::ChangeTokenMetadataUri => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::CHANGE_TOKEN_METADATA_URI
                            as u32
                    ),
                    Some(tag)
                );
            }
            crate::AccountCommandTag::LockTokenSupply => {
                assert_eq!(
                    crate::AccountCommandTag::from_u32(
                        trezor_client::protos::MintlayerAccountCommandType::LOCK_TOKEN_SUPPLY
                            as u32
                    ),
                    Some(tag)
                );
            }
        }
    }
}

#[test]
fn check_output_timelock_tag_values() {
    for tag in crate::OutputTimeLockTag::iter() {
        match tag {
            crate::OutputTimeLockTag::UntilTime => {
                assert_eq!(
                    crate::OutputTimeLockTag::from_u32(
                        trezor_client::protos::MintlayerOutputTimeLockType::UNTIL_TIME as u32
                    ),
                    Some(tag)
                );
            }
            crate::OutputTimeLockTag::UntilHeight => {
                assert_eq!(
                    crate::OutputTimeLockTag::from_u32(
                        trezor_client::protos::MintlayerOutputTimeLockType::UNTIL_HEIGHT as u32
                    ),
                    Some(tag)
                );
            }
            crate::OutputTimeLockTag::ForSeconds => {
                assert_eq!(
                    crate::OutputTimeLockTag::from_u32(
                        trezor_client::protos::MintlayerOutputTimeLockType::FOR_SECONDS as u32
                    ),
                    Some(tag)
                );
            }
            crate::OutputTimeLockTag::ForBlockCount => {
                assert_eq!(
                    crate::OutputTimeLockTag::from_u32(
                        trezor_client::protos::MintlayerOutputTimeLockType::FOR_BLOCK_COUNT as u32
                    ),
                    Some(tag)
                );
            }
        }
    }
}

#[test]
fn check_is_token_freezable_type_values() {
    for variant in crate::IsTokenFreezable::iter() {
        match variant {
            IsTokenFreezable::No => {
                assert_eq!(crate::IsTokenFreezable::from_u32(0), Some(variant));
            }
            IsTokenFreezable::Yes => {
                assert_eq!(crate::IsTokenFreezable::from_u32(1), Some(variant));
            }
        }
    }
}

#[test]
fn check_outpoint_source_id_tag_values() {
    for tag in crate::OutPointSourceIdTag::iter() {
        match tag {
            crate::OutPointSourceIdTag::Transaction => {
                assert_eq!(
                    crate::OutPointSourceIdTag::from_u32(
                        trezor_client::protos::MintlayerUtxoType::TRANSACTION as u32
                    ),
                    Some(tag)
                );
            }
            crate::OutPointSourceIdTag::BlockReward => {
                assert_eq!(
                    crate::OutPointSourceIdTag::from_u32(
                        trezor_client::protos::MintlayerUtxoType::BLOCK as u32
                    ),
                    Some(tag)
                );
            }
        }
    }
}
