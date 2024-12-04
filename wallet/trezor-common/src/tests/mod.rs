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

use std::{boxed::Box, println, vec::Vec};

use common::{chain, primitives};
use crypto::key::KeyKind;
use parity_scale_codec::{DecodeAll, Encode};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, CryptoRng, Rng, Seed};

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

impl From<chain::TxInput> for crate::TxInput {
    fn from(value: chain::TxInput) -> Self {
        match value {
            chain::TxInput::Utxo(utxo) => Self::Utxo(utxo.into()),
            chain::TxInput::Account(acc) => Self::Account(acc.into()),
            chain::TxInput::AccountCommand(nonce, command) => {
                Self::AccountCommand(nonce.value(), command.into())
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

fn make_random_destination(rng: &mut (impl Rng + CryptoRng)) -> chain::Destination {
    match rng.gen_range(0..=4) {
        0 => chain::Destination::AnyoneCanSpend,
        1 => chain::Destination::PublicKey(
            crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1,
        ),
        2 => chain::Destination::ScriptHash(primitives::H256(rng.gen()).into()),
        3 => chain::Destination::ClassicMultisig(
            (&crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1).into(),
        ),
        _ => chain::Destination::PublicKeyHash(
            (&crypto::key::PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1).into(),
        ),
    }
}

fn make_random_bytes(rng: &mut (impl Rng + CryptoRng)) -> Vec<u8> {
    (0..rng.gen_range(1..10)).map(|_| rng.gen()).collect()
}

fn make_random_account_command(rng: &mut (impl Rng + CryptoRng)) -> chain::AccountCommand {
    match rng.gen_range(0..=8) {
        0 => chain::AccountCommand::MintTokens(
            primitives::H256(rng.gen()).into(),
            primitives::Amount::from_atoms(rng.gen()),
        ),
        1 => chain::AccountCommand::UnmintTokens(primitives::H256(rng.gen()).into()),
        2 => chain::AccountCommand::LockTokenSupply(primitives::H256(rng.gen()).into()),
        3 => chain::AccountCommand::FreezeToken(
            primitives::H256(rng.gen()).into(),
            if rng.gen::<bool>() {
                chain::tokens::IsTokenUnfreezable::Yes
            } else {
                chain::tokens::IsTokenUnfreezable::No
            },
        ),
        4 => chain::AccountCommand::UnfreezeToken(primitives::H256(rng.gen()).into()),
        5 => chain::AccountCommand::ChangeTokenAuthority(
            primitives::H256(rng.gen()).into(),
            make_random_destination(rng),
        ),
        6 => chain::AccountCommand::ConcludeOrder(primitives::H256(rng.gen()).into()),
        7 => chain::AccountCommand::FillOrder(
            primitives::H256(rng.gen()).into(),
            primitives::Amount::from_atoms(rng.gen()),
            make_random_destination(rng),
        ),
        _ => chain::AccountCommand::ChangeTokenMetadataUri(
            primitives::H256(rng.gen()).into(),
            make_random_bytes(rng),
        ),
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
    match rng.gen_range(0..=3) {
        0 => chain::timelock::OutputTimeLock::UntilHeight(primitives::BlockHeight::new(rng.gen())),
        1 => chain::timelock::OutputTimeLock::UntilTime(
            chain::block::timestamp::BlockTimestamp::from_int_seconds(rng.gen()),
        ),
        2 => chain::timelock::OutputTimeLock::ForSeconds(rng.gen()),
        _ => chain::timelock::OutputTimeLock::ForBlockCount(rng.gen()),
    }
}

fn make_random_token_total_supply(
    rng: &mut (impl Rng + CryptoRng),
) -> chain::tokens::TokenTotalSupply {
    match rng.gen_range(0..=2) {
        0 => chain::tokens::TokenTotalSupply::Unlimited,
        1 => chain::tokens::TokenTotalSupply::Lockable,
        _ => chain::tokens::TokenTotalSupply::Fixed(primitives::Amount::from_atoms(rng.gen())),
    }
}

fn make_random_output(rng: &mut (impl Rng + CryptoRng)) -> chain::TxOutput {
    match rng.gen_range(0..=11) {
        0 => chain::TxOutput::Transfer(make_random_value(rng), make_random_destination(rng)),
        1 => chain::TxOutput::LockThenTransfer(
            make_random_value(rng),
            make_random_destination(rng),
            make_random_lock(rng),
        ),
        2 => chain::TxOutput::Burn(make_random_value(rng)),
        3 => chain::TxOutput::CreateStakePool(
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
        4 => chain::TxOutput::ProduceBlockFromStake(
            make_random_destination(rng),
            primitives::H256(rng.gen()).into(),
        ),
        5 => chain::TxOutput::CreateDelegationId(
            make_random_destination(rng),
            primitives::H256(rng.gen()).into(),
        ),
        6 => chain::TxOutput::DelegateStaking(
            primitives::Amount::from_atoms(rng.gen()),
            primitives::H256(rng.gen()).into(),
        ),
        7 => chain::TxOutput::IssueFungibleToken(Box::new(chain::tokens::TokenIssuance::V1(
            chain::tokens::TokenIssuanceV1 {
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
            },
        ))),
        8 => chain::TxOutput::IssueNft(
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
        9 => chain::TxOutput::DataDeposit(make_random_bytes(rng)),
        10 => chain::TxOutput::Htlc(
            make_random_value(rng),
            Box::new(chain::htlc::HashedTimelockContract {
                secret_hash: chain::htlc::HtlcSecretHash(rng.gen()),
                spend_key: make_random_destination(rng),
                refund_timelock: make_random_lock(rng),
                refund_key: make_random_destination(rng),
            }),
        ),
        _ => chain::TxOutput::CreateOrder(Box::new(chain::OrderData::new(
            make_random_destination(rng),
            make_random_value(rng),
            make_random_value(rng),
        ))),
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_input_encodings(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let inp = make_random_input(&mut rng);

    let simple_inp: crate::TxInput = inp.clone().into();

    assert_eq!(inp.encode(), simple_inp.encode());

    let decoded_simple_inp =
        chain::TxInput::decode_all(&mut simple_inp.encode().as_slice()).unwrap();
    assert_eq!(decoded_simple_inp, inp);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_output_encodings(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let out = make_random_output(&mut rng);

    let simple_out: crate::TxOutput = out.clone().into();

    assert_eq!(out.encode(), simple_out.encode());

    let decoded_simple_out =
        chain::TxOutput::decode_all(&mut simple_out.encode().as_slice()).unwrap();
    assert_eq!(decoded_simple_out, out);
}
