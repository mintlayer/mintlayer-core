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

use std::{borrow::Cow, boxed::Box, vec::Vec};

use strum::IntoEnumIterator as _;

use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::timestamp::BlockTimestamp,
        htlc::{HashedTimelockContract, HtlcSecretHash},
        output_value::{OutputValue, OutputValueTag},
        signature::sighash::input_commitments::{
            SighashInputCommitment, SighashInputCommitmentTag,
        },
        stakelock::StakePoolData,
        timelock::{OutputTimeLock, OutputTimeLockTag},
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceTag,
            NftIssuanceV0, TokenCreator, TokenIssuance, TokenIssuanceTag, TokenIssuanceV1,
            TokenTotalSupply, TokenTotalSupplyTag,
        },
        AccountCommand, AccountCommandTag, AccountNonce, AccountOutPoint, AccountSpending,
        AccountSpendingTag, Destination, DestinationTag, OrderAccountCommand,
        OrderAccountCommandTag, OrderData, OutPointSourceId, OutPointSourceIdTag, TxInput,
        TxInputTag, TxOutput, TxOutputTag, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey},
};
use test_utils::random::{CryptoRng, IteratorRandom, Rng};

pub fn make_random_destination_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: DestinationTag,
) -> Destination {
    match tag {
        DestinationTag::AnyoneCanSpend => Destination::AnyoneCanSpend,
        DestinationTag::PublicKey => Destination::PublicKey(make_random_public_key(rng)),
        DestinationTag::ScriptHash => Destination::ScriptHash(H256(rng.gen()).into()),
        DestinationTag::ClassicMultisig => {
            Destination::ClassicMultisig(make_random_public_key_hash(rng))
        }
        DestinationTag::PublicKeyHash => {
            Destination::PublicKeyHash(make_random_public_key_hash(rng))
        }
    }
}

pub fn make_random_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    let tag = DestinationTag::iter().choose(rng).unwrap();
    make_random_destination_for_tag(rng, tag)
}

pub fn make_random_public_key_hash(rng: &mut (impl Rng + CryptoRng)) -> PublicKeyHash {
    (&PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1).into()
}

pub fn make_random_public_key_for_kind(
    rng: &mut (impl Rng + CryptoRng),
    kind: KeyKind,
) -> PublicKey {
    PrivateKey::new_from_rng(rng, kind).1
}

pub fn make_random_public_key(rng: &mut (impl Rng + CryptoRng)) -> PublicKey {
    let kind = KeyKind::iter().choose(rng).unwrap();
    make_random_public_key_for_kind(rng, kind)
}

pub fn make_random_vrf_public_key_for_kind(
    rng: &mut (impl Rng + CryptoRng),
    kind: VRFKeyKind,
) -> VRFPublicKey {
    VRFPrivateKey::new_from_rng(rng, kind).1
}

pub fn make_random_vrf_public_key(rng: &mut (impl Rng + CryptoRng)) -> VRFPublicKey {
    let kind = VRFKeyKind::iter().choose(rng).unwrap();
    make_random_vrf_public_key_for_kind(rng, kind)
}

pub fn make_random_bytes(rng: &mut (impl Rng + CryptoRng)) -> Vec<u8> {
    test_utils::random::gen_random_bytes(rng, 1, 20)
}

pub fn make_random_account_command_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: AccountCommandTag,
) -> AccountCommand {
    match tag {
        AccountCommandTag::MintTokens => {
            AccountCommand::MintTokens(H256(rng.gen()).into(), Amount::from_atoms(rng.gen()))
        }
        AccountCommandTag::UnmintTokens => AccountCommand::UnmintTokens(H256(rng.gen()).into()),
        AccountCommandTag::LockTokenSupply => {
            AccountCommand::LockTokenSupply(H256(rng.gen()).into())
        }
        AccountCommandTag::FreezeToken => AccountCommand::FreezeToken(
            H256(rng.gen()).into(),
            if rng.gen::<bool>() {
                IsTokenUnfreezable::Yes
            } else {
                IsTokenUnfreezable::No
            },
        ),
        AccountCommandTag::UnfreezeToken => AccountCommand::UnfreezeToken(H256(rng.gen()).into()),
        AccountCommandTag::ChangeTokenAuthority => AccountCommand::ChangeTokenAuthority(
            H256(rng.gen()).into(),
            make_random_destination(rng),
        ),
        AccountCommandTag::ConcludeOrder => AccountCommand::ConcludeOrder(H256(rng.gen()).into()),
        AccountCommandTag::FillOrder => AccountCommand::FillOrder(
            H256(rng.gen()).into(),
            Amount::from_atoms(rng.gen()),
            make_random_destination(rng),
        ),
        AccountCommandTag::ChangeTokenMetadataUri => {
            AccountCommand::ChangeTokenMetadataUri(H256(rng.gen()).into(), make_random_bytes(rng))
        }
    }
}

pub fn make_random_account_command(rng: &mut (impl Rng + CryptoRng)) -> AccountCommand {
    let tag = AccountCommandTag::iter().choose(rng).unwrap();
    make_random_account_command_for_tag(rng, tag)
}

pub fn make_random_order_account_command(rng: &mut (impl Rng + CryptoRng)) -> OrderAccountCommand {
    let tag = OrderAccountCommandTag::iter().choose(rng).unwrap();
    make_random_order_account_command_for_tag(rng, tag)
}

pub fn make_random_order_account_command_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: OrderAccountCommandTag,
) -> OrderAccountCommand {
    match tag {
        OrderAccountCommandTag::FillOrder => {
            OrderAccountCommand::FillOrder(H256(rng.gen()).into(), Amount::from_atoms(rng.gen()))
        }
        OrderAccountCommandTag::FreezeOrder => {
            OrderAccountCommand::FreezeOrder(H256(rng.gen()).into())
        }
        OrderAccountCommandTag::ConcludeOrder => {
            OrderAccountCommand::ConcludeOrder(H256(rng.gen()).into())
        }
    }
}

pub fn make_random_outpoint_source_id_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: OutPointSourceIdTag,
) -> OutPointSourceId {
    match tag {
        OutPointSourceIdTag::Transaction => OutPointSourceId::Transaction(H256(rng.gen()).into()),
        OutPointSourceIdTag::BlockReward => OutPointSourceId::BlockReward(H256(rng.gen()).into()),
    }
}

pub fn make_random_outpoint_source_id(rng: &mut (impl Rng + CryptoRng)) -> OutPointSourceId {
    let tag = OutPointSourceIdTag::iter().choose(rng).unwrap();
    make_random_outpoint_source_id_for_tag(rng, tag)
}

pub fn make_random_utxo_outpoint(rng: &mut (impl Rng + CryptoRng)) -> UtxoOutPoint {
    UtxoOutPoint::new(make_random_outpoint_source_id(rng), rng.gen())
}

pub fn make_random_tx_input_for_tag(rng: &mut (impl Rng + CryptoRng), tag: TxInputTag) -> TxInput {
    match tag {
        TxInputTag::Utxo => TxInput::Utxo(make_random_utxo_outpoint(rng)),
        TxInputTag::Account => TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(rng.gen()),
            make_random_account_spending(rng),
        )),
        TxInputTag::AccountCommand => TxInput::AccountCommand(
            AccountNonce::new(rng.gen()),
            make_random_account_command(rng),
        ),
        TxInputTag::OrderAccountCommand => {
            TxInput::OrderAccountCommand(make_random_order_account_command(rng))
        }
    }
}

pub fn make_random_account_spending_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: AccountSpendingTag,
) -> AccountSpending {
    match tag {
        AccountSpendingTag::DelegationBalance => AccountSpending::DelegationBalance(
            H256(rng.gen()).into(),
            Amount::from_atoms(rng.gen()),
        ),
    }
}

pub fn make_random_account_spending(rng: &mut (impl Rng + CryptoRng)) -> AccountSpending {
    let tag = AccountSpendingTag::iter().choose(rng).unwrap();
    make_random_account_spending_for_tag(rng, tag)
}

pub fn make_random_account_outpoint(rng: &mut (impl Rng + CryptoRng)) -> AccountOutPoint {
    AccountOutPoint::new(
        AccountNonce::new(rng.gen()),
        make_random_account_spending(rng),
    )
}

pub fn make_random_output_value_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: OutputValueTag,
) -> OutputValue {
    match tag {
        OutputValueTag::Coin => OutputValue::Coin(Amount::from_atoms(rng.gen())),
        // Note: the other enum doesn't have the V0 variant, so we don't generate it here.
        OutputValueTag::TokenV0 | OutputValueTag::TokenV1 => {
            OutputValue::TokenV1(H256(rng.gen()).into(), Amount::from_atoms(rng.gen()))
        }
    }
}

pub fn make_random_output_value(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    let tag = OutputValueTag::iter().choose(rng).unwrap();
    make_random_output_value_for_tag(rng, tag)
}

pub fn make_random_output_time_lock_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: OutputTimeLockTag,
) -> OutputTimeLock {
    match tag {
        OutputTimeLockTag::UntilHeight => OutputTimeLock::UntilHeight(BlockHeight::new(rng.gen())),
        OutputTimeLockTag::UntilTime => {
            OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(rng.gen()))
        }
        OutputTimeLockTag::ForSeconds => OutputTimeLock::ForSeconds(rng.gen()),
        OutputTimeLockTag::ForBlockCount => OutputTimeLock::ForBlockCount(rng.gen()),
    }
}

pub fn make_random_output_time_lock(rng: &mut (impl Rng + CryptoRng)) -> OutputTimeLock {
    let tag = OutputTimeLockTag::iter().choose(rng).unwrap();
    make_random_output_time_lock_for_tag(rng, tag)
}

pub fn make_random_token_total_supply_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: TokenTotalSupplyTag,
) -> TokenTotalSupply {
    match tag {
        TokenTotalSupplyTag::Unlimited => TokenTotalSupply::Unlimited,
        TokenTotalSupplyTag::Lockable => TokenTotalSupply::Lockable,
        TokenTotalSupplyTag::Fixed => TokenTotalSupply::Fixed(Amount::from_atoms(rng.gen())),
    }
}

pub fn make_random_token_total_supply(rng: &mut (impl Rng + CryptoRng)) -> TokenTotalSupply {
    let tag = TokenTotalSupplyTag::iter().choose(rng).unwrap();
    make_random_token_total_supply_for_tag(rng, tag)
}

pub fn make_random_token_issuance_v1(rng: &mut (impl Rng + CryptoRng)) -> TokenIssuanceV1 {
    TokenIssuanceV1 {
        token_ticker: make_random_bytes(rng),
        number_of_decimals: rng.gen(),
        metadata_uri: make_random_bytes(rng),
        total_supply: make_random_token_total_supply(rng),
        authority: make_random_destination(rng),
        is_freezable: if rng.gen::<bool>() {
            IsTokenFreezable::Yes
        } else {
            IsTokenFreezable::No
        },
    }
}

pub fn make_random_token_issuance_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: TokenIssuanceTag,
) -> TokenIssuance {
    match tag {
        TokenIssuanceTag::V1 => TokenIssuance::V1(make_random_token_issuance_v1(rng)),
    }
}

pub fn make_random_token_issuance(rng: &mut (impl Rng + CryptoRng)) -> TokenIssuance {
    let tag = TokenIssuanceTag::iter().choose(rng).unwrap();
    make_random_token_issuance_for_tag(rng, tag)
}

pub fn make_random_nft_issuance_v0(rng: &mut (impl Rng + CryptoRng)) -> NftIssuanceV0 {
    NftIssuanceV0 {
        metadata: Metadata {
            creator: if rng.gen::<bool>() {
                Some(TokenCreator {
                    public_key: make_random_public_key(rng),
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
    }
}

pub fn make_random_nft_issuance_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: NftIssuanceTag,
) -> NftIssuance {
    match tag {
        NftIssuanceTag::V0 => NftIssuance::V0(make_random_nft_issuance_v0(rng)),
    }
}

pub fn make_random_nft_issuance(rng: &mut (impl Rng + CryptoRng)) -> NftIssuance {
    let tag = NftIssuanceTag::iter().choose(rng).unwrap();
    make_random_nft_issuance_for_tag(rng, tag)
}

pub fn make_random_stake_pool_data(rng: &mut (impl Rng + CryptoRng)) -> StakePoolData {
    StakePoolData::new(
        Amount::from_atoms(rng.gen()),
        make_random_destination(rng),
        make_random_vrf_public_key(rng),
        make_random_destination(rng),
        PerThousand::new_from_rng(rng),
        Amount::from_atoms(rng.gen()),
    )
}

pub fn make_random_order_data(rng: &mut (impl Rng + CryptoRng)) -> OrderData {
    OrderData::new(
        make_random_destination(rng),
        make_random_output_value(rng),
        make_random_output_value(rng),
    )
}

pub fn make_random_htlc(rng: &mut (impl Rng + CryptoRng)) -> HashedTimelockContract {
    HashedTimelockContract {
        secret_hash: HtlcSecretHash(rng.gen()),
        spend_key: make_random_destination(rng),
        refund_timelock: make_random_output_time_lock(rng),
        refund_key: make_random_destination(rng),
    }
}

pub fn make_random_tx_output_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: TxOutputTag,
) -> TxOutput {
    match tag {
        TxOutputTag::Transfer => {
            TxOutput::Transfer(make_random_output_value(rng), make_random_destination(rng))
        }
        TxOutputTag::LockThenTransfer => TxOutput::LockThenTransfer(
            make_random_output_value(rng),
            make_random_destination(rng),
            make_random_output_time_lock(rng),
        ),
        TxOutputTag::Burn => TxOutput::Burn(make_random_output_value(rng)),
        TxOutputTag::CreateStakePool => TxOutput::CreateStakePool(
            H256(rng.gen()).into(),
            Box::new(make_random_stake_pool_data(rng)),
        ),
        TxOutputTag::ProduceBlockFromStake => {
            TxOutput::ProduceBlockFromStake(make_random_destination(rng), H256(rng.gen()).into())
        }
        TxOutputTag::CreateDelegationId => {
            TxOutput::CreateDelegationId(make_random_destination(rng), H256(rng.gen()).into())
        }
        TxOutputTag::DelegateStaking => {
            TxOutput::DelegateStaking(Amount::from_atoms(rng.gen()), H256(rng.gen()).into())
        }
        TxOutputTag::IssueFungibleToken => {
            TxOutput::IssueFungibleToken(Box::new(make_random_token_issuance(rng)))
        }
        TxOutputTag::IssueNft => TxOutput::IssueNft(
            H256(rng.gen()).into(),
            Box::new(make_random_nft_issuance(rng)),
            make_random_destination(rng),
        ),
        TxOutputTag::DataDeposit => TxOutput::DataDeposit(make_random_bytes(rng)),
        TxOutputTag::Htlc => TxOutput::Htlc(
            make_random_output_value(rng),
            Box::new(make_random_htlc(rng)),
        ),
        TxOutputTag::CreateOrder => TxOutput::CreateOrder(Box::new(make_random_order_data(rng))),
    }
}

pub fn make_random_tx_output(rng: &mut (impl Rng + CryptoRng)) -> TxOutput {
    let tag = TxOutputTag::iter().choose(rng).unwrap();
    make_random_tx_output_for_tag(rng, tag)
}

pub fn make_random_input_commitment_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: SighashInputCommitmentTag,
) -> SighashInputCommitment<'static> {
    type CommTag = SighashInputCommitmentTag;
    type Comm = SighashInputCommitment<'static>;

    match tag {
        CommTag::None => Comm::None,
        CommTag::Utxo => Comm::Utxo(Cow::Owned(make_random_tx_output(rng))),
        CommTag::ProduceBlockFromStakeUtxo => Comm::ProduceBlockFromStakeUtxo {
            utxo: Cow::Owned(make_random_tx_output(rng)),
            staker_balance: Amount::from_atoms(rng.gen()),
        },
        CommTag::FillOrderAccountCommand => Comm::FillOrderAccountCommand {
            initially_asked: make_random_output_value(rng),
            initially_given: make_random_output_value(rng),
        },
        CommTag::ConcludeOrderAccountCommand => Comm::ConcludeOrderAccountCommand {
            initially_asked: make_random_output_value(rng),
            initially_given: make_random_output_value(rng),
            ask_balance: Amount::from_atoms(rng.gen()),
            give_balance: Amount::from_atoms(rng.gen()),
        },
    }
}
