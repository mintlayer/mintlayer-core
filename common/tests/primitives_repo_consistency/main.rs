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

use rstest::rstest;
use strum::IntoEnumIterator as _;

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{Builder, ChainType},
        output_value::OutputValueTag,
        signature::sighash::input_commitments::SighashInputCommitmentTag,
        timelock::OutputTimeLockTag,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, NftIssuanceTag, TokenIssuanceTag,
            TokenTotalSupplyTag,
        },
        AccountCommandTag, AccountNonce, AccountSpendingTag, DestinationTag,
        OrderAccountCommandTag, OutPointSourceIdTag, TxInputTag, TxOutputTag,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, H256},
};
use crypto::{key::KeyKind, vrf::VRFKeyKind};
use randomness::Rng as _;
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};

use crate::utils::{
    converters::ConvertInto as _,
    make_test_values_for_compact_encoding,
    makers::{
        make_random_account_command_for_tag, make_random_account_outpoint,
        make_random_account_spending_for_tag, make_random_destination_for_tag, make_random_htlc,
        make_random_input_commitment_for_tag, make_random_nft_issuance_for_tag,
        make_random_order_account_command_for_tag, make_random_order_data,
        make_random_outpoint_source_id_for_tag, make_random_output_time_lock_for_tag,
        make_random_output_value_for_tag, make_random_public_key_for_kind,
        make_random_public_key_hash, make_random_stake_pool_data,
        make_random_token_issuance_for_tag, make_random_token_total_supply_for_tag,
        make_random_tx_input_for_tag, make_random_tx_output_for_tag, make_random_utxo_outpoint,
        make_random_vrf_public_key_for_kind,
    },
};

mod utils;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_amount_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for val in make_test_values_for_compact_encoding(&mut rng, 100) {
        let ref_obj = Amount::from_atoms(val);
        let test_obj = ml_primitives::Amount::from_atoms(val);

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::Amount>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_block_height_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for val in make_test_values_for_compact_encoding(&mut rng, 100) {
        let ref_obj = BlockHeight::new(val);
        let test_obj = ml_primitives::BlockHeight(val);

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::BlockHeight>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_block_timestamp_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for val in make_test_values_for_compact_encoding(&mut rng, 100) {
        let ref_obj = BlockTimestamp::from_int_seconds(val);
        let test_obj = ml_primitives::BlockTimestamp(ml_primitives::SecondsCount(val));

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::BlockTimestamp>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_account_nonce_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for val in make_test_values_for_compact_encoding(&mut rng, 100) {
        let ref_obj = AccountNonce::new(val);
        let test_obj = ml_primitives::AccountNonce(val);

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::AccountNonce>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_account_spending_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in AccountSpendingTag::iter() {
            let ref_obj = make_random_account_spending_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::AccountSpending = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::AccountSpending>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::AccountSpendingTag| match tag {
        ml_primitives::AccountSpendingTag::DelegationBalance => {
            AccountSpendingTag::DelegationBalance
        }
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_account_outpoint_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = make_random_account_outpoint(&mut rng);
        let test_obj: ml_primitives::AccountOutPoint = ref_obj.clone().convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::AccountOutPoint>(
            encoded_test_obj.as_slice(),
        )
        .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_account_command_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in AccountCommandTag::iter() {
            let ref_obj = make_random_account_command_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::AccountCommand = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::AccountCommand>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::AccountCommandTag| match tag {
        ml_primitives::AccountCommandTag::MintTokens => AccountCommandTag::MintTokens,
        ml_primitives::AccountCommandTag::UnmintTokens => AccountCommandTag::UnmintTokens,
        ml_primitives::AccountCommandTag::LockTokenSupply => AccountCommandTag::LockTokenSupply,
        ml_primitives::AccountCommandTag::FreezeToken => AccountCommandTag::FreezeToken,
        ml_primitives::AccountCommandTag::UnfreezeToken => AccountCommandTag::UnfreezeToken,
        ml_primitives::AccountCommandTag::ChangeTokenAuthority => {
            AccountCommandTag::ChangeTokenAuthority
        }
        ml_primitives::AccountCommandTag::ConcludeOrder => AccountCommandTag::ConcludeOrder,
        ml_primitives::AccountCommandTag::FillOrder => AccountCommandTag::FillOrder,
        ml_primitives::AccountCommandTag::ChangeTokenMetadataUri => {
            AccountCommandTag::ChangeTokenMetadataUri
        }
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_order_account_command_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in OrderAccountCommandTag::iter() {
            let ref_obj = make_random_order_account_command_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::OrderAccountCommand = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::OrderAccountCommand>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::OrderAccountCommandTag| match tag {
        ml_primitives::OrderAccountCommandTag::FillOrder => OrderAccountCommandTag::FillOrder,
        ml_primitives::OrderAccountCommandTag::FreezeOrder => OrderAccountCommandTag::FreezeOrder,
        ml_primitives::OrderAccountCommandTag::ConcludeOrder => {
            OrderAccountCommandTag::ConcludeOrder
        }
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_public_key_hash_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = make_random_public_key_hash(&mut rng);
        let test_obj: ml_primitives::PublicKeyHash = ref_obj.convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::PublicKeyHash>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_public_key_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for kind in KeyKind::iter() {
            let ref_obj = make_random_public_key_for_kind(&mut rng, kind);
            let test_obj: ml_primitives::PublicKey = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj =
                ml_primitives::decode_all::<ml_primitives::PublicKey>(encoded_test_obj.as_slice())
                    .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::PublicKeyTag| match tag {
        ml_primitives::PublicKeyTag::Secp256k1Schnorr => KeyKind::Secp256k1Schnorr,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_vrf_public_key_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for kind in VRFKeyKind::iter() {
            let ref_obj = make_random_vrf_public_key_for_kind(&mut rng, kind);
            let test_obj: ml_primitives::VrfPublicKey = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::VrfPublicKey>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::VrfPublicKeyTag| match tag {
        ml_primitives::VrfPublicKeyTag::Schnorrkel => VRFKeyKind::Schnorrkel,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_destination_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in DestinationTag::iter() {
            let ref_obj = make_random_destination_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::Destination = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::Destination>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::DestinationTag| match tag {
        ml_primitives::DestinationTag::AnyoneCanSpend => DestinationTag::AnyoneCanSpend,
        ml_primitives::DestinationTag::PublicKeyHash => DestinationTag::PublicKeyHash,
        ml_primitives::DestinationTag::PublicKey => DestinationTag::PublicKey,
        ml_primitives::DestinationTag::ScriptHash => DestinationTag::ScriptHash,
        ml_primitives::DestinationTag::ClassicMultisig => DestinationTag::ClassicMultisig,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_id_encoding(#[case] seed: Seed) {
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct CustomTag;
    type RefCustomId = Id<CustomTag>;
    type TestCustomId = ml_primitives::Id<CustomTag>;

    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj: RefCustomId = H256(rng.gen()).into();
        let test_obj = TestCustomId::new(ref_obj.to_hash().convert_into());

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<TestCustomId>(encoded_test_obj.as_slice()).unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_per_thousand_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = PerThousand::new_from_rng(&mut rng);
        let test_obj: ml_primitives::PerThousand = ref_obj.convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::PerThousand>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_sighash_input_commitment_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in SighashInputCommitmentTag::iter() {
            let ref_obj = make_random_input_commitment_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::SighashInputCommitment = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj =
                ml_primitives::decode_all::<ml_primitives::SighashInputCommitment>(
                    encoded_test_obj.as_slice(),
                )
                .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::SighashInputCommitmentTag| match tag {
        ml_primitives::SighashInputCommitmentTag::None => SighashInputCommitmentTag::None,
        ml_primitives::SighashInputCommitmentTag::Utxo => SighashInputCommitmentTag::Utxo,
        ml_primitives::SighashInputCommitmentTag::ProduceBlockFromStakeUtxo => {
            SighashInputCommitmentTag::ProduceBlockFromStakeUtxo
        }
        ml_primitives::SighashInputCommitmentTag::FillOrderAccountCommand => {
            SighashInputCommitmentTag::FillOrderAccountCommand
        }
        ml_primitives::SighashInputCommitmentTag::ConcludeOrderAccountCommand => {
            SighashInputCommitmentTag::ConcludeOrderAccountCommand
        }
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_token_issuance_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in TokenIssuanceTag::iter() {
            let ref_obj = make_random_token_issuance_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::TokenIssuance = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::TokenIssuance>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::TokenIssuanceTag| match tag {
        ml_primitives::TokenIssuanceTag::V1 => TokenIssuanceTag::V1,
    };
}

#[test]
fn test_is_token_freezable_encoding() {
    for ref_obj in IsTokenFreezable::iter() {
        let test_obj: ml_primitives::IsTokenFreezable = ref_obj.convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::IsTokenFreezable>(
            encoded_test_obj.as_slice(),
        )
        .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |val: ml_primitives::IsTokenFreezable| match val {
        ml_primitives::IsTokenFreezable::No => IsTokenFreezable::No,
        ml_primitives::IsTokenFreezable::Yes => IsTokenFreezable::Yes,
    };
}

#[test]
fn test_is_token_unfreezable_encoding() {
    for ref_obj in IsTokenUnfreezable::iter() {
        let test_obj: ml_primitives::IsTokenUnfreezable = ref_obj.convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::IsTokenUnfreezable>(
            encoded_test_obj.as_slice(),
        )
        .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |val: ml_primitives::IsTokenUnfreezable| match val {
        ml_primitives::IsTokenUnfreezable::No => IsTokenUnfreezable::No,
        ml_primitives::IsTokenUnfreezable::Yes => IsTokenUnfreezable::Yes,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_token_total_supply_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in TokenTotalSupplyTag::iter() {
            let ref_obj = make_random_token_total_supply_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::TokenTotalSupply = ref_obj.convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::TokenTotalSupply>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::TokenTotalSupplyTag| match tag {
        ml_primitives::TokenTotalSupplyTag::Fixed => TokenTotalSupplyTag::Fixed,
        ml_primitives::TokenTotalSupplyTag::Lockable => TokenTotalSupplyTag::Lockable,
        ml_primitives::TokenTotalSupplyTag::Unlimited => TokenTotalSupplyTag::Unlimited,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_nft_issuance_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in NftIssuanceTag::iter() {
            let ref_obj = make_random_nft_issuance_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::NftIssuance = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::NftIssuance>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::NftIssuanceTag| match tag {
        ml_primitives::NftIssuanceTag::V0 => NftIssuanceTag::V0,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_output_value_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in OutputValueTag::iter() {
            let ref_obj = make_random_output_value_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::OutputValue = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::OutputValue>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::OutputValueTag| match tag {
        ml_primitives::OutputValueTag::Coin => OutputValueTag::Coin,
        ml_primitives::OutputValueTag::TokenV1 => OutputValueTag::TokenV1,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_output_time_lock_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in OutputTimeLockTag::iter() {
            let ref_obj = make_random_output_time_lock_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::OutputTimeLock = ref_obj.convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::OutputTimeLock>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::OutputTimeLockTag| match tag {
        ml_primitives::OutputTimeLockTag::UntilHeight => OutputTimeLockTag::UntilHeight,
        ml_primitives::OutputTimeLockTag::UntilTime => OutputTimeLockTag::UntilTime,
        ml_primitives::OutputTimeLockTag::ForBlockCount => OutputTimeLockTag::ForBlockCount,
        ml_primitives::OutputTimeLockTag::ForSeconds => OutputTimeLockTag::ForSeconds,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_outpoint_source_id_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in OutPointSourceIdTag::iter() {
            let ref_obj = make_random_outpoint_source_id_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::OutPointSourceId = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::OutPointSourceId>(
                encoded_test_obj.as_slice(),
            )
            .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::OutPointSourceIdTag| match tag {
        ml_primitives::OutPointSourceIdTag::Transaction => OutPointSourceIdTag::Transaction,
        ml_primitives::OutPointSourceIdTag::BlockReward => OutPointSourceIdTag::BlockReward,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_utxo_outpoint_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = make_random_utxo_outpoint(&mut rng);
        let test_obj: ml_primitives::UtxoOutPoint = ref_obj.clone().convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::UtxoOutPoint>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_stake_pool_data_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = make_random_stake_pool_data(&mut rng);
        let test_obj: ml_primitives::StakePoolData = ref_obj.clone().convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::StakePoolData>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_order_data_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = make_random_order_data(&mut rng);
        let test_obj: ml_primitives::OrderData = ref_obj.clone().convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj =
            ml_primitives::decode_all::<ml_primitives::OrderData>(encoded_test_obj.as_slice())
                .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_htlc_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let ref_obj = make_random_htlc(&mut rng);
        let test_obj: ml_primitives::HashedTimelockContract = ref_obj.clone().convert_into();

        let encoded_ref_obj = ref_obj.encode();
        let encoded_test_obj = ml_primitives::encode(&test_obj);

        assert_eq!(encoded_test_obj, encoded_ref_obj);

        let decoded_test_obj = ml_primitives::decode_all::<ml_primitives::HashedTimelockContract>(
            encoded_test_obj.as_slice(),
        )
        .unwrap();
        assert_eq!(decoded_test_obj, test_obj);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_tx_input_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in TxInputTag::iter() {
            let ref_obj = make_random_tx_input_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::TxInput = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj =
                ml_primitives::decode_all::<ml_primitives::TxInput>(encoded_test_obj.as_slice())
                    .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::TxInputTag| match tag {
        ml_primitives::TxInputTag::Utxo => TxInputTag::Utxo,
        ml_primitives::TxInputTag::Account => TxInputTag::Account,
        ml_primitives::TxInputTag::AccountCommand => TxInputTag::AccountCommand,
        ml_primitives::TxInputTag::OrderAccountCommand => TxInputTag::OrderAccountCommand,
    };
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_tx_output_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        for tag in TxOutputTag::iter() {
            let ref_obj = make_random_tx_output_for_tag(&mut rng, tag);
            let test_obj: ml_primitives::TxOutput = ref_obj.clone().convert_into();

            let encoded_ref_obj = ref_obj.encode();
            let encoded_test_obj = ml_primitives::encode(&test_obj);

            assert_eq!(encoded_test_obj, encoded_ref_obj);

            let decoded_test_obj =
                ml_primitives::decode_all::<ml_primitives::TxOutput>(encoded_test_obj.as_slice())
                    .unwrap();
            assert_eq!(decoded_test_obj, test_obj);
        }
    }

    // Check that for every variant of the test type we have one in the reference type as well
    // (the opposite is checked implicitly in the "convert" function).
    let _ = |tag: ml_primitives::TxOutputTag| match tag {
        ml_primitives::TxOutputTag::Transfer => TxOutputTag::Transfer,
        ml_primitives::TxOutputTag::LockThenTransfer => TxOutputTag::LockThenTransfer,
        ml_primitives::TxOutputTag::Burn => TxOutputTag::Burn,
        ml_primitives::TxOutputTag::CreateStakePool => TxOutputTag::CreateStakePool,
        ml_primitives::TxOutputTag::ProduceBlockFromStake => TxOutputTag::ProduceBlockFromStake,
        ml_primitives::TxOutputTag::CreateDelegationId => TxOutputTag::CreateDelegationId,
        ml_primitives::TxOutputTag::DelegateStaking => TxOutputTag::DelegateStaking,
        ml_primitives::TxOutputTag::IssueFungibleToken => TxOutputTag::IssueFungibleToken,
        ml_primitives::TxOutputTag::IssueNft => TxOutputTag::IssueNft,
        ml_primitives::TxOutputTag::DataDeposit => TxOutputTag::DataDeposit,
        ml_primitives::TxOutputTag::Htlc => TxOutputTag::Htlc,
        ml_primitives::TxOutputTag::CreateOrder => TxOutputTag::CreateOrder,
    };
}

// This is a compile-time test that ensures that ml_primitives used by the trezor firmware repo
// are the same ml_primitives that we've tested in this test.
#[allow(unused)]
fn ensure_trezor_firmware_uses_same_ml_primitives() {
    fn test(_: ml_primitives::Amount) {}

    // If `ml_primitives` and `trezor_client::client::ml_primitives` refer to different
    // versions (i.e. repo revisions) of the crate, this will not compile.
    test(trezor_client::client::ml_primitives::Amount::from_atoms(1));
}

#[test]
fn test_coin_type_consistency_settings() {
    for chain_type in ChainType::iter() {
        let config = Builder::new(chain_type).build();

        let coin_type = to_coin_type(chain_type);

        // Check Ticker consistency
        assert_eq!(
            config.coin_ticker(),
            coin_type.coin_ticker(),
            "Coin ticker mismatch for {:?}",
            chain_type
        );

        // Check Decimals consistency
        assert_eq!(
            config.coin_decimals(),
            coin_type.coin_decimals(),
            "Coin decimals mismatch for {:?}",
            chain_type
        );

        // Check BIP44 Coin Type consistency
        let config_bip44: u32 = config.bip44_coin_type().into_encoded_index();
        assert_eq!(
            config_bip44,
            coin_type.bip44_coin_type(),
            "BIP44 coin type mismatch for {:?}",
            chain_type
        );

        // Check Bech32 Prefixes for specific entity IDs
        assert_eq!(
            config.pool_id_address_prefix(),
            coin_type.pool_id_address_prefix(),
            "Pool ID address prefix mismatch for {:?}",
            chain_type
        );

        assert_eq!(
            config.delegation_id_address_prefix(),
            coin_type.delegation_id_address_prefix(),
            "Delegation ID address prefix mismatch for {:?}",
            chain_type
        );

        assert_eq!(
            config.token_id_address_prefix(),
            coin_type.token_id_address_prefix(),
            "Token ID address prefix mismatch for {:?}",
            chain_type
        );

        assert_eq!(
            config.order_id_address_prefix(),
            coin_type.order_id_address_prefix(),
            "Order ID address prefix mismatch for {:?}",
            chain_type
        );

        assert_eq!(
            config.vrf_public_key_address_prefix(),
            coin_type.vrf_public_key_address_prefix(),
            "VRF public key address prefix mismatch for {:?}",
            chain_type
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_coin_type_destination_address_prefixes(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for chain_type in ChainType::iter() {
        let config = Builder::new(chain_type).build();

        let coin_type = to_coin_type(chain_type);

        for tag in DestinationTag::iter() {
            // Create a random valid destination in the `common` format
            let common_dest = make_random_destination_for_tag(&mut rng, tag);

            let primitive_dest: ml_primitives::Destination = common_dest.clone().convert_into();
            let expected_prefix = config.destination_address_prefix(tag);
            let actual_prefix = coin_type.address_prefix(&primitive_dest);

            assert_eq!(
                expected_prefix, actual_prefix,
                "Address prefix mismatch for Chain: {:?}, Destination: {:?}",
                chain_type, tag
            );
        }
    }
}

fn to_coin_type(chain_type: ChainType) -> ml_primitives::CoinType {
    match chain_type {
        ChainType::Mainnet => ml_primitives::CoinType::Mainnet,
        ChainType::Testnet => ml_primitives::CoinType::Testnet,
        ChainType::Regtest => ml_primitives::CoinType::Regtest,
        ChainType::Signet => ml_primitives::CoinType::Signet,
    }
}
