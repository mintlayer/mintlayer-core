// Copyright (c) 2021-2024 RBB S.r.l
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

use crypto::vrf::VRFPublicKey;
use serialization::Encode;

use crate::{
    address::Address,
    chain::{
        tokens::{IsTokenFreezable, NftIssuance, TokenId, TokenIssuance, TokenTotalSupply},
        ChainConfig, DelegationId, PoolId,
    },
    primitives::{Amount, Idable, H256},
};

use super::{
    output_value::OutputValue, stakelock::StakePoolData, timelock::OutputTimeLock, Destination,
    Transaction, TxOutput,
};
use std::fmt::Write;

fn id_to_hex_string(id: H256) -> String {
    let hex_string = format!("{:?}", id);
    hex_string.strip_prefix("0x").unwrap_or(&hex_string).to_string()
}

pub fn transaction_summary(tx: &Transaction, chain_config: &ChainConfig) -> String {
    let mut result = format!(
        "Transaction summary:\n\
        Transaction id: {}\n\
        === BEGIN OF INPUTS ===\n\
        ",
        id_to_hex_string(tx.get_id().to_hash())
    );

    let fmt_ml = |v: &Amount| v.into_fixedpoint_str(chain_config.coin_decimals());
    let fmt_val = |val: &OutputValue| {
        match val {
            OutputValue::Coin(amount) => fmt_ml(amount),
            OutputValue::TokenV0(token_data) => format!("{token_data:?}"), // Not important since it's deprecated
            OutputValue::TokenV1(id, amount) => {
                format!(
                    "TokenV1({}, {amount:?})",
                    Address::new(chain_config, id)
                        .expect("Cannot fail due to TokenId being fixed size")
                )
            }
        }
    };
    let fmt_timelock = |tl: &OutputTimeLock| match tl {
        OutputTimeLock::UntilHeight(h) => format!("OutputTimeLock::UntilHeight({h})"),
        OutputTimeLock::UntilTime(t) => format!("OutputTimeLock::UntilTime({})", t.into_time()),
        OutputTimeLock::ForBlockCount(n) => format!("OutputTimeLock::ForBlockCount({n} blocks)"),
        OutputTimeLock::ForSeconds(secs) => {
            format!("OutputTimeLock::ForSeconds({secs} seconds)")
        }
    };
    let fmt_dest =
        |d: &Destination| format!("{}", Address::new(chain_config, d).expect("addressable"));
    let fmt_vrf =
        |k: &VRFPublicKey| format!("{}", Address::new(chain_config, k).expect("addressable"));
    let fmt_poolid = |id: &PoolId| {
        Address::new(chain_config, id).expect("Cannot fail because fixed size addressable")
    };
    let fmt_tknid = |id: &TokenId| {
        Address::new(chain_config, id).expect("Cannot fail because fixed size addressable")
    };
    let fmt_delid = |id: &DelegationId| {
        Address::new(chain_config, id).expect("Cannot fail because fixed size addressable")
    };
    let fmt_stakepooldata = |p: &StakePoolData| {
        let pledge = fmt_ml(&p.pledge());
        format!(
            "Pledge({pledge}), Staker({}), VRFPubKey({}), DecommissionKey({}), MarginRatio({}), CostPerBlock({})",
            fmt_dest(p.staker()),
            fmt_vrf(p.vrf_public_key()),
            fmt_dest(p.decommission_key()),
            p.margin_ratio_per_thousand().into_percentage_str(),
            fmt_ml(&p.cost_per_block())
        )
    };
    let fmt_tkn_supply = |s: &TokenTotalSupply, d: u8| match s {
        TokenTotalSupply::Fixed(v) => format!("Fixed({})", v.into_fixedpoint_str(d)),
        TokenTotalSupply::Lockable => "Lockable".to_string(),
        TokenTotalSupply::Unlimited => "Unlimited".to_string(),
    };
    let fmt_tkn_frzble = |f: &IsTokenFreezable| match f {
        IsTokenFreezable::No => "Yes".to_string(),
        IsTokenFreezable::Yes => "No".to_string(),
    };
    let fmt_tkn_iss = |iss: &TokenIssuance| {
        match iss {
        TokenIssuance::V1(iss1) => format!(
            "TokenIssuance(Ticker({}), Decimals({}), MetadataUri({}), TotalSupply({}), Authority({}), IsFreezable({}))",
            String::from_utf8_lossy(&iss1.token_ticker),
            iss1.number_of_decimals,
            String::from_utf8_lossy(&iss1.metadata_uri),
            fmt_tkn_supply(&iss1.total_supply, iss1.number_of_decimals),
            fmt_dest(&iss1.authority),
            fmt_tkn_frzble(&iss1.is_freezable)
        ),
    }
    };
    let fmt_nft_iss = |iss: &NftIssuance| match iss {
        NftIssuance::V0(iss1) => {
            let md = &iss1.metadata;
            let creator = match &md.creator {
                Some(c) => hex::encode(c.public_key.encode()).to_string(),
                None => "Unspecified".to_string(),
            };
            format!(
                "Create({}), Name({}), Description({}), Ticker({}), IconUri({}), AdditionalMetaData({}), MediaUri({}), MediaHash(0x{})",
                creator,
                String::from_utf8_lossy(&md.name),
                String::from_utf8_lossy(&md.description),
                String::from_utf8_lossy(&md.ticker),
                String::from_utf8_lossy(md.icon_uri.as_ref().as_ref().unwrap_or(&vec![])),
                String::from_utf8_lossy(
                    md.additional_metadata_uri.as_ref().as_ref().unwrap_or(&vec![])
                ),
                String::from_utf8_lossy(
                    md.media_uri.as_ref().as_ref().unwrap_or(&vec![])
                ),
                hex::encode(&md.media_hash),

            )
        }
    };

    for input in tx.inputs() {
        writeln!(&mut result, "- {input:?}").expect("Writing to a memory buffer should not fail");
    }

    writeln!(
        &mut result,
        "=== END OF INPUTS ===\n=== BEGIN OF OUTPUTS ==="
    )
    .expect("Writing to a memory buffer should not fail");

    for output in tx.outputs() {
        let s = match output {
            TxOutput::Transfer(val, dest) => {
                let val_str = fmt_val(val);
                format!("Transfer({}, {val_str})", fmt_dest(dest))
            }
            TxOutput::LockThenTransfer(val, dest, timelock) => {
                let val_str = fmt_val(val);
                format!(
                    "LockThenTransfer({}, {val_str}, {})",
                    fmt_dest(dest),
                    fmt_timelock(timelock)
                )
            }
            TxOutput::Burn(val) => fmt_val(val),
            TxOutput::CreateStakePool(id, data) => {
                format!(
                    "CreateStakePool(Id({}), {})",
                    fmt_poolid(id),
                    fmt_stakepooldata(data)
                )
            }
            TxOutput::ProduceBlockFromStake(dest, pool_id) => {
                format!(
                    "ProduceBlockFromStake({}, {})",
                    fmt_dest(dest),
                    fmt_poolid(pool_id)
                )
            }
            TxOutput::CreateDelegationId(owner, pool_id) => {
                format!(
                    "CreateDelegationId(Owner({}), StakingPool({}))",
                    fmt_dest(owner),
                    fmt_poolid(pool_id)
                )
            }
            TxOutput::DelegateStaking(amount, del_ig) => {
                format!(
                    "DelegateStaking(Owner({}), StakingPool({}))",
                    fmt_ml(amount),
                    fmt_delid(del_ig)
                )
            }
            TxOutput::IssueFungibleToken(issuance) => {
                format!("IssueFungibleToken({})", fmt_tkn_iss(issuance))
            }
            TxOutput::IssueNft(token_id, iss, receiver) => {
                format!(
                    "IssueNft(Id({}), NftIssuance({}), Receiver({}))",
                    fmt_tknid(token_id),
                    fmt_nft_iss(iss),
                    fmt_dest(receiver)
                )
            }
            TxOutput::DataDeposit(data) => {
                format!("DataDeposit(0x{})", hex::encode(data))
            }
        };
        writeln!(&mut result, "- {s}").expect("Writing to a memory buffer should not fail");
    }
    writeln!(&mut result, "=== END OF OUTPUTS ===")
        .expect("Writing to a memory buffer should not fail");

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        address::Address,
        chain::{
            block::timestamp::BlockTimestamp,
            config::create_mainnet,
            output_value::OutputValue,
            stakelock::StakePoolData,
            timelock::OutputTimeLock,
            tokens::{
                IsTokenFreezable, Metadata, NftIssuance, NftIssuanceV0, TokenCreator, TokenId,
                TokenIssuance, TokenIssuanceV1, TokenTotalSupply,
            },
            DelegationId, Destination, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput,
            UtxoOutPoint,
        },
        primitives::{per_thousand::PerThousand, Amount, Id, H256},
        time_getter::TimeGetter,
    };
    use crypto::{
        key::{KeyKind, PrivateKey},
        vrf::{VRFKeyKind, VRFPrivateKey},
    };
    use serialization::extras::non_empty_vec::DataOrNoVec;

    // This test is made so that the data can be viewed for evaluation purposes
    #[test]
    fn try_it_out() {
        let cfg = create_mainnet();

        let (_vrf_priv_key, vrf_pub_key) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let (_priv_key, pub_key) = PrivateKey::new_from_entropy(KeyKind::Secp256k1Schnorr);

        let outputs = [
            TxOutput::Burn(OutputValue::Coin(
                Amount::from_fixedpoint_str("10.123", 11).unwrap(),
            )),
            TxOutput::Burn(OutputValue::TokenV1(
                TokenId::zero(),
                Amount::from_fixedpoint_str("15.221", 11).unwrap(),
            )),
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_str(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .decode_object(&cfg)
                    .unwrap(),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_str(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .decode_object(&cfg)
                    .unwrap(),
                OutputTimeLock::ForBlockCount(10),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_str(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .decode_object(&cfg)
                    .unwrap(),
                OutputTimeLock::ForSeconds(2000),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_str(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .decode_object(&cfg)
                    .unwrap(),
                OutputTimeLock::UntilHeight(1000.into()),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_str(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .decode_object(&cfg)
                    .unwrap(),
                OutputTimeLock::UntilTime(BlockTimestamp::from_time(
                    TimeGetter::default().get_time(),
                )),
            ),
            TxOutput::CreateStakePool(
                PoolId::new(H256::random()),
                Box::new(StakePoolData::new(
                    Amount::from_fixedpoint_str("1000.225", 11).unwrap(),
                    Destination::AnyoneCanSpend,
                    vrf_pub_key,
                    Destination::AnyoneCanSpend,
                    PerThousand::new(15).unwrap(),
                    Amount::from_fixedpoint_str("5.2", 11).unwrap(),
                )),
            ),
            TxOutput::ProduceBlockFromStake(
                Destination::AnyoneCanSpend,
                PoolId::new(H256::random()),
            ),
            TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, PoolId::new(H256::random())),
            TxOutput::DelegateStaking(
                Amount::from_fixedpoint_str("1.2", 11).unwrap(),
                DelegationId::new(H256::random()),
            ),
            TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: "abc".to_owned().into_bytes(),
                number_of_decimals: 5,
                metadata_uri: "http://xyz.xyz".to_owned().into_bytes(),
                total_supply: TokenTotalSupply::Fixed(
                    Amount::from_fixedpoint_str("1000000", 5).unwrap(),
                ),
                authority: Destination::AnyoneCanSpend,
                is_freezable: IsTokenFreezable::No,
            }))),
            TxOutput::IssueNft(
                TokenId::new(H256::random()),
                Box::new(NftIssuance::V0(NftIssuanceV0 {
                    metadata: Metadata {
                        creator: Some(TokenCreator {
                            public_key: pub_key,
                        }),
                        name: "MyGreatNFT".to_string().into_bytes(),
                        description: "NFTDescription".to_string().into_bytes(),
                        ticker: "abc".to_owned().into_bytes(),
                        icon_uri: DataOrNoVec::from(Some(
                            "http://icon.com".to_string().into_bytes(),
                        )),
                        additional_metadata_uri: DataOrNoVec::from(Some(
                            "http://uri.com".to_string().into_bytes(),
                        )),
                        media_uri: DataOrNoVec::from(Some(
                            "http://media.com".to_string().into_bytes(),
                        )),
                        media_hash: H256::random().as_bytes().to_vec(),
                    },
                })),
                Destination::AnyoneCanSpend,
            ),
            TxOutput::DataDeposit("DataToDeposit!".to_string().into_bytes()),
        ];

        let tx = Transaction::new(
            0,
            [
                TxInput::Utxo(UtxoOutPoint::new(
                    OutPointSourceId::Transaction(Id::new(H256::random())),
                    2,
                )),
                TxInput::Utxo(UtxoOutPoint::new(
                    OutPointSourceId::Transaction(Id::new(H256::random())),
                    1,
                )),
            ]
            .to_vec(),
            outputs.to_vec(),
        )
        .unwrap();

        println!("{}", transaction_summary(&tx, &cfg));
    }
}
