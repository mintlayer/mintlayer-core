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

use crate::{
    chain::ChainConfig,
    primitives::{Idable, H256},
    text_summary::TextSummary,
};

use super::Transaction;
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

    for input in tx.inputs() {
        let s = input.text_summary(chain_config);
        writeln!(&mut result, "- {s}").expect("Writing to a memory buffer should not fail");
    }

    writeln!(
        &mut result,
        "=== END OF INPUTS ===\n=== BEGIN OF OUTPUTS ==="
    )
    .expect("Writing to a memory buffer should not fail");

    for output in tx.outputs() {
        let s = output.text_summary(chain_config);
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
            AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, DelegationId,
            Destination, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
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
                Address::from_string(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .into_object(),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_string(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .into_object(),
                OutputTimeLock::ForBlockCount(10),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_string(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .into_object(),
                OutputTimeLock::ForSeconds(2000),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_string(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .into_object(),
                OutputTimeLock::UntilHeight(1000.into()),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_fixedpoint_str("123.15", 11).unwrap()),
                Address::from_string(&cfg, "mtc1q9d860uag5swe78ac9c2lct9mkctfyftqvwj3ypa")
                    .unwrap()
                    .into_object(),
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
                TxInput::Utxo(UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(Id::new(H256::random())),
                    1,
                )),
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(15),
                    AccountSpending::DelegationBalance(
                        Id::new(H256::random()),
                        Amount::from_atoms(100000),
                    ),
                )),
                TxInput::AccountCommand(
                    AccountNonce::new(25),
                    AccountCommand::MintTokens(Id::new(H256::random()), Amount::from_atoms(100000)),
                ),
            ]
            .to_vec(),
            outputs.to_vec(),
        )
        .unwrap();

        println!("{}", transaction_summary(&tx, &cfg));
    }
}
