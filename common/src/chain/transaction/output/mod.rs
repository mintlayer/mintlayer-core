// Copyright (c) 2022 RBB S.r.l
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
    address::{
        hexified::HexifiedAddress, pubkeyhash::PublicKeyHash, traits::Addressable, Address,
        AddressError,
    },
    chain::{
        output_value::OutputValue,
        tokens::{IsTokenFreezable, NftIssuance, TokenId, TokenIssuance, TokenTotalSupply},
        ChainConfig, DelegationId, PoolId,
    },
    primitives::{Amount, Id},
    text_summary::TextSummary,
};
use crypto::vrf::VRFPublicKey;
use script::Script;
use serialization::{Decode, DecodeAll, Encode};
use variant_count::VariantCount;

use self::{stakelock::StakePoolData, timelock::OutputTimeLock};

pub mod classic_multisig;
pub mod output_value;
pub mod stakelock;
pub mod timelock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, VariantCount)]
pub enum Destination {
    #[codec(index = 0)]
    AnyoneCanSpend, // zero verification; used primarily for testing. Never use this for real money
    #[codec(index = 1)]
    PublicKeyHash(PublicKeyHash),
    #[codec(index = 2)]
    PublicKey(crypto::key::PublicKey),
    #[codec(index = 3)]
    ScriptHash(Id<Script>),
    #[codec(index = 4)]
    ClassicMultisig(PublicKeyHash),
}

impl serde::Serialize for Destination {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HexifiedAddress::serde_serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Destination {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HexifiedAddress::<Self>::serde_deserialize(deserializer)
    }
}

impl rpc_description::HasValueHint for Destination {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::BECH32_STRING;
}

impl Addressable for Destination {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.destination_address_prefix(self)
    }

    fn encode_to_bytes_for_address(&self) -> Vec<u8> {
        self.encode()
    }

    fn decode_from_bytes_from_address<T: AsRef<[u8]>>(address_bytes: T) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::decode_all(&mut address_bytes.as_ref())
            .map_err(|e| AddressError::DecodingError(e.to_string()))
    }

    fn json_wrapper_prefix() -> &'static str {
        "HexifiedDestination"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub enum TxOutput {
    /// Transfer an output, giving the provided Destination the authority to spend it (no conditions)
    #[codec(index = 0)]
    Transfer(OutputValue, Destination),
    /// Same as Transfer, but with the condition that an output can only be specified after some point in time.
    #[codec(index = 1)]
    LockThenTransfer(OutputValue, Destination, OutputTimeLock),
    /// Burn an amount (whether coin or token)
    #[codec(index = 2)]
    Burn(OutputValue),
    /// Output type that is used to create a stake pool
    #[codec(index = 3)]
    CreateStakePool(PoolId, Box<StakePoolData>),
    /// Output type that represents spending of a stake pool output in a block reward
    /// in order to produce a block
    #[codec(index = 4)]
    ProduceBlockFromStake(Destination, PoolId),
    /// Create a delegation; takes the owner destination (address authorized to withdraw from the delegation)
    /// and a pool id
    #[codec(index = 5)]
    CreateDelegationId(Destination, PoolId),
    /// Transfer an amount to a delegation that was previously created for staking
    #[codec(index = 6)]
    DelegateStaking(Amount, DelegationId),
    #[codec(index = 7)]
    IssueFungibleToken(Box<TokenIssuance>),
    #[codec(index = 8)]
    IssueNft(TokenId, Box<NftIssuance>, Destination),
    #[codec(index = 9)]
    DataDeposit(Vec<u8>),
}

impl TxOutput {
    pub fn timelock(&self) -> Option<&OutputTimeLock> {
        match self {
            TxOutput::Transfer(_, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => None,
            TxOutput::LockThenTransfer(_, _, tl) => Some(tl),
        }
    }
}

impl TextSummary for TxOutput {
    fn text_summary(&self, chain_config: &ChainConfig) -> String {
        let fmt_ml = |v: &Amount| v.into_fixedpoint_str(chain_config.coin_decimals());
        let fmt_val = |val: &OutputValue| {
            match val {
                OutputValue::Coin(amount) => fmt_ml(amount),
                OutputValue::TokenV0(token_data) => format!("{token_data:?}"), // Not important since it's deprecated
                OutputValue::TokenV1(id, amount) => {
                    format!(
                        "TokenV1({}, {amount:?})",
                        Address::new(chain_config, *id)
                            .expect("Cannot fail due to TokenId being fixed size")
                    )
                }
            }
        };
        let fmt_timelock = |tl: &OutputTimeLock| match tl {
            OutputTimeLock::UntilHeight(h) => format!("OutputTimeLock::UntilHeight({h})"),
            OutputTimeLock::UntilTime(t) => format!("OutputTimeLock::UntilTime({})", t.into_time()),
            OutputTimeLock::ForBlockCount(n) => {
                format!("OutputTimeLock::ForBlockCount({n} blocks)")
            }
            OutputTimeLock::ForSeconds(secs) => {
                format!("OutputTimeLock::ForSeconds({secs} seconds)")
            }
        };
        let fmt_dest = |d: &Destination| {
            Address::new(chain_config, d.clone()).expect("addressable").into_string()
        };
        let fmt_vrf = |k: &VRFPublicKey| {
            Address::new(chain_config, k.clone()).expect("addressable").into_string()
        };
        let fmt_poolid = |id: &PoolId| {
            Address::new(chain_config, *id).expect("Cannot fail because fixed size addressable")
        };
        let fmt_tknid = |id: &TokenId| {
            Address::new(chain_config, *id).expect("Cannot fail because fixed size addressable")
        };
        let fmt_delid = |id: &DelegationId| {
            Address::new(chain_config, *id).expect("Cannot fail because fixed size addressable")
        };
        let fmt_stakepooldata = |p: &StakePoolData| {
            let pledge = fmt_ml(&p.pledge());
            format!(
                "Pledge({pledge}), Staker({}), VRFPubKey({}), DecommissionKey({}), MarginRatio({}), CostPerBlock({})",
                fmt_dest(p.staker()),
                fmt_vrf(p.vrf_public_key()),
                fmt_dest(p.decommission_key()),
                p.margin_ratio_per_thousand().to_percentage_str(),
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

        match self {
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
            TxOutput::Burn(val) => format!("Burn({})", fmt_val(val)),
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
        }
    }
}

impl rpc_description::HasValueHint for TxOutput {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
}
