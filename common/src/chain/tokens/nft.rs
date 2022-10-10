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

use crypto::key::PublicKey;
use serialization::{extras::non_empty_vec::DataOrNoVec, Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct NftIssuanceV1 {
    pub metadata: Metadata,
    // TODO: Implement after additional research payout, royalty and refund.
    //       Payout might be Multisig contract with amount enforcement.
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TokenCreator {
    pub public_key: PublicKey,
}

impl From<PublicKey> for TokenCreator {
    fn from(public_key: PublicKey) -> Self {
        Self { public_key }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Metadata {
    // FIXME(nft_issuance): Can it be optional?
    pub creator: Option<TokenCreator>,
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub ticker: Vec<u8>,
    pub icon_uri: DataOrNoVec<u8>,
    pub additional_metadata_uri: DataOrNoVec<u8>,
    pub media_uri: DataOrNoVec<u8>,
    pub media_hash: Vec<u8>,
}

impl Metadata {
    pub fn creator(&self) -> &Option<TokenCreator> {
        &self.creator
    }

    pub fn name(&self) -> &Vec<u8> {
        &self.name
    }

    pub fn description(&self) -> &Vec<u8> {
        &self.description
    }

    pub fn ticker(&self) -> &Vec<u8> {
        &self.ticker
    }

    pub fn icon_uri(&self) -> &DataOrNoVec<u8> {
        &self.icon_uri
    }

    pub fn additional_metadata_uri(&self) -> &DataOrNoVec<u8> {
        &self.additional_metadata_uri
    }

    pub fn media_uri(&self) -> &DataOrNoVec<u8> {
        &self.media_uri
    }

    pub fn media_hash(&self) -> &Vec<u8> {
        &self.media_hash
    }
}
