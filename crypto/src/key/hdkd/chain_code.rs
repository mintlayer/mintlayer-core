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

use super::derivation_path::ChildNumber;

pub const CHAINCODE_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainCode([u8; 32]);

impl From<[u8; CHAINCODE_LENGTH]> for ChainCode {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}

impl From<ChainCode> for [u8; CHAINCODE_LENGTH] {
    fn from(cc: ChainCode) -> Self {
        cc.0
    }
}

impl From<ChildNumber> for ChainCode {
    fn from(num: ChildNumber) -> Self {
        let mut chaincode = ChainCode([0u8; CHAINCODE_LENGTH]);
        chaincode.0[0..4].copy_from_slice(&num.to_encoded_index().to_be_bytes());
        chaincode
    }
}
