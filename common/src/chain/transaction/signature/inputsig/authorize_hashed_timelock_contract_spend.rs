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

use strum::EnumDiscriminants;

use serialization::{Decode, DecodeAll, Encode};

use crate::chain::{htlc::HtlcSecret, signature::DestinationSigError};

#[derive(Debug, Encode, Decode, PartialEq, Eq, EnumDiscriminants)]
#[strum_discriminants(name(AuthorizedHashedTimelockContractSpendTag))]
pub enum AuthorizedHashedTimelockContractSpend {
    Secret(HtlcSecret, Vec<u8>),
    Multisig(Vec<u8>),
}

impl AuthorizedHashedTimelockContractSpend {
    pub fn from_data(data: &[u8]) -> Result<Self, DestinationSigError> {
        let decoded = AuthorizedHashedTimelockContractSpend::decode_all(&mut &data[..])
            .map_err(|_| DestinationSigError::InvalidSignatureEncoding)?;
        Ok(decoded)
    }
}
