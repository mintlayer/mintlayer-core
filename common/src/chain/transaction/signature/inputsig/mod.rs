// Copyright (c) 2021-2022 RBB S.r.l
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

pub mod arbitrary_message;
pub mod authorize_hashed_timelock_contract_spend;
pub mod authorize_pubkey_spend;
pub mod authorize_pubkeyhash_spend;
pub mod classical_multisig;
pub mod htlc;
pub mod standard_signature;

use strum::EnumDiscriminants;

use serialization::{Decode, Encode};
use standard_signature::StandardInputSignature;

use super::{DestinationSigError, Signable};

#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd, EnumDiscriminants)]
#[strum_discriminants(name(InputWitnessTag))]
pub enum InputWitness {
    #[codec(index = 0)]
    NoSignature(Option<Vec<u8>>),
    #[codec(index = 1)]
    Standard(StandardInputSignature),
}
