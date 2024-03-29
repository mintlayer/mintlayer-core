// Copyright (c) 2023 RBB S.r.l
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

use common::{
    chain::{classic_multisig::ClassicMultisigChallenge, ChainConfig, Destination, GenBlock},
    primitives::{BlockHeight, Id},
};
use crypto::{
    key::{extended::ExtendedPublicKey, hdkd::u31::U31, PrivateKey},
    vrf::ExtendedVRFPublicKey,
};
use rpc_description::HasValueHint;
use serialization::{Decode, Encode};

pub const DEFAULT_ACCOUNT_INDEX: U31 = match U31::from_u32(0) {
    Some(v) => v,
    None => unreachable!(),
};

/// Serialized data for deterministic accounts. The fields are documented in `AccountKeyChain`.
/// Account metadata that contains information like from which master key it was derived from
// TODO tbd what metadata we need to store
#[derive(Debug, Clone, Encode, Decode)]
pub struct AccountInfo {
    account_index: U31,
    account_key: ExtendedPublicKey,
    lookahead_size: u32,
    best_block_height: BlockHeight,
    best_block_id: Id<GenBlock>,
    name: Option<String>,
}

impl AccountInfo {
    pub fn new(
        chain_config: &ChainConfig,
        account_index: U31,
        account_key: ExtendedPublicKey,
        lookahead_size: u32,
        name: Option<String>,
    ) -> Self {
        Self {
            account_index,
            account_key,
            lookahead_size,
            best_block_height: BlockHeight::zero(),
            best_block_id: chain_config.genesis_block_id(),
            name,
        }
    }

    pub fn account_index(&self) -> U31 {
        self.account_index
    }

    pub fn account_key(&self) -> &ExtendedPublicKey {
        &self.account_key
    }

    pub fn lookahead_size(&self) -> u32 {
        self.lookahead_size
    }

    pub fn set_lookahead_size(&mut self, lookahead_size: u32) {
        self.lookahead_size = lookahead_size
    }

    pub fn best_block_height(&self) -> BlockHeight {
        self.best_block_height
    }

    pub fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_id
    }

    pub fn name(&self) -> &Option<String> {
        &self.name
    }

    pub fn set_name(&mut self, new_name: Option<String>) {
        self.name = new_name;
    }

    pub fn update_best_block(
        &mut self,
        best_block_height: BlockHeight,
        best_block_id: Id<GenBlock>,
    ) {
        self.best_block_height = best_block_height;
        self.best_block_id = best_block_id;
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct AccountVrfKeys {
    pub account_vrf_key: ExtendedVRFPublicKey,
    pub legacy_vrf_key: ExtendedVRFPublicKey,
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum AccountStandaloneKey {
    #[codec(index = 0)]
    Address {
        label: Option<String>,
        private_key: Option<PrivateKey>,
    },
    #[codec(index = 1)]
    Multisig {
        label: Option<String>,
        challenge: ClassicMultisigChallenge,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, HasValueHint)]
pub enum AccountStandaloneKeyType {
    PublicKey,
    PublicKeyHash,
    ScriptHash,
    ClassicMultisig,
    AnyoneCanSpend,
}

impl AccountStandaloneKeyType {
    pub fn new(dest: &Destination) -> Self {
        match dest {
            Destination::AnyoneCanSpend => Self::AnyoneCanSpend,
            Destination::PublicKey(_) => Self::PublicKey,
            Destination::PublicKeyHash(_) => Self::PublicKeyHash,
            Destination::ScriptHash(_) => Self::ScriptHash,
            Destination::ClassicMultisig(_) => Self::ClassicMultisig,
        }
    }
}

pub struct AccountStandaloneKeyInfo {
    pub address: Destination,
    pub address_type: AccountStandaloneKeyType,
    pub label: Option<String>,
}
