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

#![allow(clippy::unwrap_used)]

mod block_builder;
mod framework;
mod framework_builder;
mod pos_block_builder;
mod random_tx_maker;
mod staking_pools;
mod transaction_builder;
mod tx_verification_strategy;
mod utils;

/// Storage backend used for testing (the in-memory backend)
pub type TestStore = chainstate_storage::inmemory::Store;

/// Chainstate instantiation for testing, using the in-memory storage backend
pub type TestChainstate = Box<dyn chainstate::chainstate_interface::ChainstateInterface>;

pub use {
    crate::utils::{
        anyonecanspend_address, create_chain_config_with_default_staking_pool,
        create_chain_config_with_staking_pool, empty_witness, get_output_value, pos_mine,
        produce_kernel_signature,
    },
    block_builder::BlockBuilder,
    framework::TestFramework,
    framework_builder::{OrphanErrorHandler, TestFrameworkBuilder, TxVerificationStrategy},
    transaction_builder::TransactionBuilder,
};
