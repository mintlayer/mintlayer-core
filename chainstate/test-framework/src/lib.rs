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
pub mod helpers;
mod key_manager;
mod pos_block_builder;
mod random_tx_maker;
mod signature_destination_getter;
mod staking_pools;
pub mod storage;
mod test_block_index_handle;
mod transaction_builder;
mod tx_verification_strategy;
mod utils;
mod utxo_for_spending;

/// Storage backend used for testing (the in-memory backend with simulated failures)
pub use storage::TestStore;

/// Chainstate instantiation for testing, using the in-memory storage backend
pub type TestChainstate = Box<dyn chainstate::chainstate_interface::ChainstateInterface>;

pub use {
    crate::utils::{
        anyonecanspend_address, calculate_new_pos_compact_target,
        create_chain_config_with_default_staking_pool, create_chain_config_with_staking_pool,
        create_custom_genesis_with_stake_pool, create_stake_pool_data_with_all_reward_to_staker,
        empty_witness, get_output_value, get_pos_target, output_value_amount, pos_mine,
        produce_kernel_signature,
    },
    block_builder::BlockBuilder,
    framework::TestFramework,
    framework_builder::{OrphanErrorHandler, TestFrameworkBuilder, TxVerificationStrategy},
    pos_block_builder::PoSBlockBuilder,
    test_block_index_handle::TestBlockIndexHandle,
    transaction_builder::TransactionBuilder,
    utxo_for_spending::UtxoForSpending,
};
