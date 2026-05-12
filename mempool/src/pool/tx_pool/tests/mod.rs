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
    config::*,
    pool::{
        OrphanType, TxOptions, TxOrigin, TxStatus,
        tx_pool::{memory_usage_estimator::StoreMemoryUsageEstimator, *},
    },
};

use ::utils::atomics::SeqCstAtomicU64;
use chainstate::{
    BlockSource, ChainstateConfig, DefaultTransactionVerificationStrategy, MaxTipAge,
    make_chainstate,
};
use common::{
    chain::{
        OutPointSourceId, Transaction, UtxoOutPoint,
        block::{Block, BlockReward, ConsensusData, timestamp::BlockTimestamp},
        config::ChainConfig,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        transaction::{Destination, TxInput, TxOutput},
    },
    primitives::{Id, Idable},
};
use serialization::Encode;

use std::{collections::BTreeMap, ops::Deref, sync::Arc};

mod accumulator;
mod basic;
mod expiry;
mod reorg;
mod replacement;
pub mod utils;

use self::utils::*;
