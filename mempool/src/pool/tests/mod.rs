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

use super::*;
use crate::config::*;
use utils::*;

use common::{
    chain::{
        output_value::OutputValue, signature::inputsig::InputWitness, Destination,
        OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable, H256},
};

mod basic;
mod orders_v1;
mod orphans;
mod utils;

#[ctor::ctor]
fn init() {
    logging::init_logging();
}
