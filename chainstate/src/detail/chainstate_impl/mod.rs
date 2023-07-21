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

use crate::{BlockError, ChainstateEvent};
use ::utils::eventhandler::EventHandler;
use chainstate_storage::Transactional;

pub use block_invalidation::best_chain_candidates;
pub use block_processing::BlockSource;
pub use the_struct::Chainstate;

mod block_checking;
mod block_invalidation;
mod block_processing;
mod the_struct;
mod utils;

type TxRw<'a, S> = <S as Transactional<'a>>::TransactionRw;
type TxRo<'a, S> = <S as Transactional<'a>>::TransactionRo;
type ChainstateEventHandler = EventHandler<ChainstateEvent>;

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;
