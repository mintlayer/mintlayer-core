// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{cmp::Reverse, collections::BinaryHeap, time::Duration};

use common::{
    chain::Transaction,
    primitives::{Id, H256},
    time_getter::TimeGetter,
};

use crate::Result;

pub struct PendingTransactions {
    time_getter: TimeGetter,
    txs: BinaryHeap<Reverse<(Duration, Id<Transaction>)>>,
}

impl PendingTransactions {
    pub fn new(time_getter: TimeGetter) -> Self {
        Self {
            time_getter,
            txs: Default::default(),
        }
    }

    pub fn push(&mut self, tx: Id<Transaction>, due_time: Duration) {
        self.txs.push(Reverse((due_time, tx)));
    }

    pub async fn due(&mut self) -> Result<Id<Transaction>> {
        if self.txs.is_empty() {
            std::future::pending::<()>().await;
            Ok(Id::<Transaction>::new(H256::zero())) // unreachable
        } else {
            let now = self.time_getter.get_time().as_duration_since_epoch();
            let (due, _) = self.txs.peek().expect("cannot be empty").0;
            if now < due {
                tokio::time::sleep(due - now).await;
            }

            let (_, tx) = self.txs.pop().expect("cannot be empty").0;
            Ok(tx)
        }
    }
}
