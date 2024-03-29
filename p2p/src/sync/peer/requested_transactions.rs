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

use std::{collections::BTreeMap, time::Duration};

use common::{
    chain::Transaction,
    primitives::{time::Time, Id},
    time_getter::TimeGetter,
};

/// A tx request will expire after this duration.
pub const REQUESTED_TX_EXPIRY_PERIOD: Duration = Duration::from_secs(60 * 60);
/// This specifies how often `RequestedTransactions` will check for expired tx requests.
pub const REQUESTED_TX_PURGE_INTERVAL: Duration = Duration::from_secs(5);

/// This struct tracks transactions that have been requested from a peer, but for which no
/// response has been received yet.
//
// TODO: ideally, this should be replaced with something similar to bitcoin's TxRequestTracker,
// which tracks tx requests across peers and allows to save bandwidth by requesting a tx
// only from one peer, see https://github.com/mintlayer/mintlayer-core/issues/829 for details.
pub struct RequestedTransactions {
    transactions: BTreeMap<Id<Transaction>, Time>,
    time_getter: TimeGetter,
    next_purge_time: Time,
}

impl RequestedTransactions {
    pub fn new(time_getter: TimeGetter) -> Self {
        let cur_time = time_getter.get_time();
        // Note: there is no sense in using a timeout less than REQUESTED_TX_EXPIRY_PERIOD for
        // the first purge interval, so we use that value instead of REQUESTED_TX_PURGE_INTERVAL
        // here.
        let next_purge_time =
            (cur_time + REQUESTED_TX_EXPIRY_PERIOD).expect("Bad current time or time offset");

        Self {
            transactions: BTreeMap::new(),
            time_getter,
            next_purge_time,
        }
    }

    pub fn add(&mut self, id: &Id<Transaction>) {
        let cur_time = self.time_getter.get_time();
        let old_val = self.transactions.insert(*id, cur_time);
        assert!(old_val.is_none());
    }

    pub fn remove(&mut self, id: &Id<Transaction>) -> Option<Time> {
        self.transactions.remove(id)
    }

    pub fn count(&self) -> usize {
        self.transactions.len()
    }

    pub fn contains(&self, id: &Id<Transaction>) -> bool {
        self.transactions.contains_key(id)
    }

    pub fn purge_if_needed(&mut self) {
        let cur_time = self.time_getter.get_time();

        if cur_time >= self.next_purge_time {
            let min_time =
                (cur_time - REQUESTED_TX_EXPIRY_PERIOD).expect("Bad time or time offset");

            // Note: this function is not supposed to be called often, so linear complexity is ok.
            self.transactions.retain(|_, time| *time >= min_time);

            self.next_purge_time =
                (cur_time + REQUESTED_TX_PURGE_INTERVAL).expect("Bad time or time offset");
        }
    }
}
