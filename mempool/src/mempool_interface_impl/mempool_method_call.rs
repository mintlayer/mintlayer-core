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

use tokio::sync::oneshot;

use common::{
    chain::{signed_transaction::SignedTransaction, Transaction},
    primitives::Id,
};
use utils::eventhandler::EventHandler;

use crate::error::Error;
use crate::{tx_accumulator::TransactionAccumulator, MempoolEvent};

pub type MempoolEventHandler = EventHandler<MempoolEvent>;

pub enum MempoolMethodCall {
    AddTransaction {
        tx: SignedTransaction,
        rtx: oneshot::Sender<Result<(), Error>>,
    },
    GetAll {
        rtx: oneshot::Sender<Vec<SignedTransaction>>,
    },
    CollectTxs {
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
        rtx: oneshot::Sender<Box<dyn TransactionAccumulator>>,
    },
    ContainsTransaction {
        tx_id: Id<Transaction>,
        rtx: oneshot::Sender<bool>,
    },
    SubscribeToEvents {
        handler: MempoolEventHandler,
        rtx: oneshot::Sender<()>,
    },
}
