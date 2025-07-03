// Copyright (c) 2024-2025 RBB S.r.l
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

use parity_scale_codec::Encode;

use crate::{Amount, OutputValue, TxOutput};

#[derive(Encode)]
pub enum SighashInputCommitment {
    #[codec(index = 0)]
    None,

    #[codec(index = 1)]
    Utxo(TxOutput),

    #[codec(index = 2)]
    ProduceBlockFromStakeUtxo {
        utxo: TxOutput,
        staker_balance: Amount,
    },

    #[codec(index = 3)]
    FillOrderAccountCommand {
        initially_asked: OutputValue,
        initially_given: OutputValue,
    },

    #[codec(index = 4)]
    ConcludeOrderAccountCommand {
        initially_asked: OutputValue,
        initially_given: OutputValue,
        ask_balance: Amount,
        give_balance: Amount,
    },
}
