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

use common::{
    chain::{
        AccountCommand, AccountOutPoint, ChainConfig, DelegationId, Destination, OutPointSourceId,
        PoolId, SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
        block::timestamp::BlockTimestamp,
        output_value::OutputValue,
        signature::{
            inputsig::{InputWitness, standard_signature::StandardInputSignature},
            sighash::{input_commitments::SighashInputCommitment, sighashtype::SigHashType},
        },
        timelock::OutputTimeLock,
        tokens::TokenId,
    },
    primitives::{Amount, BlockHeight, H256, Id},
};
use crypto::key::{KeyKind, PrivateKey, PublicKey};
use test_utils::random::{
    CryptoRng, RngExt as _, Seed, TestRng, make_seedable_rng, randomness::SliceRandom,
};
use utxo::{Utxo, UtxoSource};

use crate::script::*;
use crate::translate::*;
use utils::*;

type WS = WitnessScript;

mod utils;

mod checkers;
mod hashlock_checker;
mod script;
mod translate;
