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
        block::timestamp::BlockTimestamp,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        timelock::OutputTimeLock,
        ChainConfig, Destination, OutPointSourceId, SignedTransaction, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Amount, BlockHeight, Id},
};
use crypto::key::{KeyKind, PrivateKey, PublicKey};
use test_utils::random::{
    make_seedable_rng, randomness::SliceRandom, CryptoRng, Rng, Seed, TestRng,
};

use crate::script::*;
use utils::*;

type WS = WitnessScript;

mod utils;

mod checkers;
mod script;
mod translate;
