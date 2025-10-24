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

use crate::checker::HashlockError;

use super::*;

struct EmptyContext;

impl crate::SignatureContext for EmptyContext {
    type Tx = SignedTransaction;

    fn chain_config(&self) -> &ChainConfig {
        unreachable!()
    }

    fn transaction(&self) -> &Self::Tx {
        unreachable!()
    }

    fn input_commitments(&self) -> &[SighashInputCommitment<'_>] {
        unreachable!()
    }

    fn input_num(&self) -> usize {
        unreachable!()
    }
}

impl crate::TimelockContext for EmptyContext {
    type Error = std::convert::Infallible;

    fn spending_height(&self) -> BlockHeight {
        unreachable!()
    }

    fn spending_time(&self) -> BlockTimestamp {
        unreachable!()
    }

    fn source_height(&self) -> Result<BlockHeight, Self::Error> {
        unreachable!()
    }

    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        unreachable!()
    }
}

#[rstest::rstest]
#[case(
    "0ced88ff2bdba91614bf52b680d70f2266d57317dfc0472e83c580fc3a66354f",
    "57a48169b4e981fc91e98018bb9fcf671a7750d8"
)]
#[case(
    "d1f6b1e83354e413f0d91898a5db6c8d088e548dd28084d12c573dc55ead1771",
    "9d0682090f0d0e13191053c4f1554ea6ac4210b2"
)]
#[case(
    "d27163347156f35d4fa7ad69886252a2a3efa73dc42359cf8d7a7cb99edfa400",
    "58bfb1c5c3b7894b9fb06b3d185224c79bd8dd78"
)]
fn check_hashlock_160_ok(#[case] preimage: &str, #[case] hash: &str) {
    let hash = hex::decode(hash).unwrap().try_into().unwrap();
    let preimage = hex::decode(preimage).unwrap().try_into().unwrap();

    let script = WitnessScript::hashlock(HashChallenge::Hash160(hash), preimage);

    let context = EmptyContext;
    let mut checker = crate::ScriptChecker::full(context);
    script.verify(&mut checker).unwrap();
}

#[rstest::rstest]
#[case(Seed::from_entropy())]
fn check_hashlock_160_random_values_mismatch(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let preimage: [u8; 32] = std::array::from_fn(|_| rng.gen::<u8>());
    let hash: [u8; 20] = std::array::from_fn(|_| rng.gen::<u8>());

    let script = WitnessScript::hashlock(HashChallenge::Hash160(hash), preimage);

    let context = EmptyContext;
    let mut checker = crate::ScriptChecker::full(context);
    assert_eq!(
        script.verify(&mut checker).unwrap_err(),
        ScriptError::Hashlock(HashlockError::HashMismatch)
    );
}
