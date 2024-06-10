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

    fn input_utxos(&self) -> &[Option<&common::chain::TxOutput>] {
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
#[case([209, 246, 177, 232, 51, 84, 228, 19, 240, 217, 24, 152, 165, 219, 108, 141, 8, 142, 84, 141, 210, 128, 132, 209, 44, 87, 61, 197, 94, 173, 23, 113],
       [157, 6, 130, 9, 15, 13, 14, 19, 25, 16, 83, 196, 241, 85, 78, 166, 172, 66, 16, 178])]
#[case([210, 113, 99, 52, 113, 86, 243, 93, 79, 167, 173, 105, 136, 98, 82, 162, 163, 239, 167, 61, 196, 35, 89, 207, 141, 122, 124, 185, 158, 223, 164, 0],
       [88, 191, 177, 197, 195, 183, 137, 75, 159, 176, 107, 61, 24, 82, 36, 199, 155, 216, 221, 120])]
#[case([12, 237, 136, 255, 43, 219, 169, 22, 20, 191, 82, 182, 128, 215, 15, 34, 102, 213, 115, 23, 223, 192, 71, 46, 131, 197, 128, 252, 58, 102, 53, 79],
       [87, 164, 129, 105, 180, 233, 129, 252, 145, 233, 128, 24, 187, 159, 207, 103, 26, 119, 80, 216])]
fn check_hashlock_160(#[case] preimage: [u8; 32], #[case] hash: [u8; 20]) {
    let script = WitnessScript::hashlock(HashType::HASH160, hash.to_vec(), preimage.to_vec());

    let context = EmptyContext;
    let mut checker = crate::ScriptChecker::full(context);
    script.verify(&mut checker).unwrap();
}

#[rstest::rstest]
#[case(Seed::from_entropy())]
fn check_hashlock_160_random_values(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let preimage: [u8; 32] = std::array::from_fn(|_| rng.gen::<u8>());
    let hash: [u8; 20] = std::array::from_fn(|_| rng.gen::<u8>());

    let script = WitnessScript::hashlock(HashType::HASH160, hash.to_vec(), preimage.to_vec());

    let context = EmptyContext;
    let mut checker = crate::ScriptChecker::full(context);
    assert_eq!(
        script.verify(&mut checker).unwrap_err(),
        ScriptError::Hashlock(HashlockError::HashMismatch)
    );
}

#[rstest::rstest]
#[case(Seed::from_entropy())]
fn check_hashlock_160_wrong_preimage_size(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let preimage: [u8; 32] = std::array::from_fn(|_| rng.gen::<u8>());
    let hash = {
        let length1: usize = rng.gen_range(1..20);
        let length2: usize = rng.gen_range(21..100);
        let length = if rng.gen::<bool>() { length1 } else { length2 };
        let random_vector: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
        random_vector
    };

    let script = WitnessScript::hashlock(HashType::HASH160, hash, preimage.to_vec());

    let context = EmptyContext;
    let mut checker = crate::ScriptChecker::full(context);
    assert_eq!(
        script.verify(&mut checker).unwrap_err(),
        ScriptError::Hashlock(HashlockError::IncorrectHashSize)
    );
}
