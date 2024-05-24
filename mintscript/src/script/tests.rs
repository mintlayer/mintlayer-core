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

use common::primitives::BlockHeight;

use super::*;

type WS = WitnessScript;

#[rstest::rstest]
#[case(0, 0, true)]
#[case(0, 1, true)]
#[case(1, 1, true)]
#[case(1, 7, true)]
#[case(7, 7, true)]
#[case(2, 1, false)]
#[case(13, 11, false)]
#[case(5, 0, false)]
fn threshold_construction(#[case] n: usize, #[case] k: usize, #[case] ok: bool) {
    let res = Threshold::new(n, vec![ScriptCondition::TRUE; k]);
    assert_eq!(res.is_ok(), ok);
    match res {
        Ok(thresh) => {
            assert_eq!(thresh.required(), n);
            assert_eq!(thresh.conditions().len(), k);
        }
        Err(ScriptConstructionError::InvalidThreshold(..)) => (),
    }
}

fn conj(conds: impl IntoIterator<Item = WS>) -> WS {
    WS::satisfied_conjunction(conds)
}

const fn tl(n: u64) -> WS {
    WS::timelock(OutputTimeLock::UntilHeight(BlockHeight::new(n)))
}

#[rstest::rstest]
#[case(conj([tl(1), tl(2), tl(3), tl(4)]))]
#[case(conj([tl(1), conj([tl(2), tl(3), tl(4)])]))]
#[case(conj([conj([tl(1)]), conj([tl(2), tl(3), tl(4)])]))]
#[case(conj([conj([tl(1), tl(2), tl(3)]), tl(4)]))]
#[case(conj([tl(1), conj([tl(2), conj([tl(3), tl(4)])])]))]
#[case(conj([conj([conj([conj([conj([conj([]), tl(1)])]), tl(2)]), tl(3)]), tl(4)]))]
#[case(conj([conj([tl(1), tl(2)]), tl(3), tl(4)]))]
#[case(conj([tl(1), tl(2), conj([tl(3), tl(4)])]))]
fn visit_order(#[case] script: WS) {
    #[derive(Default)]
    struct LockLogger(Vec<OutputTimeLock>);

    impl ScriptVisitor for LockLogger {
        type SignatureError = std::convert::Infallible;

        type TimelockError = std::convert::Infallible;

        fn visit_signature(
            &mut self,
            _destination: &Destination,
            _signature: &InputWitness,
        ) -> Result<(), Self::SignatureError> {
            unreachable!("Not used in this test")
        }

        fn visit_timelock(&mut self, lock: &OutputTimeLock) -> Result<(), Self::TimelockError> {
            self.0.push(lock.clone());
            Ok(())
        }
    }

    let mut logger = LockLogger::default();
    script.verify(&mut logger).unwrap();
    let expected = [1, 2, 3, 4].map(|n| OutputTimeLock::UntilHeight(BlockHeight::new(n)));
    assert_eq!(logger.0.as_slice(), expected.as_slice());
}

// TODO(PR) Evaluation tests
