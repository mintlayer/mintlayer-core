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

use std::ops::RangeInclusive;

use super::*;

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
    if let Ok(thresh) = res {
        assert_eq!(thresh.required(), n);
        assert_eq!(thresh.conditions().len(), k);
    }
}

fn conj(conds: impl IntoIterator<Item = WS>) -> WS {
    WS::satisfied_conjunction(conds)
}

const fn tl(n: u64) -> WS {
    WS::timelock(tl_until_height(n))
}

fn generate_conds(rng: &mut impl Rng, n_sat: usize, n_dissat: usize) -> Vec<ScriptCondition> {
    let mut conds = vec![ScriptCondition::TRUE; n_sat];
    conds.extend(vec![ScriptCondition::FALSE; n_dissat]);
    conds.shuffle(rng);
    conds
}

#[rstest::rstest]
#[case(Seed::from_entropy(), 0..=0, 0..=0)]
#[case(Seed::from_entropy(), 0..=0, 1..=1)]
#[case(Seed::from_entropy(), 1..=1, 0..=0)]
#[case(Seed::from_entropy(), 1..=1, 1..=1)]
#[trace]
#[case(Seed::from_entropy(), 2..=100, 2..=100)]
fn threshold_collect_satisfied(
    #[case] seed: Seed,
    #[case] sat_range: RangeInclusive<usize>,
    #[case] dissat_range: RangeInclusive<usize>,
) {
    let mut rng = make_seedable_rng(seed);
    let n_sat = rng.gen_range(sat_range);
    let n_dissat = rng.gen_range(dissat_range);
    let conds = generate_conds(&mut rng, n_sat, n_dissat);

    {
        let thresh = Threshold::new(n_sat, conds.clone()).unwrap();
        assert_eq!(
            thresh.collect_satisfied(),
            Ok(vec![&WitnessScript::TRUE; n_sat])
        );
    }

    if n_sat > 0 {
        let thresh = Threshold::new(rng.gen_range(0..n_sat), conds.clone()).unwrap();
        assert_eq!(thresh.collect_satisfied(), Err(ThresholdError::Excessive));
    }

    if n_dissat > 0 {
        let required = rng.gen_range((n_sat + 1)..=conds.len());
        let thresh = Threshold::new(required, conds.clone()).unwrap();
        assert_eq!(
            thresh.collect_satisfied(),
            Err(ThresholdError::Insufficient)
        );
    }
}

#[rstest::rstest]
#[trace]
#[case::zero(Seed::from_entropy(), 0..=0)]
#[case::unit(Seed::from_entropy(), 1..=1)]
#[case::rand(Seed::from_entropy(), 2..=100)]
fn conjunction_matches_explicit(#[case] seed: Seed, #[case] size_range: RangeInclusive<usize>) {
    let mut rng = make_seedable_rng(seed);
    let n = rng.gen_range(size_range);

    let conds: Vec<_> = (0..n).map(|_| ScriptCondition::from_bool(rng.gen_bool(0.8))).collect();

    let thr_conj = WitnessScript::conjunction(conds.clone());
    let thr_expl = WitnessScript::threshold(n, conds).unwrap();
    assert_eq!(thr_conj, thr_expl);
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
            self.0.push(*lock);
            Ok(())
        }
    }

    let mut logger = LockLogger::default();
    script.verify(&mut logger).unwrap();
    let expected = [1, 2, 3, 4].map(tl_until_height);
    assert_eq!(logger.0.as_slice(), expected.as_slice());
}
