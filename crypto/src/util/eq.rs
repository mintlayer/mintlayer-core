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

use std::ops::BitXor;

pub enum SliceEqualityCheckMethod {
    Normal,
    TimingResistant,
}

impl SliceEqualityCheckMethod {
    pub fn timing_resistant_equal<T: Eq + BitXor + Copy>(a: &[T], b: &[T]) -> bool
    where
        <T as BitXor>::Output: Into<usize>,
    {
        if b.is_empty() {
            return a.is_empty();
        }
        let accumulated = (0..a.len()).into_iter().fold(a.len() ^ b.len(), |accumulated, idx| {
            let step: usize = (a[idx] ^ b[idx % b.len()]).into();
            accumulated | step
        });
        accumulated == 0
    }

    pub fn is_equal<T: Eq + BitXor + Copy>(&self, a: &[T], b: &[T]) -> bool
    where
        <T as BitXor>::Output: Into<usize>,
    {
        match self {
            SliceEqualityCheckMethod::Normal => a == b,
            SliceEqualityCheckMethod::TimingResistant => Self::timing_resistant_equal(a, b),
        }
    }
}

#[cfg(test)]
pub mod test {
    use rstest::rstest;

    use crate::random::Rng;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    #[test]
    fn empty() {
        let normal = SliceEqualityCheckMethod::Normal;
        let timing_resistant = SliceEqualityCheckMethod::TimingResistant;

        let empty_slice1 = b"";
        let empty_slice2 = b"";
        assert_eq!(empty_slice1.len(), 0);
        assert_eq!(empty_slice2.len(), 0);
        assert!(normal.is_equal(empty_slice1, empty_slice2));
        assert!(timing_resistant.is_equal(empty_slice1, empty_slice2));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn with_data_unequal_size(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let normal = SliceEqualityCheckMethod::Normal;
        let timing_resistant = SliceEqualityCheckMethod::TimingResistant;

        let data1_len = rng.gen_range(1..256);
        let data3_len = rng.gen_range(1..256);

        let data1: Vec<u8> = (0..data1_len).map(|_| rng.gen::<u8>()).collect();
        let data2: Vec<u8> = data1.clone();
        let data3: Vec<u8> = (0..data3_len).map(|_| rng.gen::<u8>()).collect();
        assert_eq!(data1.len(), data1_len);
        assert_eq!(data2.len(), data1_len);
        assert_eq!(data3.len(), data3_len);

        assert!(normal.is_equal(&data1, &data2));
        assert!(timing_resistant.is_equal(&data1, &data2));

        assert!(!normal.is_equal(&data1, &data3));
        assert!(!timing_resistant.is_equal(&data1, &data3));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn with_data_equal_size(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let normal = SliceEqualityCheckMethod::Normal;
        let timing_resistant = SliceEqualityCheckMethod::TimingResistant;

        let data_len = rng.gen_range(1..256);

        let data1: Vec<u8> = (0..data_len).map(|_| rng.gen::<u8>()).collect();
        let data2: Vec<u8> = data1.clone();
        let data3: Vec<u8> = (0..data_len).map(|_| rng.gen::<u8>()).collect();
        assert_eq!(data1.len(), data_len);
        assert_eq!(data2.len(), data_len);
        assert_eq!(data3.len(), data_len);

        assert!(normal.is_equal(&data1, &data2));
        assert!(timing_resistant.is_equal(&data1, &data2));

        assert!(!normal.is_equal(&data1, &data3));
        assert!(!timing_resistant.is_equal(&data1, &data3));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn one_empty_other_not(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let normal = SliceEqualityCheckMethod::Normal;
        let timing_resistant = SliceEqualityCheckMethod::TimingResistant;

        let empty_slice = b"";
        let data_len = rng.gen_range(1..256);

        let data: Vec<u8> = (0..data_len).map(|_| rng.gen::<u8>()).collect();
        assert_eq!(data.len(), data_len);

        assert!(!normal.is_equal(empty_slice, &data));
        assert!(!normal.is_equal(&data, empty_slice));
        assert!(!timing_resistant.is_equal(empty_slice, &data));
        assert!(!timing_resistant.is_equal(&data, empty_slice));
    }
}
