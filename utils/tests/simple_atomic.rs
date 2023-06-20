// Copyright (c) 2023 RBB S.r.l
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

use utils::{atomics::RelaxedAtomicU32, concurrency};

// Here we have simple tests that basically check that the correct function of the wrapped
// type is called by each function of the "Atomic" wrapper.
// Note that this will also indirectly check the correctness of implementation of "Atomic"
// traits, which are used by the wrapper.

#[test]
fn test_load_store_swap() {
    concurrency::model(|| {
        let a = RelaxedAtomicU32::new(1);
        assert_eq!(a.load(), 1);

        a.store(2);
        assert_eq!(a.load(), 2);

        assert_eq!(a.swap(3), 2);
        assert_eq!(a.load(), 3);
    });
}

#[test]
fn test_compare_exchange() {
    concurrency::model(|| {
        let a = RelaxedAtomicU32::new(1);

        assert_eq!(a.compare_exchange(2, 1), Err(1));
        assert_eq!(a.load(), 1);

        assert_eq!(a.compare_exchange(1, 2), Ok(1));
        assert_eq!(a.load(), 2);
    });
}

#[test]
fn test_compare_exchange_weak() {
    concurrency::model(|| {
        let a = RelaxedAtomicU32::new(1);

        assert_eq!(a.compare_exchange_weak(2, 1), Err(1));
        assert_eq!(a.load(), 1);

        let result = a.compare_exchange_weak(1, 2);
        assert!(result == Ok(1) || result == Err(1));
    });
}

#[test]
fn test_fetch_update() {
    concurrency::model(|| {
        let a = RelaxedAtomicU32::new(1);

        assert_eq!(
            a.fetch_update(|x| {
                assert_eq!(x, 1);
                None
            }),
            Err(1)
        );
        assert_eq!(a.load(), 1);

        assert_eq!(
            a.fetch_update(|x| {
                assert_eq!(x, 1);
                Some(2)
            }),
            Ok(1)
        );
        assert_eq!(a.load(), 2);
    });
}

#[test]
fn test_bit_ops() {
    concurrency::model(|| {
        let a = RelaxedAtomicU32::new(0b1100);
        assert_eq!(a.fetch_and(0b1010), 0b1100);
        assert_eq!(a.load(), 0b1000);

        a.store(0b1100);
        assert_eq!(a.fetch_nand(0b1010), 0b1100);
        assert_eq!(a.load(), 0b11111111_11111111_11111111_11110111);

        a.store(0b1100);
        assert_eq!(a.fetch_or(0b1010), 0b1100);
        assert_eq!(a.load(), 0b1110);

        a.store(0b1100);
        assert_eq!(a.fetch_xor(0b1010), 0b1100);
        assert_eq!(a.load(), 0b0110);
    });
}

#[test]
fn test_num_ops() {
    concurrency::model(|| {
        let a = RelaxedAtomicU32::new(10);

        assert_eq!(a.fetch_add(20), 10);
        assert_eq!(a.load(), 30);

        assert_eq!(a.fetch_sub(20), 30);
        assert_eq!(a.load(), 10);

        assert_eq!(a.fetch_max(100), 10);
        assert_eq!(a.load(), 100);
        assert_eq!(a.fetch_max(10), 100);
        assert_eq!(a.load(), 100);

        assert_eq!(a.fetch_min(10), 100);
        assert_eq!(a.load(), 10);
        assert_eq!(a.fetch_min(100), 10);
        assert_eq!(a.load(), 10);
    });
}

#[test]
fn test_default_debug_from() {
    concurrency::model(|| {
        let a = <RelaxedAtomicU32 as Default>::default();
        assert_eq!(a.load(), 0);

        let a: RelaxedAtomicU32 = 123.into();
        assert_eq!(a.load(), 123);

        assert_eq!(format!("{a:?}"), "123");
    });
}
