// Copyright (c) 2021-2023 RBB S.r.l
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

use crate::primitives::merkle::proof::multi::is_sorted_and_unique;

#[test]
fn sorted_and_unique() {
    assert!(is_sorted_and_unique(&[]));
    assert!(is_sorted_and_unique(&[1]));
    assert!(is_sorted_and_unique(&[1, 2]));
    assert!(is_sorted_and_unique(&[1, 2, 5, 10]));
    assert!(is_sorted_and_unique(&[1, 2, 5, 10, 100]));

    assert!(!is_sorted_and_unique(&[1, 1]));
    assert!(!is_sorted_and_unique(&[2, 1]));
    assert!(!is_sorted_and_unique(&[1, 2, 5, 10, 100, 99]));
    assert!(!is_sorted_and_unique(&[2, 1, 2, 5, 10, 100]));
    assert!(!is_sorted_and_unique(&[1, 2, 5, 4, 10, 100]));
}
