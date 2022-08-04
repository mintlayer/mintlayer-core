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

use serialization::{Decode, Encode, Tagged};

/// Version tag for SCALE-encoded values
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Encode, Decode, Copy, Clone, Tagged)]
pub struct VersionTag<const V: u8>(serialization::Tag<V>);

impl<const V: u8> Default for VersionTag<V> {
    fn default() -> Self {
        VersionTag(Default::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn version_encodes_to_correct_byte() {
        assert_eq!(VersionTag::<0>::default().encode(), vec![0]);
        assert_eq!(VersionTag::<1>::default().encode(), vec![1]);
        assert_eq!(VersionTag::<2>::default().encode(), vec![2]);
        assert_eq!(VersionTag::<42>::default().encode(), vec![42]);
        assert_eq!(VersionTag::<255>::default().encode(), vec![255]);
    }
}
