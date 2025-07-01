// Copyright (c) 2021-2025 RBB S.r.l
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

/// Same as `concat!`, but also adds "\n" to every line except the last one.
#[macro_export]
macro_rules! concatln {
    ($e:expr $(,)?) => { $e };
    ($e:expr, $($tail:expr),* $(,)?) => { concat!($e, "\n", concatln!($($tail),*)) };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_concatln() {
        let s = concatln!("a");
        assert_eq!(s, "a");

        let s = concatln!("a",);
        assert_eq!(s, "a");

        let s = concatln!("a", "b");
        assert_eq!(s, "a\nb");

        let s = concatln!("a", "b",);
        assert_eq!(s, "a\nb");

        let s = concatln!("a", "b", "c");
        assert_eq!(s, "a\nb\nc");

        let s = concatln!("a", "b", "c",);
        assert_eq!(s, "a\nb\nc");
    }
}
