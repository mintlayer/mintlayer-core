// Copyright (c) 2021-2024 RBB S.r.l
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

use std::fmt::Display;

/// A trait that provides a reasonable way to print an `Option` via `Display`.
///
/// If the value is `Some(val)`, `val` will be printed directly; otherwise, `None` will be printed.
///
/// The trait is particularly useful for logging types like `Id`, whose `Display` representation
/// is much more compact than `Debug`.
pub trait DisplayableOption<T> {
    fn as_displayable(&self) -> DisplayableOptionWrapper<'_, T>;
}

pub struct DisplayableOptionWrapper<'a, T>(Option<&'a T>);

impl<T> DisplayableOption<T> for Option<T> {
    fn as_displayable(&self) -> DisplayableOptionWrapper<'_, T> {
        DisplayableOptionWrapper(self.as_ref())
    }
}

impl<T> Display for DisplayableOptionWrapper<'_, T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(val) = self.0 {
            write!(f, "{val}")
        } else {
            write!(f, "None")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::displayable_option::DisplayableOption;

    #[test]
    fn test() {
        let x = Some(123);
        assert_eq!(x.as_displayable().to_string(), "123");

        let x: Option<i32> = None;
        assert_eq!(x.as_displayable().to_string(), "None");
    }
}
