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

// A helper struct that will call a function when it is dropped
#[must_use = "The value must be held in the scope"]
pub struct OnceDestructor<F: FnOnce()> {
    call_on_drop: Option<F>,
}

impl<F: FnOnce()> OnceDestructor<F> {
    pub fn new(call_on_drop: F) -> Self {
        Self { call_on_drop: Some(call_on_drop) }
    }
}

impl<F: FnOnce()> Drop for OnceDestructor<F> {
    fn drop(&mut self) {
        let mut finalizer: Option<F> = None;
        std::mem::swap(&mut finalizer, &mut self.call_on_drop);
        finalizer.expect("Must exist")();
    }
}
