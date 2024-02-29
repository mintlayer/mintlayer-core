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

mod display;
mod value_hint;

pub use value_hint::{HasValueHint, ValueHint};

/// Type that has RPC interface description associated with it
pub trait Described {
    /// Description for given RPC interface marker
    const DESCRIPTION: Module;
}

/// Description of the whole RPC interface (a sequence of [Module]s)
#[derive(PartialEq, Eq, Debug)]
pub struct Interface {
    modules: Vec<Module>,
}

impl FromIterator<Module> for Interface {
    fn from_iter<T: IntoIterator<Item = Module>>(iter: T) -> Self {
        let modules = iter.into_iter().collect();
        Self { modules }
    }
}

/// Description of an RPC module
#[derive(PartialEq, Eq, Debug)]
pub struct Module {
    pub name: &'static str,
    pub description: &'static str,
    pub methods: &'static [Method],
}

/// Description of an RPC method
#[derive(PartialEq, Eq, Debug)]
pub struct Method {
    pub name: &'static str,
    pub description: &'static str,
    pub params: ValueHint,
    pub kind_data: MethodKindData,
}

/// Kind-specific method data
#[derive(PartialEq, Eq, Debug)]
pub enum MethodKindData {
    /// Regular method
    Method {
        /// Method return type
        return_type: ValueHint,
    },

    /// Subscription
    Subscription {
        /// Method name to cancel the event subscription
        unsubscribe_name: &'static str,

        /// Type of items that the subscription produces
        item_type: ValueHint,
    },
}
