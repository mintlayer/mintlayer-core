// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(unused)]

use crate::{
    error::{self, P2pError},
    event,
    message::MessageType,
    net::{self, NetworkService, PubSubService},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct PubSubManager<T>
where
    T: NetworkService,
{
    handle: T::PubSubHandle,
}

impl<T> PubSubManager<T>
where
    T: NetworkService,
    T::PubSubHandle: PubSubService<T>,
{
    pub fn new(handle: T::PubSubHandle) -> Self {
        Self { handle }
    }

    pub async fn on_floodsub_event(&mut self, event: net::PubSubEvent<T>) -> error::Result<()> {
        todo!();
    }

    pub async fn run(&mut self) -> error::Result<()> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
