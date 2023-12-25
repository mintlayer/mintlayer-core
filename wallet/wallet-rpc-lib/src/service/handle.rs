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

//! Handle used to control the wallet service

use futures::future::{BoxFuture, Future};

use utils::shallow_clone::ShallowClone;

use super::worker::{self, WalletCommand, WalletController};

/// Wallet handle allows the user to control the wallet service, perform queries etc.
#[derive(Clone)]
pub struct WalletHandle(worker::CommandSender);

impl WalletHandle {
    pub(super) fn new(sender: worker::CommandSender) -> Self {
        Self(sender)
    }

    pub fn call_async<R: Send + 'static>(
        &self,
        action: impl FnOnce(&mut WalletController) -> BoxFuture<R> + Send + 'static,
    ) -> impl Future<Output = Result<R, SubmitError>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let command = WalletCommand::Call(Box::new(move |controller| {
            Box::pin(async move {
                let _ = tx.send(action(controller).await);
            })
        }));

        let send_result = self.send_raw(command);

        async {
            send_result?;
            rx.await.map_err(|_| SubmitError::Recv)
        }
    }

    pub fn call<R: Send + 'static>(
        &self,
        action: impl FnOnce(&mut WalletController) -> R + Send + 'static,
    ) -> impl Future<Output = Result<R, SubmitError>> {
        self.call_async(|controller| {
            let res = action(controller);
            Box::pin(std::future::ready(res))
        })
    }

    pub fn stop(self) -> Result<(), SubmitError> {
        self.send_raw(WalletCommand::Stop)
    }

    pub fn is_running(&self) -> bool {
        !self.0.is_closed()
    }

    fn send_raw(&self, cmd: WalletCommand) -> Result<(), SubmitError> {
        self.0.send(cmd).map_err(|_| SubmitError::Send)
    }
}

impl ShallowClone for WalletHandle {
    fn shallow_clone(&self) -> Self {
        Self(worker::CommandSender::clone(&self.0))
    }
}

/// Error that can occur during wallet request submission or reply reception
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SubmitError {
    #[error("Cannot send request")]
    Send,

    #[error("Cannot receive response")]
    Recv,
}