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
use wallet_controller::NodeInterface;

use crate::{
    service::worker::{self, WalletCommand, WalletController, WalletWorker},
    types::RpcError,
};

pub use crate::service::worker::EventStream;

/// Wallet handle allows the user to control the wallet service, perform queries etc.
#[derive(Clone)]
pub struct WalletHandle<N: Clone>(worker::CommandSender<N>);

impl<N> WalletHandle<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
    /// Asynchronous wallet service call
    pub fn call_async<R: Send + 'static, E: Into<RpcError<N>> + Send + 'static>(
        &self,
        action: impl FnOnce(&mut WalletController<N>) -> BoxFuture<Result<R, E>> + Send + 'static,
    ) -> impl Future<Output = Result<Result<R, RpcError<N>>, SubmitError>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let command = WalletCommand::Call(Box::new(move |opt_controller| match opt_controller {
            Some(controller) => Box::pin(async move {
                let _ = tx.send(action(controller).await.map_err(|e| e.into()));
            }),
            None => Box::pin(async move {
                let _ = tx.send(Err(RpcError::NoWalletOpened));
            }),
        }));

        let send_result = self.send_raw(command);

        async {
            send_result?;
            rx.await.map_err(|_| SubmitError::Recv)
        }
    }

    /// Wallet service call
    pub fn call<R: Send + 'static, E: Into<RpcError<N>> + Send + 'static>(
        &self,
        action: impl FnOnce(&mut WalletController<N>) -> Result<R, E> + Send + 'static,
    ) -> impl Future<Output = Result<Result<R, RpcError<N>>, SubmitError>> {
        self.call_async(|controller| {
            let res = action(controller);
            Box::pin(std::future::ready(res))
        })
    }

    pub fn manage_async<R: Send + 'static>(
        &self,
        action_fn: impl FnOnce(&mut WalletWorker<N>) -> BoxFuture<R> + Send + 'static,
    ) -> impl Future<Output = Result<R, SubmitError>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let command = WalletCommand::Manage(Box::new(move |wallet_manager| {
            Box::pin(async move {
                let _ = tx.send(action_fn(wallet_manager).await);
            })
        }));

        let send_result = self.send_raw(command);

        async {
            send_result?;
            rx.await.map_err(|_| SubmitError::Recv)
        }
    }

    /// Subscribe to wallet events
    pub async fn subscribe(&self) -> Result<EventStream, SubmitError> {
        self.manage_async(move |worker| Box::pin(async move { worker.subscribe() }))
            .await
    }

    /// Stop the wallet service
    pub fn stop(self) -> Result<(), SubmitError> {
        self.send_raw(WalletCommand::Stop)
    }

    /// Check if the wallet service is currently running
    pub fn is_running(&self) -> bool {
        !self.0.is_closed()
    }

    /// Completes when the receiver has dropped
    pub async fn closed(&self) {
        self.0.closed().await
    }

    fn send_raw(&self, cmd: WalletCommand<N>) -> Result<(), SubmitError> {
        self.0.send(cmd).map_err(|_| SubmitError::Send)
    }
}

pub fn create<N: Clone>(sender: worker::CommandSender<N>) -> WalletHandle<N> {
    WalletHandle(sender)
}

impl<N: Clone> ShallowClone for WalletHandle<N> {
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
