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

mod jobs_container;

use std::sync::Arc;

use crate::detail::CustomId;
use async_trait::async_trait;
use chainstate::{ChainstateEvent, ChainstateHandle};
use common::{chain::GenBlock, primitives::Id};
use logging::log;
use serialization::{Decode, Encode};
use tokio::sync::{
    mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};
use utils::{ensure, tap_log::TapLog};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum JobManagerError {
    #[error("Error getting job count")]
    FailedToReadJobCount,
    #[error("Error sending get job count event")]
    FailedToSendGetJobCountEvent,
    #[error("Error creating new job")]
    FailedToCreateJob,
    #[error("Error sending new job event")]
    FailedToSendNewJobEvent,
    #[error("Tried to create an already existing job")]
    JobAlreadyExists,
    #[error("Error stopping jobs")]
    FailedToStopJobs,
    #[error("Error sending stop job event")]
    FailedToSendStopJobEvent,
    #[error("Error sending update last timestamp seconds used event")]
    FailedToSendUpdateLastTimestampSecondsUsed,
    #[error("Error updating last timestamp seconds used")]
    FailedToUpdateLastTimestampSecondsUsed,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct JobKey {
    /// The job key is provided in tests to make it possible to run
    /// multiple block productions in parallel.
    /// In PoS this will be generated based on staker's `stake_public_key` to avoid
    /// staking twice with the same key.
    custom_id: CustomId,
}

impl JobKey {
    pub fn new(custom_id: CustomId) -> Self {
        JobKey { custom_id }
    }
}

pub struct NewJobEvent {
    custom_id: CustomId,
    expected_tip_id: Option<Id<GenBlock>>,
    cancel_sender: UnboundedSender<()>,
    result_sender: oneshot::Sender<Result<JobKey, JobManagerError>>,
}

pub struct JobManager {
    chainstate_handle: Option<ChainstateHandle>,
    get_job_count_sender: UnboundedSender<oneshot::Sender<usize>>,
    new_job_sender: UnboundedSender<NewJobEvent>,
    stop_job_sender: UnboundedSender<(Option<JobKey>, oneshot::Sender<usize>)>,
    shutdown_sender: UnboundedSender<oneshot::Sender<usize>>,
}

#[async_trait]
pub trait JobManagerInterface: Send + Sync {
    #[allow(dead_code)]
    async fn get_job_count(&self) -> Result<usize, JobManagerError>;

    /// Add a new job
    /// If `expected_tip_id` is `Some`, the job will be cancelled once the current tip changes to something else.
    async fn add_job(
        &self,
        custom_id: CustomId,
        expected_tip_id: Option<Id<GenBlock>>,
    ) -> Result<(JobKey, UnboundedReceiver<()>), JobManagerError>;

    async fn stop_all_jobs(&mut self) -> Result<usize, JobManagerError>;

    async fn stop_job(&mut self, job_key: JobKey) -> Result<usize, JobManagerError>;

    /// For destructors, we make a job stopper that will send a stop signal
    ///
    /// Returns both the function and a oneshot-receiver.
    ///
    /// Once the job is dropped from the job manager, the receiver will be notified.
    fn make_job_stopper_function(
        &self,
    ) -> (Box<dyn FnOnce(JobKey) + Send>, oneshot::Receiver<usize>);
}

pub type JobManagerHandle = Box<dyn JobManagerInterface>;

pub struct JobManagerImpl {
    job_manager: JobManager,
}

impl JobManagerImpl {
    pub fn new(chainstate_handle: Option<ChainstateHandle>) -> Self {
        Self {
            job_manager: JobManager::new(chainstate_handle),
        }
    }
}

#[async_trait]
impl JobManagerInterface for JobManagerImpl {
    async fn get_job_count(&self) -> Result<usize, JobManagerError> {
        self.job_manager.get_job_count().await
    }

    async fn add_job(
        &self,
        custom_id: CustomId,
        expected_tip_id: Option<Id<GenBlock>>,
    ) -> Result<(JobKey, UnboundedReceiver<()>), JobManagerError> {
        self.job_manager.add_job(custom_id, expected_tip_id).await
    }

    async fn stop_all_jobs(&mut self) -> Result<usize, JobManagerError> {
        self.job_manager.stop_all_jobs().await
    }

    async fn stop_job(&mut self, job_key: JobKey) -> Result<usize, JobManagerError> {
        self.job_manager.stop_job(job_key).await
    }

    fn make_job_stopper_function(
        &self,
    ) -> (Box<dyn FnOnce(JobKey) + Send>, oneshot::Receiver<usize>) {
        self.job_manager.make_job_stopper_function()
    }
}

/// Helper function that calls a closure if the event is `Some`.
fn event_then<T>(ev: Option<T>, f: impl FnOnce(T)) {
    if let Some(ev) = ev {
        f(ev)
    }
}

impl JobManager {
    pub fn new(chainstate_handle: Option<ChainstateHandle>) -> JobManager {
        let (chainstate_sender, chainstate_receiver) = mpsc::unbounded_channel::<Id<GenBlock>>();
        let (get_job_count_sender, get_job_count_receiver) = mpsc::unbounded_channel();
        let (new_job_sender, new_job_receiver) = mpsc::unbounded_channel::<NewJobEvent>();
        let (stop_job_sender, stop_job_receiver) = mpsc::unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = mpsc::unbounded_channel();

        let mut job_manager = JobManager {
            chainstate_handle: chainstate_handle.clone(),
            get_job_count_sender,
            new_job_sender,
            stop_job_sender,
            shutdown_sender,
        };

        if chainstate_handle.is_some() {
            job_manager.subscribe_to_chainstate(chainstate_sender);
        }

        job_manager.run(
            chainstate_receiver,
            get_job_count_receiver,
            new_job_receiver,
            stop_job_receiver,
            shutdown_receiver,
        );

        job_manager
    }

    fn run(
        &mut self,
        mut chainstate_receiver: UnboundedReceiver<Id<GenBlock>>,
        mut get_job_count_receiver: UnboundedReceiver<oneshot::Sender<usize>>,
        mut new_job_receiver: UnboundedReceiver<NewJobEvent>,
        mut stop_job_receiver: UnboundedReceiver<(Option<JobKey>, oneshot::Sender<usize>)>,
        mut shutdown_receiver: UnboundedReceiver<oneshot::Sender<usize>>,
    ) {
        tokio::spawn(async move {
            let mut jobs = jobs_container::JobsContainer::default();

            loop {
                tokio::select! {
                    event = get_job_count_receiver.recv()
                        => event_then(event, |result_sender| jobs.handle_job_count(result_sender)),

                    tip_id = chainstate_receiver.recv()
                        => event_then(tip_id, |id| jobs.handle_chainstate_event(id)),

                    event = new_job_receiver.recv()
                        => event_then(event, |job| jobs.handle_add_job(job)),

                    event = stop_job_receiver.recv()
                        => event_then(event, |ev| jobs.handle_stop_job(ev)),

                    event = shutdown_receiver.recv()
                        => return event_then(event, |result_sender| jobs.handle_shutdown(result_sender)),
                }
            }
        });
    }

    fn subscribe_to_chainstate(&self, chainstate_sender: UnboundedSender<Id<GenBlock>>) {
        let chainstate_handle = match &self.chainstate_handle {
            Some(handle) => handle.clone(),
            None => return,
        };

        tokio::spawn(async move {
            chainstate_handle
                .call_mut(|this| {
                    let subscribe_func =
                        Arc::new(
                            move |chainstate_event: ChainstateEvent| match chainstate_event {
                                ChainstateEvent::NewTip(block_id, _) => {
                                    _ = chainstate_sender.send(block_id.into()).log_err_pfx(
                                        "Chainstate subscriber failed to send new tip",
                                    );
                                }
                            },
                        );

                    this.subscribe_to_subsystem_events(subscribe_func);
                })
                .await
        });
    }

    #[allow(dead_code)]
    pub async fn get_job_count(&self) -> Result<usize, JobManagerError> {
        let (result_sender, result_receiver) = oneshot::channel();

        ensure!(
            self.get_job_count_sender.send(result_sender).is_ok(),
            JobManagerError::FailedToSendGetJobCountEvent
        );

        result_receiver.await.map_err(|_| JobManagerError::FailedToReadJobCount)
    }

    pub async fn add_job(
        &self,
        custom_id: CustomId,
        expected_tip_id: Option<Id<GenBlock>>,
    ) -> Result<(JobKey, UnboundedReceiver<()>), JobManagerError> {
        let (result_sender, result_receiver) = oneshot::channel();
        let (cancel_sender, cancel_receiver) = unbounded_channel::<()>();

        let job = NewJobEvent {
            custom_id,
            expected_tip_id,
            cancel_sender,
            result_sender,
        };

        ensure!(
            self.new_job_sender.send(job).is_ok(),
            JobManagerError::FailedToSendNewJobEvent
        );

        result_receiver
            .await
            .map_err(|_| JobManagerError::FailedToCreateJob)?
            .map(|job_key| (job_key, cancel_receiver))
    }

    pub async fn stop_all_jobs(&mut self) -> Result<usize, JobManagerError> {
        self.stop_job_internal(None).await
    }

    pub async fn stop_job(&mut self, job_key: JobKey) -> Result<usize, JobManagerError> {
        self.stop_job_internal(Some(job_key)).await
    }

    async fn stop_job_internal(
        &mut self,
        job_key: Option<JobKey>,
    ) -> Result<usize, JobManagerError> {
        let (result_sender, result_receiver) = oneshot::channel();

        ensure!(
            self.stop_job_sender.send((job_key, result_sender)).is_ok(),
            JobManagerError::FailedToSendStopJobEvent
        );

        result_receiver.await.map_err(|_| JobManagerError::FailedToStopJobs)
    }

    #[must_use]
    pub fn make_job_stopper_function(
        &self,
    ) -> (Box<dyn FnOnce(JobKey) + Send>, oneshot::Receiver<usize>) {
        let (result_sender, result_receiver) = oneshot::channel::<usize>();

        let sender = self.stop_job_sender.clone();

        let stopper = Box::new(move |job_key: JobKey| {
            let _ = sender.send((Some(job_key), result_sender));
        });

        (stopper, result_receiver)
    }
}

impl Drop for JobManager {
    fn drop(&mut self) {
        let (result_sender, result_receiver) = oneshot::channel();

        if let Err(e) = self.shutdown_sender.send(result_sender) {
            log::error!("Error sending shutdown during job manager drop: {e:?}");
            return;
        }

        tokio::spawn(result_receiver);
    }
}

// TODO: tests
#[cfg(test)]
pub mod tests {
    use common::{chain::GenBlock, primitives::Id};
    use tokio::sync::{mpsc::UnboundedReceiver, oneshot};

    use crate::detail::job_manager::{JobManagerError, JobManagerInterface};

    use super::*;

    mockall::mock! {
        pub JobManager {}

        #[async_trait::async_trait]
        impl JobManagerInterface for JobManager {
            async fn get_job_count(&self) -> Result<usize, JobManagerError>;

            async fn add_job(
                &self,
                custom_id: CustomId,
                expected_tip_id: Option<Id<GenBlock>>,
            ) -> Result<(JobKey, UnboundedReceiver<()>), JobManagerError>;

            async fn stop_all_jobs(&mut self) -> Result<usize, JobManagerError>;

            async fn stop_job(&mut self, job_key: JobKey) -> Result<usize, JobManagerError>;

            fn make_job_stopper_function(
                &self,
            ) -> (Box<dyn FnOnce(JobKey) + Send>, oneshot::Receiver<usize>);
        }
    }
}
