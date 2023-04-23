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

use std::{collections::BTreeMap, sync::Arc};

use chainstate::{ChainstateEvent, ChainstateHandle};
use common::{chain::GenBlock, primitives::Id};
use logging::log;
use serialization::{Decode, Encode};
use tokio::sync::{
    mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};
use utils::{ensure, tap_error_log::LogError};

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
}

pub struct JobHandle {
    cancel_sender: UnboundedSender<()>,
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
    current_tip_id: Id<GenBlock>,
    // TODO: in proof of stake, we also add some identifier of the
    // current key so that we don't stake twice from the same key.
    // This is because in PoS, there could be penalties for creating
    // multiple blocks by the same staker.
}

impl JobKey {
    pub fn new(current_tip_id: Id<GenBlock>) -> Self {
        JobKey { current_tip_id }
    }

    pub fn current_tip_id(&self) -> Id<GenBlock> {
        self.current_tip_id
    }
}

#[allow(clippy::type_complexity)]
pub struct JobManager {
    chainstate_handle: ChainstateHandle,
    get_job_count_sender: UnboundedSender<oneshot::Sender<usize>>,
    new_job_sender: UnboundedSender<(
        Id<GenBlock>,
        UnboundedSender<()>,
        oneshot::Sender<Result<JobKey, JobManagerError>>,
    )>,
    stop_job_sender: UnboundedSender<(Option<JobKey>, oneshot::Sender<usize>)>,
    shutdown_sender: UnboundedSender<oneshot::Sender<usize>>,
}

impl JobManager {
    pub fn new(chainstate_handle: ChainstateHandle) -> JobManager {
        let (chainstate_sender, chainstate_receiver) = mpsc::unbounded_channel::<Id<GenBlock>>();
        let (get_job_count_sender, get_job_count_receiver) = mpsc::unbounded_channel();
        let (stop_job_sender, stop_job_receiver) = mpsc::unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = mpsc::unbounded_channel();

        let (new_job_sender, new_job_receiver) = mpsc::unbounded_channel::<(
            Id<GenBlock>,
            UnboundedSender<()>,
            oneshot::Sender<Result<JobKey, JobManagerError>>,
        )>();

        let mut job_manager = JobManager {
            chainstate_handle,
            get_job_count_sender,
            new_job_sender,
            stop_job_sender,
            shutdown_sender,
        };

        job_manager.subscribe_to_chainstate(chainstate_sender);
        job_manager.run(
            chainstate_receiver,
            get_job_count_receiver,
            new_job_receiver,
            stop_job_receiver,
            shutdown_receiver,
        );

        job_manager
    }

    #[allow(clippy::type_complexity)]
    fn run(
        &mut self,
        mut chainstate_receiver: UnboundedReceiver<Id<GenBlock>>,
        mut get_job_count_receiver: UnboundedReceiver<oneshot::Sender<usize>>,
        mut new_job_receiver: UnboundedReceiver<(
            Id<GenBlock>,
            UnboundedSender<()>,
            oneshot::Sender<Result<JobKey, JobManagerError>>,
        )>,
        mut stop_job_receiver: UnboundedReceiver<(Option<JobKey>, oneshot::Sender<usize>)>,
        mut shutdown_receiver: UnboundedReceiver<oneshot::Sender<usize>>,
    ) {
        tokio::spawn(async move {
            let mut jobs: BTreeMap<JobKey, JobHandle> = BTreeMap::new();

            loop {
                tokio::select! {
                    event = get_job_count_receiver.recv()
                        => Self::get_job_count_handler(&jobs, event),

                    event = chainstate_receiver.recv()
                        => Self::chainstate_handler(&mut jobs, event),

                    event = new_job_receiver.recv()
                        => Self::new_job_handler(&mut jobs, event),

                    event = stop_job_receiver.recv()
                        => Self::stop_job_handler(&mut jobs, event),

                    event = shutdown_receiver.recv()
                        => return Self::shutdown_handler(&mut jobs, event), // Note: the return here
                }
            }
        });
    }

    fn subscribe_to_chainstate(&mut self, chainstate_sender: UnboundedSender<Id<GenBlock>>) {
        let chainstate_handle = self.chainstate_handle.clone();

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

                    this.subscribe_to_events(subscribe_func);
                })
                .await
        });
    }

    fn chainstate_handler(jobs: &mut BTreeMap<JobKey, JobHandle>, event: Option<Id<GenBlock>>) {
        if let Some(new_tip_id) = event {
            let mut jobs_to_stop: Vec<JobKey> = vec![];

            for (job_key, _) in jobs.iter() {
                if job_key.current_tip_id() != new_tip_id {
                    jobs_to_stop.push(job_key.clone());
                }
            }

            for job_key in jobs_to_stop {
                if let Some(handle) = jobs.remove(&job_key) {
                    _ = handle.cancel_sender.send(()).log_err_pfx("Error sending cancel job event");
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn get_job_count(&self) -> Result<usize, JobManagerError> {
        let (result_sender, result_receiver) = oneshot::channel();

        ensure!(
            self.get_job_count_sender.send(result_sender).is_ok(),
            JobManagerError::FailedToSendGetJobCountEvent
        );

        tokio::select! {
            result = result_receiver => result.map_err(|_| JobManagerError::FailedToReadJobCount),
        }
    }

    fn get_job_count_handler(
        jobs: &BTreeMap<JobKey, JobHandle>,
        event: Option<oneshot::Sender<usize>>,
    ) {
        if let Some(result_sender) = event {
            _ = result_sender
                .send(jobs.len())
                .log_err_pfx("Error sending get job count results");
        }
    }

    pub async fn new_job(
        &self,
        block_id: Id<GenBlock>,
    ) -> Result<(JobKey, UnboundedReceiver<()>), JobManagerError> {
        let (result_sender, result_receiver) = oneshot::channel();
        let (cancel_sender, cancel_receiver) = unbounded_channel::<()>();

        ensure!(
            self.new_job_sender.send((block_id, cancel_sender, result_sender)).is_ok(),
            JobManagerError::FailedToSendNewJobEvent
        );

        tokio::select! {
            result = result_receiver
                => result
                    .map_err(|_| JobManagerError::FailedToCreateJob)?
                    .and_then(|v| Ok((v, cancel_receiver))).or_else(|e| Err(e))
        }
    }

    #[allow(clippy::type_complexity)]
    fn new_job_handler(
        jobs: &mut BTreeMap<JobKey, JobHandle>,
        event: Option<(
            Id<GenBlock>,
            UnboundedSender<()>,
            oneshot::Sender<Result<JobKey, JobManagerError>>,
        )>,
    ) {
        if let Some((current_tip_id, cancel_sender, result_sender)) = event {
            let job_key = JobKey::new(current_tip_id);

            if jobs.contains_key(&job_key) {
                if let Err(e) = result_sender.send(Err(JobManagerError::JobAlreadyExists)) {
                    log::info!("Error sending new job exists error: {e:?}");
                }
            } else {
                jobs.insert(job_key.clone(), JobHandle { cancel_sender });

                if let Err(e) = result_sender.send(Ok(job_key)) {
                    log::info!("Error sending new job event: {e:?}");
                }
            }
        }
    }

    pub async fn stop_job(&mut self, job_key: Option<JobKey>) -> Result<usize, JobManagerError> {
        let (result_sender, result_receiver) = oneshot::channel();

        ensure!(
            self.stop_job_sender.send((job_key, result_sender)).is_ok(),
            JobManagerError::FailedToSendStopJobEvent
        );

        tokio::select! {
            result = result_receiver => result.map_err(|_| JobManagerError::FailedToStopJobs),
        }
    }

    fn stop_job_handler(
        jobs: &mut BTreeMap<JobKey, JobHandle>,
        event: Option<(Option<JobKey>, oneshot::Sender<usize>)>,
    ) {
        if let Some((job_key, result_sender)) = event {
            let mut stop_jobs = Vec::new();

            match job_key {
                Some(job_key) => {
                    if let Some(job_handle) = jobs.remove(&job_key) {
                        stop_jobs.push((job_key, job_handle));
                    }
                }
                None => {
                    while let Some((job_key, job_handle)) = jobs.pop_first() {
                        stop_jobs.push((job_key, job_handle));
                    }

                    log::info!("Cancelling {} jobs", stop_jobs.len());
                }
            }

            let stop_count = stop_jobs.len();

            for (job_key, job_handle) in stop_jobs.drain(..) {
                let _ = job_handle.cancel_sender.send(());
                log::info!("Stopped mining job for tip {}", job_key.current_tip_id());
            }

            _ = result_sender.send(stop_count).log_err_pfx("Error sending stop jobs count");
        }
    }

    fn shutdown_handler(
        jobs: &mut BTreeMap<JobKey, JobHandle>,
        event: Option<oneshot::Sender<usize>>,
    ) {
        if let Some(result_sender) = event {
            log::info!("Stopping job manager");
            Self::stop_job_handler(jobs, Some((None, result_sender)));
        }
    }
}

impl Drop for JobManager {
    fn drop(&mut self) {
        let (result_sender, result_receiver) = oneshot::channel();

        if let Err(e) = self.shutdown_sender.send(result_sender) {
            log::info!("Error sending shutdown during job manager drop: {e:?}");
            return;
        }

        tokio::spawn(async move {
            tokio::select! {
                _ = result_receiver => {},
            }
        });
    }
}
