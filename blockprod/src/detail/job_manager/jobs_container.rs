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

use std::collections::BTreeMap;

use common::{chain::GenBlock, primitives::Id};
use logging::log;
use tokio::sync::oneshot;
use utils::tap_error_log::LogError;

use super::{JobHandle, JobKey, JobManagerError, NewJobEvent};

#[derive(Default)]
pub struct JobsContainer {
    jobs: BTreeMap<JobKey, JobHandle>,
}

impl JobsContainer {
    pub fn job_count(&self, result_sender: oneshot::Sender<usize>) {
        _ = result_sender
            .send(self.jobs.len())
            .log_err_pfx("Error sending get job count results");
    }

    pub fn new_job(&mut self, event: NewJobEvent) {
        let NewJobEvent {
            current_tip_id,
            cancel_sender,
            result_sender,
        } = event;

        let job_key = JobKey::new(current_tip_id);

        if self.jobs.contains_key(&job_key) {
            if let Err(e) = result_sender.send(Err(JobManagerError::JobAlreadyExists)) {
                log::error!("Error sending new job exists error: {e:?}");
            }
        } else {
            self.jobs.insert(job_key.clone(), JobHandle { cancel_sender });

            if let Err(e) = result_sender.send(Ok(job_key)) {
                log::error!("Error sending new job event: {e:?}");
            }
        }
    }

    pub fn handle_chainstate_event(&mut self, new_tip_id: Id<GenBlock>) {
        let mut jobs_to_stop: Vec<JobKey> = vec![];

        for (job_key, _) in self.jobs.iter() {
            if job_key.current_tip_id() != new_tip_id {
                jobs_to_stop.push(job_key.clone());
            }
        }

        for job_key in jobs_to_stop {
            if let Some(handle) = self.jobs.remove(&job_key) {
                _ = handle.cancel_sender.send(()).log_err_pfx("Error sending cancel job event");
            }
        }
    }

    /// Remove a job by its key. If `and_stop` is true, the job will be stopped.
    /// Returns true if the job was removed, false if it was not found.
    #[allow(dead_code)]
    pub fn remove_job(&mut self, job_key: JobKey, and_stop: bool) -> bool {
        match self.jobs.entry(job_key) {
            std::collections::btree_map::Entry::Vacant(j) => {
                log::error!("Attempted to stop non-existent job: {j:?}");
                false
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if and_stop {
                    _ = entry
                        .get()
                        .cancel_sender
                        .send(())
                        .log_err_pfx("Error sending cancel job event");
                }
                true
            }
        }
    }

    #[allow(dead_code)]
    pub fn stop_all(&mut self) -> usize {
        let taken_jobs = std::mem::take(&mut self.jobs);
        let count = taken_jobs.len();
        let _stop_results =
            taken_jobs.into_iter().map(|j| j.1.cancel_sender.send(())).collect::<Vec<_>>();
        count
    }

    pub fn handle_stop_job(&mut self, event: (Option<JobKey>, oneshot::Sender<usize>)) {
        let (job_key, result_sender) = event;
        let mut stop_jobs = Vec::new();

        match job_key {
            Some(job_key) => {
                if let Some(job_handle) = self.jobs.remove(&job_key) {
                    stop_jobs.push((job_key, job_handle));
                } else {
                    log::error!("Attempted to stop non-existent job: {job_key:?}")
                }
            }
            None => {
                stop_jobs =
                    std::mem::take(&mut self.jobs).into_iter().map(|(k, v)| (k, v)).collect();
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

    pub fn shutdown(&mut self, result_sender: oneshot::Sender<usize>) {
        log::info!("Stopping block production job manager");
        self.handle_stop_job((None, result_sender));
    }
}

// TODO: tests
