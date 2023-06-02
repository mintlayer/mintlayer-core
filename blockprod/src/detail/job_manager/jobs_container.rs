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

use std::collections::{btree_map::Entry, BTreeMap};

use common::{chain::GenBlock, primitives::Id};
use logging::log;
use tokio::sync::oneshot;

use super::{JobHandle, JobKey, JobManagerError, NewJobEvent};

#[derive(Default)]
pub struct JobsContainer {
    jobs: BTreeMap<JobKey, JobHandle>,
}

impl JobsContainer {
    pub fn handle_job_count(&self, result_sender: oneshot::Sender<usize>) {
        _ = result_sender.send(self.jobs.len());
    }

    pub fn handle_add_job(&mut self, event: NewJobEvent) {
        let NewJobEvent {
            custom_id,
            current_tip_id,
            cancel_sender,
            result_sender,
        } = event;

        let job_key = JobKey::new(custom_id, current_tip_id);

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
        let jobs_to_stop: Vec<JobKey> = self
            .jobs
            .iter()
            .filter(|(job_key, _)| job_key.current_tip_id() != new_tip_id)
            .map(|(job_key, _)| job_key.clone())
            .collect();

        for job_key in jobs_to_stop {
            if let Some(handle) = self.jobs.remove(&job_key) {
                _ = handle.cancel_sender.send(())
            }
        }
    }

    /// Remove a job by its key
    ///
    /// If `and_stop` is true, the job will be stopped.
    ///
    /// Returns true if the job was removed, false if it was not found.
    fn remove_job(&mut self, job_key: JobKey, and_stop: bool) -> bool {
        match self.jobs.entry(job_key) {
            Entry::Vacant(j) => {
                log::error!("Attempted to stop non-existent job: {j:?}");
                false
            }
            Entry::Occupied(entry) => {
                let removed_job = entry.remove();

                if and_stop {
                    _ = removed_job.cancel_sender.send(())
                }

                true
            }
        }
    }

    fn stop_all(&mut self) -> usize {
        let taken_jobs = std::mem::take(&mut self.jobs);
        let count = taken_jobs.len();
        let stop_results = taken_jobs
            .into_values()
            .map(|job_handle| job_handle.cancel_sender.send(()))
            .collect::<Vec<_>>();

        let send_fail_count = stop_results.into_iter().filter_map(|r| r.ok()).count();
        if send_fail_count > 0 {
            log::info!("Sending stop jobs for block production failed for {send_fail_count}");
        }

        // We don't do `count - send_fail_count` because the failures
        // are in sending, not in stopping. The jobs are assumed to
        // have been stopped already.
        count
    }

    pub fn handle_stop_job(&mut self, event: (Option<JobKey>, oneshot::Sender<usize>)) {
        let (job_key, result_sender) = event;

        let stopped_count = match job_key {
            Some(job_key) => self.remove_job(job_key, true) as usize,
            None => self.stop_all(),
        };

        _ = result_sender.send(stopped_count);
    }

    pub fn handle_shutdown(&mut self, result_sender: oneshot::Sender<usize>) {
        log::info!("Stopping block production job manager");
        self.handle_stop_job((None, result_sender));
    }
}

// TODO: tests
