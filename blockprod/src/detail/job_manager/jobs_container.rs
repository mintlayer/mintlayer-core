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
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use super::{JobKey, JobManagerError, NewJobEvent};

#[derive(Default)]
pub struct JobsContainer {
    jobs: BTreeMap<JobKey, JobData>,
}

impl JobsContainer {
    pub fn handle_job_count(&self, result_sender: oneshot::Sender<usize>) {
        _ = result_sender.send(self.jobs.len());
    }

    pub fn handle_add_job(&mut self, event: NewJobEvent) {
        let NewJobEvent {
            custom_id,
            expected_tip_id,
            cancel_sender,
            result_sender,
        } = event;

        let job_key = JobKey::new(custom_id.clone());

        if self.jobs.contains_key(&job_key) {
            if let Err(e) = result_sender.send(Err(JobManagerError::JobAlreadyExists)) {
                log::error!("Error sending new job exists error: {e:?}");
            }
        } else {
            self.jobs.insert(
                job_key.clone(),
                JobData {
                    cancel_sender,
                    expected_tip_id,
                },
            );

            if let Err(e) = result_sender.send(Ok(job_key)) {
                log::error!("Error sending new job event: {e:?}");
            }
        }
    }

    pub fn handle_chainstate_event(&mut self, new_tip_id: Id<GenBlock>) {
        let jobs_to_stop: Vec<JobKey> = self
            .jobs
            .iter()
            .filter_map(|(job_key, job_data)| {
                job_data.expected_tip_id.and_then(|expected_tip_id| {
                    (expected_tip_id != new_tip_id).then(|| job_key.clone())
                })
            })
            .collect();

        for job_key in jobs_to_stop {
            self.remove_job(job_key, true);
        }
    }

    /// Remove a job by its key
    ///
    /// If `and_stop` is true, the job will be stopped.
    ///
    /// Returns true if the job was removed, false if it was not found.
    fn remove_job(&mut self, job_key: JobKey, and_stop: bool) -> bool {
        match self.jobs.entry(job_key) {
            Entry::Vacant(_) => false,
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
            .into_keys()
            .map(|job_key| self.remove_job(job_key, true))
            .filter(|stopped| *stopped)
            .collect::<Vec<_>>();

        if !stop_results.is_empty() {
            log::info!(
                "Sending stop jobs for block production failed for {}",
                stop_results.len()
            );
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

struct JobData {
    cancel_sender: UnboundedSender<()>,
    expected_tip_id: Option<Id<GenBlock>>,
}

// TODO: tests
