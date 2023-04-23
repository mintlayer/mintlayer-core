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
    pub fn handle_get_job_count(&self, event: Option<oneshot::Sender<usize>>) {
        if let Some(result_sender) = event {
            _ = result_sender
                .send(self.jobs.len())
                .log_err_pfx("Error sending get job count results");
        }
    }

    pub fn handle_new_job(&mut self, event: Option<NewJobEvent>) {
        if let Some((current_tip_id, cancel_sender, result_sender)) = event {
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
    }

    pub fn handle_chainstate_event(&mut self, event: Option<Id<GenBlock>>) {
        if let Some(new_tip_id) = event {
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
    }

    pub fn handle_stop_job(&mut self, event: Option<(Option<JobKey>, oneshot::Sender<usize>)>) {
        if let Some((job_key, result_sender)) = event {
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
    }

    pub fn handle_shutdown(&mut self, event: Option<oneshot::Sender<usize>>) {
        if let Some(result_sender) = event {
            log::info!("Stopping block production job manager");
            self.handle_stop_job(Some((None, result_sender)));
        }
    }
}

// TODO: tests
