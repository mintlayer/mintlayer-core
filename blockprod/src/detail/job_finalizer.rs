// A helper struct that will call a function when it is dropped.
pub struct JobFinalizer<F: FnOnce()> {
    job_finalizer: Option<F>,
}

impl<F: FnOnce()> JobFinalizer<F> {
    pub fn new(job_stopper: F) -> Self {
        Self {
            job_finalizer: Some(job_stopper),
        }
    }
}

impl<F: FnOnce()> Drop for JobFinalizer<F> {
    fn drop(&mut self) {
        let mut stopper: Option<F> = None;
        std::mem::swap(&mut stopper, &mut self.job_finalizer);
        stopper.expect("Must exist")();
    }
}
