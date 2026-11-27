// Copyright (c) 2026 RBB S.r.l
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

//! Helpers shared by the unit tests of the crate.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use tracing_subscriber::{Registry, layer::SubscriberExt as _};

use crate::{
    LogStyle, ValueOrEnvVar, ValueOrEnvVarWithDefault, WriterSettings, make_layer,
    write_to_make_writer,
};

/// A log output collector that can be shared between the subscriber and the test.
///
/// Unlike the global initialization functions, the subscriber built here is installed
/// with `with_default` for the duration of a closure, so each test captures only its own
/// output.
#[derive(Clone, Default)]
pub(crate) struct LogOutput(Arc<Mutex<Vec<u8>>>);

impl LogOutput {
    /// Returns everything captured so far, leaving the buffer empty.
    pub(crate) fn take(&self) -> String {
        let mut vec = self.0.lock().unwrap();
        String::from_utf8(std::mem::take(&mut *vec)).unwrap()
    }

    /// Runs the closure with a subscriber writing to this buffer, returning the output.
    ///
    /// The subscriber passes every level through (`trace`), so that the output shows what
    /// the code emits rather than what a default filter would let through;
    /// `source_location` and `thread_info` select the optional fields of the lines.
    pub(crate) fn capture<R>(
        &self,
        log_style: LogStyle,
        source_location: bool,
        thread_info: bool,
        f: impl FnOnce() -> R,
    ) -> String {
        let mut errors = Vec::new();
        let layer = make_layer(
            WriterSettings {
                make_writer: write_to_make_writer(self.clone()),
                is_terminal: false,
                filter: ValueOrEnvVarWithDefault::Value("trace".to_owned()),
                log_style: ValueOrEnvVar::Value(log_style),
                source_location,
                thread_info,
            },
            &mut errors,
        );
        assert!(errors.is_empty(), "unexpected log init errors: {errors:?}");

        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        self.take()
    }
}

impl Write for LogOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
