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

struct ReedlineLogWriter {
    printer: reedline::ExternalPrinter<String>,
    buf: Vec<u8>,
}

impl ReedlineLogWriter {
    fn new(printer: reedline::ExternalPrinter<String>) -> Self {
        Self {
            printer,
            buf: Vec::new(),
        }
    }
}

impl std::io::Write for ReedlineLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        if self.buf.last() == Some(&b'\n') {
            let line = std::mem::take(&mut self.buf);
            // Try to send without blocking to avoid deadlocks (which can happen when the send buffer is full)
            let _ = self
                .printer
                .sender()
                .try_send(String::from_utf8_lossy(&line.as_slice()[0..line.len() - 1]).to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Use [reedline::ExternalPrinter] to print log output without mangling reedline console input
pub fn init() -> reedline::ExternalPrinter<String> {
    // Increase the buffer to prevent dropped log output.
    // Do not use very large buffers here, as this will increase
    // the amount of allocated memory (even if the buffer is not used).
    let external_printer = reedline::ExternalPrinter::new(1024);

    let log_writer = ReedlineLogWriter::new(external_printer.clone());

    logging::init_logging_pipe(log_writer);

    external_printer
}
