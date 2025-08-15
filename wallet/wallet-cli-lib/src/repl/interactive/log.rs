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

use std::sync::{Arc, Mutex};

struct ReedlineLogWriter {
    printer: reedline::ExternalPrinter<String>,
    buf: Vec<u8>,
    print_directly: Arc<Mutex<bool>>,
}

impl ReedlineLogWriter {
    fn new(printer: reedline::ExternalPrinter<String>, print_directly: Arc<Mutex<bool>>) -> Self {
        Self {
            printer,
            print_directly,
            buf: Vec::new(),
        }
    }
}

impl std::io::Write for ReedlineLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        if self.buf.last() == Some(&b'\n') {
            let line = std::mem::take(&mut self.buf);
            let line = String::from_utf8_lossy(&line.as_slice()[0..line.len() - 1]);

            // Hold lock while printing to stdout
            let print_directly_lock = self.print_directly.lock().expect("must succeed");
            if *print_directly_lock {
                println!("{}", line);
            } else {
                // Try to send without blocking to avoid deadlocks (which can happen when the send buffer is full)
                let _ = self.printer.sender().try_send(line.to_string());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Use [reedline::ExternalPrinter] to print log output without mangling reedline console input
pub struct InteractiveLogger {
    external_printer: reedline::ExternalPrinter<String>,
    // A mutex is used to ensure that prints to logs/stdout is serialized
    print_directly: Arc<Mutex<bool>>,
}

impl InteractiveLogger {
    pub fn init() -> Self {
        // Increase the buffer to prevent dropped log output.
        // Do not use very large buffers here, as this will increase
        // the amount of allocated memory (even if the buffer is not used).
        // Note that it shouldn't be too small either, because InteractiveLogger is also used
        // to collect logs when displaying paginated output; 8k should be enough to collect
        // relatively verbose debug logs for several minutes.
        let external_printer = reedline::ExternalPrinter::new(8192);

        let print_directly = Arc::new(Mutex::new(true));

        let log_writer =
            ReedlineLogWriter::new(external_printer.clone(), Arc::clone(&print_directly));

        logging::init_logging_to(log_writer, true);

        Self {
            external_printer,
            print_directly,
        }
    }

    pub fn printer(&self) -> &reedline::ExternalPrinter<String> {
        &self.external_printer
    }

    pub fn set_print_directly(&self, value: bool) {
        *self.print_directly.lock().expect("must succeed") = value;
    }
}
