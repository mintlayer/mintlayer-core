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
        if self.buf.ends_with(&[b'\n']) {
            let mut line = std::mem::take(&mut self.buf);
            line.pop();
            let _ = self.printer.print(String::from_utf8_lossy(line.as_slice()).to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Use [reedline::ExternalPrinter] to print log output without mangling reedline console input
pub fn init() -> reedline::ExternalPrinter<String> {
    let external_printer = reedline::ExternalPrinter::default();

    let log_writer = ReedlineLogWriter::new(external_printer.clone());

    env_logger::builder()
        .target(env_logger::Target::Pipe(Box::new(log_writer)))
        .init();

    external_printer
}
