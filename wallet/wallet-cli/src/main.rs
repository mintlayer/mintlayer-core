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

use clap::{CommandFactory, Parser};
use wallet_cli_lib::{
    config::WalletCliArgs,
    console::{StdioInputConsole, StdioOutputConsole},
};

utils::enable_rust_backtrace!();

/// Emit a shell completion script for the wallet CLI binary.
///
/// This verb is handled by the binary before the main argument parser runs, so
/// it does not appear in the command grammar, in the help output, or in the
/// generated completions.
#[derive(Parser, Debug)]
struct CompletionsArgs {
    /// Shell to generate the completion script for
    #[clap(long)]
    shell: clap_complete::Shell,
}

/// The name completions should bind to: the invoked file name, falling back
/// to the package name when it cannot be determined.
fn binary_name() -> String {
    std::env::args_os()
        .next()
        .as_deref()
        .map(std::path::Path::new)
        // `file_stem` drops any extension (e.g. `.exe` on Windows); completion
        // script identifiers must not contain a dot.
        .and_then(|path| path.file_stem())
        .and_then(|name| name.to_str())
        .map_or_else(|| env!("CARGO_PKG_NAME").to_owned(), str::to_owned)
}

fn generate_completions() {
    use std::io::Write;
    let bin_name = binary_name();
    // Name the parser after the real binary; the intercepted `completions`
    // verb is not part of this parser's arguments.
    let mut argv: Vec<std::ffi::OsString> = vec![bin_name.as_str().into()];
    argv.extend(std::env::args_os().skip(2));
    let args = CompletionsArgs::parse_from(argv);
    // Buffer the script so a failed write (closed pipe, full disk) is
    // observable: clap_complete discards write errors internally.
    let mut script = Vec::new();
    let mut command = WalletCliArgs::command();
    clap_complete::generate(args.shell, &mut command, bin_name, &mut script);
    std::io::stdout().write_all(&script).unwrap_or_else(|err| {
        eprintln!("failed to write completions: {err}");
        std::process::exit(1);
    });
}

#[tokio::main]
async fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("completions")) {
        generate_completions();
        return;
    }
    let args = WalletCliArgs::parse();
    wallet_cli_lib::run(StdioInputConsole, StdioOutputConsole, args, None)
        .await
        .unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        })
}
