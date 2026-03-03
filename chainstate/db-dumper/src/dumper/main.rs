// Copyright (c) 2021-2025 RBB S.r.l
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

use chainstate_launcher::SUBDIRECTORY_LMDB;
use logging::{init_logging, log};
use utils::default_data_dir::default_data_dir_for_chain;

use chainstate_db_dumper_lib::{dump_blocks_to_file, parse_block_output_fields_list};

use crate::options::{default_fields, Options};

mod options;

fn run() -> anyhow::Result<()> {
    let opts = Options::parse();
    let chain_type = opts.chain_type.chain_type();
    let db_dir = opts
        .db_dir
        .unwrap_or_else(|| default_data_dir_for_chain(chain_type.name()).join(SUBDIRECTORY_LMDB));
    let fields = opts.fields.map(|fields| parse_block_output_fields_list(&fields)).transpose()?;
    let fields = fields.as_deref().unwrap_or(default_fields(opts.mainchain_only));

    log::info!("Using db dir {}", db_dir.display());

    dump_blocks_to_file(
        chain_type,
        db_dir,
        opts.mainchain_only,
        opts.from_height,
        fields,
        &opts.output_file,
    )?;
    Ok(())
}

fn main() {
    utils::rust_backtrace::enable();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    init_logging();

    run().unwrap_or_else(|err| {
        eprintln!("Error: {err:?}");
        std::process::exit(1)
    })
}
