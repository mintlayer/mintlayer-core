// Copyright (c) 2024 RBB S.r.l
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

use std::fmt;

use common::chain::timelock::OutputTimeLock;
use serialization::hex_encoded::HexEncoded;

use super::{DissatisfiedScript, ScriptCondition, Threshold, WitnessScript};

impl Threshold {
    fn fmt_indent(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        let indent_str = "    ";
        let next_indent = indent + indent_str.len();
        let req = self.required();

        if req == 0 {
            f.write_str("true")
        } else {
            write!(f, "threshold({req}, [\n{:indent$}", "")?;
            for cond in self.conditions() {
                f.write_str(indent_str)?;
                cond.fmt_indent(f, next_indent)?;
                write!(f, ",\n{:indent$}", "")?;
            }
            write!(f, "])")
        }
    }
}

impl ScriptCondition {
    fn fmt_indent(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        match self {
            Self::Satisfied(ws) => ws.fmt_indent(f, indent),
            Self::Dissatisfied(DissatisfiedScript::False) => f.write_str("false"),
        }
    }
}

impl WitnessScript {
    fn fmt_indent(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        match self {
            Self::Threshold(thresh) => thresh.fmt_indent(f, indent),

            Self::Signature(destination, witness) => {
                let dest = HexEncoded::new(destination);
                let wit = HexEncoded::new(witness);
                write!(f, "signature(0x{dest}, 0x{wit})")
            }

            Self::Timelock(tl) => match tl {
                OutputTimeLock::UntilHeight(ht) => write!(f, "until_height({ht})"),
                OutputTimeLock::UntilTime(t) => write!(f, "until_time({t})"),
                OutputTimeLock::ForBlockCount(c) => write!(f, "after_blocks({c})"),
                OutputTimeLock::ForSeconds(s) => write!(f, "after_seconds({s})"),
            },
        }
    }
}

impl fmt::Display for WitnessScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indent(f, 0)
    }
}
