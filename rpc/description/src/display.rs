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

use super::{Interface, Method, MethodKindData, Module, ValueHint};

impl std::fmt::Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { modules } = self;

        for module in modules {
            module.fmt(f)?;
        }

        Ok(())
    }
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            description,
            methods,
        } = self;

        writeln!(f, "## Module `{name}`\n")?;
        if !description.trim().is_empty() {
            writeln!(f, "{description}\n")?;
        }
        for method in *methods {
            method.fmt(f)?;
        }

        Ok(())
    }
}

fn code_block<T: std::fmt::Display>(
    header: &str,
    content: T,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{header}:")?;
    writeln!(f, "```")?;
    writeln!(f, "{content}")?;
    writeln!(f, "```\n")?;
    Ok(())
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            description,
            params,
            kind_data,
        } = self;

        let kind = match kind_data {
            MethodKindData::Subscription { .. } => "Subscription",
            MethodKindData::Method { .. } => "Method",
        };

        writeln!(f, "### {kind} `{name}`\n")?;
        if !description.trim().is_empty() {
            writeln!(f, "{description}\n")?;
        }
        code_block("Parameters", params, f)?;

        match kind_data {
            MethodKindData::Method { return_type } => {
                code_block("Returns", return_type, f)?;
            }
            MethodKindData::Subscription {
                unsubscribe_name,
                item_type,
            } => {
                code_block("Produces", item_type, f)?;
                writeln!(f, "Unsubscribe using `{unsubscribe_name}`.")?;
            }
        }

        f.write_str("\n")?;

        Ok(())
    }
}

impl ValueHint {
    fn fmt_indent(&self, indent: usize, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let indent_str = "    ";
        let next_indent = indent + indent_str.len();

        // Implementing indentation can be a bit tricky. Here are some general rules:
        //
        // * Use `indent_str` to indent something beyond the current indentation level.
        // * Use `next_indent` in recursive calls for nested structures.
        // * Emit the correct number of spaces according to the current indentation level after
        //   each newline character (and nowhere else). Use `write!(f, "\n{:indent$}", "")?`.

        match self {
            ValueHint::Prim(h) => f.write_str(h)?,

            ValueHint::Choice(hints) => {
                if hints.is_empty() {
                    f.write_str("impossible")?;
                    return Ok(());
                }
                let mut hints = hints.iter();
                if let Some(hint) = hints.next() {
                    hint.fmt_indent(indent, f)?;
                }
                for hint in hints {
                    f.write_str(" OR ")?;
                    hint.fmt_indent(indent, f)?;
                }
            }

            ValueHint::Object(hints) => {
                if hints.is_empty() {
                    f.write_str("{}")?;
                    return Ok(());
                }
                write!(f, "{{\n{:indent$}", "")?;
                for (name, hint) in *hints {
                    write!(f, "{indent_str}{name:?}: ")?;
                    hint.fmt_indent(next_indent, f)?;
                    write!(f, ",\n{:indent$}", "")?;
                }
                f.write_str("}")?;
            }

            ValueHint::Tuple(hints) => {
                if hints.is_empty() {
                    f.write_str("[]")?;
                    return Ok(());
                }
                write!(f, "[\n{:indent$}", "")?;
                for hint in *hints {
                    f.write_str(indent_str)?;
                    hint.fmt_indent(next_indent, f)?;
                    write!(f, ",\n{:indent$}", "")?;
                }
                f.write_str("]")?;
            }

            ValueHint::Array(inner) => {
                f.write_str("[ ")?;
                inner.fmt_indent(indent, f)?;
                f.write_str(", .. ]")?;
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for ValueHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indent(0, f)
    }
}
