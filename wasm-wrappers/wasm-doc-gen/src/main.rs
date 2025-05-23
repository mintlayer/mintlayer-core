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

mod run_options;

use std::io::{Read, Write};

use clap::Parser;
use run_options::DocGenRunOptions;

trait Documentable {
    fn name(&self) -> &str;
    fn docs(&self) -> &str;
    fn title(&self) -> &str;
}

#[derive(Debug)]
struct StructData {
    struct_name: String,
    docs: String,
}

impl StructData {
    fn from_item(item: &syn::ItemStruct) -> Option<Self> {
        let item = match item.vis {
            syn::Visibility::Public(_) => item,
            syn::Visibility::Restricted(_) => return None,
            syn::Visibility::Inherited => return None,
        };

        let name = item.ident.to_string();

        let docs = pull_docs_from_attribute(&item.attrs);

        Some(Self {
            struct_name: name,
            docs,
        })
    }

    fn pull_from_items(all_items: &[syn::Item]) -> Vec<StructData> {
        all_items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item) => StructData::from_item(item),
                _ => None,
            })
            .collect()
    }
}

impl Documentable for StructData {
    fn name(&self) -> &str {
        &self.struct_name
    }

    fn docs(&self) -> &str {
        &self.docs
    }

    fn title(&self) -> &str {
        "Struct"
    }
}

struct EnumData {
    enum_name: String,
    docs: String,
}

impl EnumData {
    fn from_item(item: &syn::ItemEnum) -> Option<Self> {
        let item = match item.vis {
            syn::Visibility::Public(_) => item,
            syn::Visibility::Restricted(_) => return None,
            syn::Visibility::Inherited => return None,
        };

        let name = item.ident.to_string();

        let docs = pull_docs_from_attribute(&item.attrs);

        Some(Self {
            enum_name: name,
            docs,
        })
    }

    fn pull_from_items(all_items: &[syn::Item]) -> Vec<EnumData> {
        all_items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Enum(item) => EnumData::from_item(item),
                _ => None,
            })
            .collect()
    }
}

impl Documentable for EnumData {
    fn name(&self) -> &str {
        &self.enum_name
    }

    fn docs(&self) -> &str {
        &self.docs
    }

    fn title(&self) -> &str {
        "Enum"
    }
}

#[derive(Debug)]
struct FunctionData {
    function_name: String,
    docs: String,
}

impl FunctionData {
    fn from_item(item: &syn::ItemFn) -> Option<Self> {
        let item = match item.vis {
            syn::Visibility::Public(_) => item,
            syn::Visibility::Restricted(_) => return None,
            syn::Visibility::Inherited => return None,
        };

        let name = item.sig.ident.to_string();

        let docs = pull_docs_from_attribute(&item.attrs);

        Some(FunctionData {
            function_name: name,
            docs,
        })
    }

    fn pull_from_items(all_items: &[syn::Item]) -> Vec<FunctionData> {
        all_items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) => FunctionData::from_item(item),
                _ => None,
            })
            .collect()
    }
}

impl Documentable for FunctionData {
    fn name(&self) -> &str {
        &self.function_name
    }

    fn docs(&self) -> &str {
        &self.docs
    }

    fn title(&self) -> &str {
        "Function"
    }
}

fn pull_docs_from_attribute(attrs: &[syn::Attribute]) -> String {
    let docs = attrs
        .iter()
        .filter_map(|m| m.meta.require_name_value().ok())
        .filter(|m| m.path.is_ident("doc"))
        .filter_map(|v| match &v.value {
            syn::Expr::Lit(lit) => Some(lit),
            _ => None,
        })
        .filter_map(|l| match &l.lit {
            syn::Lit::Str(s) => Some(s),
            _ => None,
        })
        .map(|s| s.value().trim().to_string())
        .collect::<Vec<_>>();

    docs.join("\n")
}

fn write_to_stream<'a, D: Documentable>(
    large_title: Option<impl AsRef<str>>,
    data: impl IntoIterator<Item = D>,
    stream: &mut std::io::BufWriter<Box<dyn std::io::Write + 'a>>,
) -> anyhow::Result<()> {
    if let Some(title) = large_title {
        stream.write_all(format!("## {}", title.as_ref()).as_bytes())?;
        stream.write_all("\n\n".as_bytes())?;
    }

    for item in data {
        stream.write_all(format!("### {}: `{}`", item.title(), item.name()).as_bytes())?;
        stream.write_all("\n\n".as_bytes())?;

        stream.write_all(item.docs().to_string().as_bytes())?;
        stream.write_all("\n\n".as_bytes())?;
    }

    Ok(())
}

fn write_docs_to_data_vec(
    docs_title: Option<impl AsRef<str>>,
    library_file_paths: impl IntoIterator<Item = impl AsRef<std::path::Path>>,
) -> anyhow::Result<Vec<u8>> {
    let mut expected_doc_file_data = Vec::new();

    for library_file_path in library_file_paths {
        let file_to_doc =
            std::fs::read_to_string(library_file_path).expect("Source file not found");
        let file_to_doc_contents = syn::parse_file(&file_to_doc).expect("Unable to parse file");

        let fn_docs = FunctionData::pull_from_items(&file_to_doc_contents.items);
        let enum_docs = EnumData::pull_from_items(&file_to_doc_contents.items);
        let struct_docs = StructData::pull_from_items(&file_to_doc_contents.items);

        {
            let mut stream: std::io::BufWriter<Box<dyn std::io::Write>> =
                std::io::BufWriter::new(Box::new(&mut expected_doc_file_data));

            write_to_stream(docs_title.as_ref(), fn_docs, &mut stream)?;
            write_to_stream(docs_title.as_ref(), enum_docs, &mut stream)?;
            write_to_stream(docs_title.as_ref(), struct_docs, &mut stream)?;
        }
    }

    Ok(expected_doc_file_data)
}

fn open_output_file(file_path: impl AsRef<std::path::Path>) -> anyhow::Result<std::fs::File> {
    let out_file_obj = std::fs::File::create(file_path.as_ref());
    let out_file_obj = match out_file_obj {
        Ok(f) => f,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to open output file {}: {e}",
                file_path.as_ref().display()
            ));
        }
    };
    Ok(out_file_obj)
}

fn main() -> anyhow::Result<()> {
    let args = DocGenRunOptions::parse();

    let generated_doc_data = write_docs_to_data_vec(
        args.doc_title,
        [
            "wasm-wrappers/src/lib.rs",
            "wasm-wrappers/src/encode_input.rs",
            "wasm-wrappers/src/encode_output.rs",
            "wasm-wrappers/src/types.rs",
        ],
    )?;

    if args.check {
        if let Some(ref file_path) = args.output_file {
            let mut file = match std::fs::File::open(file_path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to open file {} to check docs: {e}\n
                        Does it really exist?",
                        file_path.display()
                    ))
                }
            };

            let mut doc_file_data = Vec::new();
            file.read_to_end(&mut doc_file_data).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read file {} to check docs: {e}",
                    file_path.display()
                )
            })?;

            if generated_doc_data != doc_file_data {
                return Err(anyhow::anyhow!(
                    "Expected doc data and current doc data in {} didn't match. Consider regenerating docs",
                    file_path.display()
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Cannot run doc-generator in check-mode without specifying an output file",
            ));
        }
    } else {
        let mut output_stream: Box<dyn std::io::Write> = match args.output_file {
            Some(outfile) => Box::new(open_output_file(outfile)?),
            None => Box::new(std::io::stdout()),
        };

        output_stream
            .write_all(generated_doc_data.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to write documentation to output stream: {e}",))?;
    }

    Ok(())
}
