mod run_options;

use std::io::Write;

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

    fn pull_from_items(all_items: &Vec<syn::Item>) -> Vec<StructData> {
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

    fn pull_from_items(all_items: &Vec<syn::Item>) -> Vec<EnumData> {
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

    fn pull_from_items(all_items: &Vec<syn::Item>) -> Vec<FunctionData> {
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

fn pull_docs_from_attribute(attrs: &Vec<syn::Attribute>) -> String {
    let docs = attrs
        .iter()
        .filter_map(|m| m.meta.require_name_value().ok())
        .filter(|m| {
            m.path.segments.first().is_some()
                && m.path.segments.first().expect("Was checked").ident.to_string() == "doc"
        })
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

        stream.write_all(format!("{}", item.docs()).as_bytes())?;
        stream.write_all("\n\n".as_bytes())?;
    }

    Ok(())
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
    let file = std::fs::read_to_string("wasm-wrappers/src/lib.rs").expect("Source file not found");
    let file_contents = syn::parse_file(&file).expect("Unable to parse file");

    let fn_docs = FunctionData::pull_from_items(&file_contents.items);
    let enum_docs = EnumData::pull_from_items(&file_contents.items);
    let struct_docs = StructData::pull_from_items(&file_contents.items);

    let args = DocGenRunOptions::parse();

    let output_stream: Box<dyn std::io::Write> = match args.output_file {
        Some(outfile) => Box::new(open_output_file(outfile)?),
        None => Box::new(std::io::stdout()),
    };

    let mut stream = Box::new(std::io::BufWriter::new(output_stream));

    write_to_stream(args.doc_title.as_ref(), fn_docs, stream.as_mut())?;
    write_to_stream(args.doc_title.as_ref(), enum_docs, stream.as_mut())?;
    write_to_stream(args.doc_title.as_ref(), struct_docs, stream.as_mut())?;

    Ok(())
}
