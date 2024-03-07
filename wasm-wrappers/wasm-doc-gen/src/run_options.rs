use clap::Parser;

#[derive(Parser, Clone, Debug, Default)]
pub struct DocGenRunOptions {
    /// The path, to which the file will be written.
    /// If not specified, stdout will be used
    #[clap(long, short('o'), default_value = None)]
    pub output_file: Option<std::path::PathBuf>,

    /// The title of the documentation
    #[clap(long, short('t'))]
    pub doc_title: Option<String>,

    /// Whether to only check the target file without writing to an output file
    #[clap(long, short('c'))]
    pub check: bool,
}
