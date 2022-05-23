//! Top-level node binary

mod options;
mod runner;

async fn run() -> anyhow::Result<()> {
    let opts = options::Options::from_args(std::env::args_os());

    logging::init_logging(opts.log_path.as_ref());
    logging::log::trace!("Command line options: {:?}", opts);

    runner::run(opts).await
}

#[tokio::main]
async fn main() {
    run().await.unwrap_or_else(|err| {
        eprintln!("ERROR: {}", err);
        std::process::exit(1)
    })
}
