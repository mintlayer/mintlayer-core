//! Top-level node binary

mod runner;
mod options;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = options::Options::from_args();

    logging::init_logging(opts.log_path.as_ref());
    logging::log::trace!("Command line options: {:?}", opts);

    let manager = runner::initialize(opts).await?;

    #[allow(clippy::unit_arg)]
    Ok(manager.main().await)
}
