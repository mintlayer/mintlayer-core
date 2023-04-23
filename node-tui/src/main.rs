pub async fn run() -> anyhow::Result<()> {
    let opts = node::Options::from_args(std::env::args_os());
    logging::init_logging::<&std::path::Path>(None);
    logging::log::info!("Command line options: {opts:?}");
    node::run(opts).await
}

#[tokio::main]
async fn main() {
    run().await.unwrap_or_else(|err| {
        eprintln!("Mintlayer node launch failed: {err:?}");
        std::process::exit(1)
    })
}
