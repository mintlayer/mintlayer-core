use std::env;

#[tokio::main]
async fn main() -> Result<(), node::Error> {
    let opts = node::Options::from_args(env::args_os());
    node::init_logging(&opts);
    node::run(opts).await
}
