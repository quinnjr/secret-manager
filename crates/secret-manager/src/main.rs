use clap::Parser;
use secret_manager::cli::{Cli, run};
use tracing_subscriber::EnvFilter;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse_from(secret_manager::cli::argv_with_dispatch(std::env::args_os()));
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(run(cli))
}
