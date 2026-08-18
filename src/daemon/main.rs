use devault::daemon::Daemon;
use devault::ipc::get_socket_path;
use devault::error::DevaultResult;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> DevaultResult<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let socket_path = get_socket_path();
    let daemon = Daemon::new(socket_path);
    daemon.run().await?;
    Ok(())
}