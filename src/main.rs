use devault::cli::run;
use devault::cli::Cli;
use devault::error::DevaultResult;
use clap::Parser;

#[tokio::main]
async fn main() -> DevaultResult<()> {
    let cli = Cli::parse();
    
    if let Err(e) = run(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}