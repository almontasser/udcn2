use anyhow::Result;
use clap::Parser;
use log::info;
use std::net::SocketAddr;
use tokio::signal;
use udcn2_quic::QuicServer;

#[derive(Parser)]
#[command(name = "test-server")]
#[command(about = "Simple μDCN test server for development")]
struct Args {
    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Initialize crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;

    info!("Starting μDCN test server on {}", args.bind);
    
    let server = QuicServer::new(args.bind)?;
    let actual_addr = server.local_addr()?;
    
    info!("μDCN test server listening on {}", actual_addr);
    info!("Press Ctrl+C to stop the server");
    
    // Run server with graceful shutdown
    tokio::select! {
        result = server.run() => {
            match result {
                Ok(_) => info!("Server completed successfully"),
                Err(e) => log::error!("Server error: {}", e),
            }
        }
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal, stopping server");
        }
    }
    
    Ok(())
}