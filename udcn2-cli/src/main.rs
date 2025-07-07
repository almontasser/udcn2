use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::net::SocketAddr;
use tokio::time::{Duration, Instant};
use udcn2_common::{Interest, Name};
use udcn2_quic::QuicTransport;

#[derive(Parser)]
#[command(name = "udcn2-cli")]
#[command(about = "μDCN CLI tool for benchmarking and traffic generation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Interest packets
    Interest {
        /// Target server address
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        server: SocketAddr,
        /// Name to request
        #[arg(short, long, default_value = "/example/data")]
        name: String,
        /// Number of requests to send
        #[arg(short, long, default_value = "1")]
        count: u64,
        /// Interval between requests in milliseconds
        #[arg(short, long, default_value = "1000")]
        interval: u64,
    },
    /// Run benchmark tests
    Benchmark {
        /// Target server address
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        server: SocketAddr,
        /// Number of concurrent connections
        #[arg(short, long, default_value = "10")]
        connections: u64,
        /// Duration of benchmark in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    // Initialize crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;
    
    let cli = Cli::parse();

    match &cli.command {
        Commands::Interest { server, name, count, interval } => {
            run_interest_test(*server, name, *count, *interval).await?;
        }
        Commands::Benchmark { server, connections, duration } => {
            run_benchmark(*server, *connections, *duration).await?;
        }
    }

    Ok(())
}

async fn run_interest_test(server: SocketAddr, name: &str, count: u64, interval: u64) -> Result<()> {
    let bind_addr = "127.0.0.1:0".parse()?;
    let transport = QuicTransport::new(bind_addr)?;
    
    info!("Starting Interest test: {} requests to {}", count, server);
    
    for i in 0..count {
        let interest = Interest::new(Name::new(format!("{}/{}", name, i)));
        let start = Instant::now();
        
        match transport.send_interest(interest, server).await {
            Ok(data) => {
                let duration = start.elapsed();
                info!("Request {}: Got data '{}' in {:?}", i, data.name(), duration);
            }
            Err(e) => {
                log::error!("Request {}: Failed: {}", i, e);
            }
        }
        
        if i < count - 1 {
            tokio::time::sleep(Duration::from_millis(interval)).await;
        }
    }
    
    Ok(())
}

async fn run_benchmark(server: SocketAddr, connections: u64, duration: u64) -> Result<()> {
    info!("Starting benchmark: {} connections for {} seconds", connections, duration);
    
    let mut handles = Vec::new();
    let test_duration = Duration::from_secs(duration);
    
    for i in 0..connections {
        let server_addr = server;
        let handle = tokio::spawn(async move {
            let bind_addr = "127.0.0.1:0".parse().unwrap();
            let transport = QuicTransport::new(bind_addr).unwrap();
            
            let mut requests = 0u64;
            let mut successes = 0u64;
            let start = Instant::now();
            
            while start.elapsed() < test_duration {
                let interest = Interest::new(Name::new(format!("/benchmark/{}", requests)));
                
                match transport.send_interest(interest, server_addr).await {
                    Ok(_) => successes += 1,
                    Err(_) => {}
                }
                
                requests += 1;
            }
            
            (i, requests, successes)
        });
        
        handles.push(handle);
    }
    
    // Wait for all connections to complete
    let mut total_requests = 0u64;
    let mut total_successes = 0u64;
    
    for handle in handles {
        let (conn_id, requests, successes) = handle.await?;
        total_requests += requests;
        total_successes += successes;
        info!("Connection {}: {} requests, {} successes", conn_id, requests, successes);
    }
    
    let success_rate = if total_requests > 0 {
        (total_successes as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };
    
    info!("Benchmark complete:");
    info!("Total requests: {}", total_requests);
    info!("Total successes: {}", total_successes);
    info!("Success rate: {:.2}%", success_rate);
    info!("Requests per second: {:.2}", total_requests as f64 / duration as f64);
    
    Ok(())
}