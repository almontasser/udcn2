use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    /// Network interface to attach the XDP program to
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    udcn2::run_xdp(&opt.iface).await
}
