use anyhow::{Context, Result};
use aya::{programs::{Xdp, XdpFlags}, Ebpf};
use log::{debug, warn};

/// Load and attach the μDCN XDP program to the given network interface.
///
/// The function bumps the `RLIMIT_MEMLOCK`, loads the compiled eBPF
/// program and attaches it to `iface`. The XDP program will remain
/// attached until the returned future resolves, which happens when a
/// Ctrl‑C signal is received.
pub async fn run_xdp(iface: &str) -> Result<()> {
    // Bump the memlock rlimit for older kernels.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load the eBPF bytecode.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/udcn2"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if all log statements are removed from the eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Attach the XDP program.
    let program: &mut Xdp = ebpf.program_mut("udcn2").unwrap().try_into()?;
    program.load()?;
    program
        .attach(iface, XdpFlags::default())
        .context(
            "failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE",
        )?;

    // Wait for Ctrl-C.
    tokio::signal::ctrl_c().await?;
    Ok(())
}
