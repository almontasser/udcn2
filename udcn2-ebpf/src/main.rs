#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::{HashMap, LruHashMap},
};
use aya_log_ebpf::info;

// Maximum number of pending interests
const MAX_PIT_ENTRIES: u32 = 1024;
// Maximum number of cached data packets
const MAX_CACHE_ENTRIES: u32 = 512;

// Simplified NDN packet type indicator
#[derive(Clone, Copy)]
#[repr(u8)]
enum NdnPacketType {
    Interest = 0x05,
    Data = 0x06,
}

// Simplified name hash for demonstration
type NameHash = u64;

// PIT entry structure
#[derive(Clone, Copy)]
struct PitEntry {
    name_hash: NameHash,
    timestamp: u64,
    interface: u32,
}

// Cache entry structure  
#[derive(Clone, Copy)]
struct CacheEntry {
    name_hash: NameHash,
    timestamp: u64,
    size: u32,
}

// Statistics counters
#[derive(Clone, Copy)]
struct Stats {
    interests_processed: u64,
    data_processed: u64,
    pit_hits: u64,
    cache_hits: u64,
    packets_dropped: u64,
}

// eBPF maps for NDN forwarding
#[map]
static PIT: LruHashMap<NameHash, PitEntry> = LruHashMap::with_max_entries(MAX_PIT_ENTRIES, 0);

#[map]
static CACHE: LruHashMap<NameHash, CacheEntry> = LruHashMap::with_max_entries(MAX_CACHE_ENTRIES, 0);

#[map]
static STATS: HashMap<u32, Stats> = HashMap::with_max_entries(1, 0);

#[xdp]
pub fn udcn2(ctx: XdpContext) -> u32 {
    match try_udcn2(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_udcn2(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    
    // Basic packet size validation
    if data >= data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Check if packet has minimum size for NDN processing
    let packet_size = data_end - data;
    if packet_size < 2 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Try to identify NDN packet by looking for TLV structure
    let packet_type = unsafe {
        let ptr = data as *const u8;
        if ptr.add(1) >= data_end as *const u8 {
            return Ok(xdp_action::XDP_PASS);
        }
        *ptr
    };
    
    let mut stats = get_stats();
    
    match packet_type {
        0x05 => {
            // Interest packet
            info!(&ctx, "Processing Interest packet");
            stats.interests_processed += 1;
            
            let name_hash = compute_simple_hash(data, packet_size);
            
            // Check cache first
            if let Some(_cache_entry) = unsafe { CACHE.get(&name_hash) } {
                info!(&ctx, "Cache hit for Interest");
                stats.cache_hits += 1;
                update_stats(stats);
                return Ok(xdp_action::XDP_PASS); // Forward to userspace for Data response
            }
            
            // Add to PIT
            let pit_entry = PitEntry {
                name_hash,
                timestamp: 0, // Would use bpf_ktime_get_ns() in real implementation
                interface: 0, // Would get from ctx metadata in real implementation
            };
            
            if let Err(_) = PIT.insert(&name_hash, &pit_entry, 0) {
                info!(&ctx, "Failed to insert PIT entry");
                stats.packets_dropped += 1;
                update_stats(stats);
                return Ok(xdp_action::XDP_DROP);
            }
            
            update_stats(stats);
            Ok(xdp_action::XDP_PASS)
        },
        0x06 => {
            // Data packet
            info!(&ctx, "Processing Data packet");
            stats.data_processed += 1;
            
            let name_hash = compute_simple_hash(data, packet_size);
            
            // Check PIT for matching Interest
            if let Some(_pit_entry) = unsafe { PIT.get(&name_hash) } {
                info!(&ctx, "PIT hit for Data packet");
                stats.pit_hits += 1;
                
                // Remove from PIT
                let _ = PIT.remove(&name_hash);
                
                // Add to cache
                let cache_entry = CacheEntry {
                    name_hash,
                    timestamp: 0, // Would use bpf_ktime_get_ns() in real implementation
                    size: packet_size as u32,
                };
                
                if let Err(_) = CACHE.insert(&name_hash, &cache_entry, 0) {
                    info!(&ctx, "Failed to insert cache entry");
                }
                
                update_stats(stats);
                return Ok(xdp_action::XDP_PASS); // Forward to userspace
            }
            
            // No matching Interest, drop packet
            info!(&ctx, "No matching Interest for Data packet");
            stats.packets_dropped += 1;
            update_stats(stats);
            Ok(xdp_action::XDP_DROP)
        },
        _ => {
            // Not an NDN packet, pass through
            Ok(xdp_action::XDP_PASS)
        }
    }
}

fn get_stats() -> Stats {
    unsafe {
        STATS.get(&0).copied().unwrap_or(Stats {
            interests_processed: 0,
            data_processed: 0,
            pit_hits: 0,
            cache_hits: 0,
            packets_dropped: 0,
        })
    }
}

fn update_stats(stats: Stats) {
    let _ = STATS.insert(&0, &stats, 0);
}

// Simple hash function for demonstration
fn compute_simple_hash(data: usize, size: usize) -> NameHash {
    let mut hash: u64 = 0;
    let mut remaining = size.min(32); // Hash first 32 bytes max
    let mut offset = 0;
    
    while remaining >= 8 && offset < remaining {
        if let Ok(bytes) = unsafe {
            let ptr = (data + offset) as *const u64;
            if ptr.add(1) as usize <= data + size {
                Ok(*ptr)
            } else {
                Err(())
            }
        } {
            hash = hash.wrapping_mul(31).wrapping_add(bytes);
            offset += 8;
            remaining -= 8;
        } else {
            break;
        }
    }
    
    hash
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
