#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, sk_msg},
    maps::SockHash,
    programs::SkMsgContext,
};
use aya_log_ebpf::info;
use quicd_ebpf_router_common::SockKey;

#[map]
static QUICD_WORKERS: SockHash<SockKey> = SockHash::<SockKey>::with_max_entries(1024, 0);

#[sk_msg]
pub fn quicd_ebpf_router(ctx: SkMsgContext) -> u32 {
    match try_quicd_ebpf_router(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_quicd_ebpf_router(ctx: SkMsgContext) -> Result<u32, u32> {
    info!(&ctx, "received a message on the socket");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
