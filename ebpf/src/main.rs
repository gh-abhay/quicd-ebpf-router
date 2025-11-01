#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, sk_msg},
    maps::SockHash,
    programs::SkMsgContext,
};
use aya_log_ebpf::info;
use common::SockKey;

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
    // Extract the cookie from the QUIC connection ID
    let cookie = match extract_cookie(&ctx) {
        Some(c) => c,
        None => {
            info!(&ctx, "failed to extract cookie, passing through");
            return Ok(0); // SK_PASS
        }
    };

    // Validate the cookie checksum
    let generation = cookie >> 11;
    let idx = (cookie >> 3) & 0xff;
    let chksum = cookie & 0x7;
    let sum = generation + idx;
    
    if chksum != (sum & 0x7) {
        info!(&ctx, "invalid cookie checksum, passing through");
        return Ok(0); // SK_PASS (invalid cookie, treat as new)
    }

    info!(&ctx, "valid cookie found: {}, redirecting", cookie);

    // Redirect to the socket associated with this cookie
    let ret = QUICD_WORKERS.redirect_msg(&ctx, cookie, 0);

    if ret < 0 {
        info!(&ctx, "redirect failed, passing through");
        Ok(0) // SK_PASS if redirect failed
    } else {
        Ok(ret as u32) // SK_REDIRECT
    }
}

/// Extract the 16-bit cookie from the QUIC connection ID (DCID)
fn extract_cookie(ctx: &SkMsgContext) -> Option<u16> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    // Check if we have at least 1 byte for the first byte
    if data_end <= data_start {
        return None;
    }
    
    let data_len = data_end - data_start;
    if data_len < 1 {
        return None;
    }

    // Read first byte to determine packet type
    let first_byte = unsafe { *(data_start as *const u8) };
    
    let mut dcid: [u8; 8] = [0; 8];

    if first_byte & 0x80 == 0 {
        // Short header packet: 1 byte flags + 8 byte DCID
        if data_len < 1 + 8 {
            return None;
        }
        
        // Read 8 bytes of DCID starting at offset 1
        for i in 0..8 {
            dcid[i] = unsafe { *((data_start + 1 + i) as *const u8) };
        }
    } else {
        // Long header packet: 1 byte flags + 4 bytes version + 1 byte DCID len + DCID
        if data_len < 6 {
            return None;
        }

        // Read version (bytes 1-4)
        let version = unsafe {
            u32::from_be_bytes([
                *((data_start + 1) as *const u8),
                *((data_start + 2) as *const u8),
                *((data_start + 3) as *const u8),
                *((data_start + 4) as *const u8),
            ])
        };

        // Check QUIC version 1
        if version != 1 {
            return None;
        }

        // Read DCID length (byte 5)
        let dcid_len = unsafe { *((data_start + 5) as *const u8) } as usize;

        // We expect 8-byte DCID
        if dcid_len != 8 {
            return None;
        }

        // Check if we have enough data
        if data_len < 6 + 8 {
            return None;
        }

        // Read 8 bytes of DCID starting at offset 6
        for i in 0..8 {
            dcid[i] = unsafe { *((data_start + 6 + i) as *const u8) };
        }
    }

    // Extract cookie from bytes 6-7 of the DCID
    let cookie = u16::from_be_bytes([dcid[6], dcid[7]]);

    Some(cookie)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
