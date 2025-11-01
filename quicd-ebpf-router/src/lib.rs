use aya::{maps::SockHash, programs::SkMsg};
use common::SockKey;
#[rustfmt::skip]
use log::debug;

// Re-export Cookie utilities for applications
pub use common::Cookie;

/// Standard Connection ID length used by this router (8 bytes)
pub const CID_LENGTH: usize = 8;

/// Helper struct for working with QUIC Connection IDs
/// 
/// # Overview
/// 
/// This module provides utilities to embed routing cookies into QUIC Connection IDs,
/// enabling eBPF-based routing of QUIC packets to specific worker sockets.
/// 
/// # QUIC Connection ID Flow
/// 
/// 1. **Client sends Initial packet** - Contains client-chosen DCID (no valid cookie)
/// 2. **Server generates SCID** - Server creates a new Connection ID with embedded cookie
/// 3. **Server responds** - Sends Initial/Handshake with the new CID as SCID
/// 4. **Client adopts SCID** - Client uses server's SCID as DCID in subsequent packets
/// 5. **eBPF routes packets** - eBPF extracts cookie from DCID and redirects to correct socket
/// 
/// # Cookie Format
/// 
/// The 16-bit cookie is embedded in bytes 6-7 of the 8-byte Connection ID:
/// - Bits 11-15 (5 bits): Generation counter (allows rotation)
/// - Bits 3-10 (8 bits): Worker/socket index (0-255)
/// - Bits 0-2 (3 bits): Checksum for validation
/// 
/// # Example Usage
/// 
/// ```no_run
/// use quicd_ebpf_router::{ConnectionId, Cookie};
/// 
/// // When receiving a client Initial packet without a valid cookie:
/// let worker_idx = 42u8; // This socket's worker index
/// let generation = 0u8;   // Current generation (can increment over time)
/// 
/// // Option 1: Use a proper random number generator for the prefix
/// let mut random_prefix = [0u8; 6];
/// // Fill random_prefix with secure random bytes (e.g., from rand crate)
/// let server_cid = ConnectionId::new(generation, worker_idx, random_prefix);
/// 
/// // Option 2: Use the simple seed-based method (less secure)
/// let prefix_seed = 0x12345678u32; // Could be derived from timestamp, etc.
/// let server_cid = ConnectionId::new_with_seed(generation, worker_idx, prefix_seed);
/// 
/// // Use server_cid as SCID in the Server Initial packet
/// // The client will echo it back as DCID in subsequent packets
/// 
/// // Later, when receiving packets, validate the cookie:
/// if ConnectionId::validate_cookie(&server_cid) {
///     let worker = ConnectionId::get_worker_idx(&server_cid).unwrap();
///     println!("Valid cookie for worker {}", worker);
/// }
/// 
/// // The eBPF program will automatically extract and validate the cookie
/// // and redirect packets to the appropriate socket in the QUICD_WORKERS map
/// ```
pub struct ConnectionId;

impl ConnectionId {
    /// Generate a new 8-byte Connection ID with an embedded cookie
    /// 
    /// The cookie is embedded in bytes 6-7 (big-endian u16).
    /// Bytes 0-5 can be random or application-specific data.
    /// 
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `random_prefix` - 6 bytes of random or application data for bytes 0-5
    /// 
    /// # Returns
    /// An 8-byte array representing the Connection ID
    /// 
    /// # Example
    /// ```
    /// use quicd_ebpf_router::ConnectionId;
    /// 
    /// // Generate random prefix (in real code, use a CSPRNG)
    /// let random_prefix = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    /// let cid = ConnectionId::new(0, 42, random_prefix);
    /// 
    /// // This CID can now be used as SCID in server Initial packet
    /// // Client will echo it back as DCID, allowing eBPF routing
    /// ```
    pub fn new(generation: u8, worker_idx: u8, random_prefix: [u8; 6]) -> [u8; CID_LENGTH] {
        let cookie = Cookie::generate(generation, worker_idx);
        let cookie_bytes = cookie.to_be_bytes();
        
        let mut cid = [0u8; CID_LENGTH];
        cid[0..6].copy_from_slice(&random_prefix);
        cid[6..8].copy_from_slice(&cookie_bytes);
        
        cid
    }
    
    /// Generate a new Connection ID with a simple random prefix
    /// 
    /// This is a convenience method that generates a basic random-looking prefix.
    /// For production use, consider using a cryptographically secure random generator.
    /// 
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `prefix_seed` - A seed value to generate the prefix (for simplicity)
    /// 
    /// # Returns
    /// An 8-byte array representing the Connection ID
    pub fn new_with_seed(generation: u8, worker_idx: u8, prefix_seed: u32) -> [u8; CID_LENGTH] {
        // Simple pseudo-random prefix generation (not cryptographically secure)
        // In production, use a proper CSPRNG
        let prefix = [
            (prefix_seed >> 24) as u8,
            (prefix_seed >> 16) as u8,
            (prefix_seed >> 8) as u8,
            prefix_seed as u8,
            worker_idx.wrapping_mul(17).wrapping_add(generation),
            generation.wrapping_mul(31).wrapping_add(worker_idx),
        ];
        
        Self::new(generation, worker_idx, prefix)
    }
    
    /// Extract the cookie from a Connection ID
    /// 
    /// # Arguments
    /// * `cid` - The Connection ID (must be at least 8 bytes)
    /// 
    /// # Returns
    /// The extracted cookie value, or None if the CID is too short
    pub fn extract_cookie(cid: &[u8]) -> Option<u16> {
        if cid.len() < 8 {
            return None;
        }
        
        Some(u16::from_be_bytes([cid[6], cid[7]]))
    }
    
    /// Validate a Connection ID's cookie
    /// 
    /// # Arguments
    /// * `cid` - The Connection ID to validate
    /// 
    /// # Returns
    /// `true` if the cookie is valid, `false` otherwise
    pub fn validate_cookie(cid: &[u8]) -> bool {
        Self::extract_cookie(cid)
            .map(|cookie| Cookie::validate(cookie))
            .unwrap_or(false)
    }
    
    /// Get the worker index from a Connection ID
    /// 
    /// # Arguments
    /// * `cid` - The Connection ID
    /// 
    /// # Returns
    /// The worker index, or None if extraction fails
    pub fn get_worker_idx(cid: &[u8]) -> Option<u8> {
        Self::extract_cookie(cid).map(|cookie| Cookie::get_worker_idx(cookie))
    }
    
    /// Get the generation from a Connection ID
    /// 
    /// # Arguments
    /// * `cid` - The Connection ID
    /// 
    /// # Returns
    /// The generation, or None if extraction fails
    pub fn get_generation(cid: &[u8]) -> Option<u8> {
        Self::extract_cookie(cid).map(|cookie| Cookie::get_generation(cookie))
    }
}

pub fn setup_rlimit() -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    Ok(())
}

pub fn load_ebpf() -> anyhow::Result<aya::Ebpf> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/quicd-ebpf-router"
    )))?)
}

pub fn attach_program(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let sock_map: SockHash<_, SockKey> = ebpf.map("QUICD_WORKERS").unwrap().try_into()?;
    let map_fd = sock_map.fd().try_clone()?;
    let prog: &mut SkMsg = ebpf.program_mut("quicd_ebpf_router").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&map_fd)?;
    // Insert sockets to the map using sock_map.insert(cookie, socket_fd) here,
    // or from a sock_ops program. The cookie value should match the one embedded
    // in the QUIC connection ID (bytes 6-7).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation_and_validation() {
        // Test cookie generation
        let cookie = Cookie::generate(5, 42);
        
        // Validate the cookie
        assert!(Cookie::validate(cookie));
        
        // Extract components
        assert_eq!(Cookie::get_generation(cookie), 5);
        assert_eq!(Cookie::get_worker_idx(cookie), 42);
    }

    #[test]
    fn test_cookie_checksum() {
        // Valid cookie should validate
        let valid_cookie = Cookie::generate(0, 0);
        assert!(Cookie::validate(valid_cookie));
        
        // Manipulated cookie should fail validation
        let invalid_cookie = valid_cookie ^ 0x0001; // Flip checksum bit
        assert!(!Cookie::validate(invalid_cookie));
    }

    #[test]
    fn test_connection_id_creation() {
        let generation = 3;
        let worker_idx = 17;
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        
        let cid = ConnectionId::new(generation, worker_idx, prefix);
        
        // Check length
        assert_eq!(cid.len(), CID_LENGTH);
        
        // Check prefix is preserved
        assert_eq!(&cid[0..6], &prefix);
        
        // Validate cookie
        assert!(ConnectionId::validate_cookie(&cid));
        
        // Extract components
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));
    }

    #[test]
    fn test_connection_id_with_seed() {
        let generation = 7;
        let worker_idx = 99;
        let seed = 0x12345678;
        
        let cid = ConnectionId::new_with_seed(generation, worker_idx, seed);
        
        // Validate
        assert!(ConnectionId::validate_cookie(&cid));
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));
    }

    #[test]
    fn test_cookie_extraction() {
        let cid = ConnectionId::new_with_seed(2, 50, 0xABCDEF);
        
        let cookie = ConnectionId::extract_cookie(&cid).unwrap();
        assert!(Cookie::validate(cookie));
        assert_eq!(Cookie::get_generation(cookie), 2);
        assert_eq!(Cookie::get_worker_idx(cookie), 50);
    }

    #[test]
    fn test_short_cid_handling() {
        let short_cid = [0x01, 0x02, 0x03]; // Too short
        
        assert_eq!(ConnectionId::extract_cookie(&short_cid), None);
        assert!(!ConnectionId::validate_cookie(&short_cid));
        assert_eq!(ConnectionId::get_worker_idx(&short_cid), None);
        assert_eq!(ConnectionId::get_generation(&short_cid), None);
    }

    #[test]
    fn test_generation_wrap() {
        // Test that generation is properly masked to 5 bits
        let cookie1 = Cookie::generate(31, 0); // Max generation (0b11111)
        let cookie2 = Cookie::generate(32, 0); // Should wrap to 0
        
        assert_eq!(Cookie::get_generation(cookie1), 31);
        assert_eq!(Cookie::get_generation(cookie2), 0);
    }

    #[test]
    fn test_all_workers() {
        // Test that all 256 worker indices work
        for worker_idx in 0..=255 {
            let cookie = Cookie::generate(0, worker_idx);
            assert!(Cookie::validate(cookie));
            assert_eq!(Cookie::get_worker_idx(cookie), worker_idx);
        }
    }
}
