//! tls_sanity_handshake — well-formed handshake baseline.
//!
//! Phase α: this is the always-on PASS binary (analogous to h3i's sanity_get).
//! Phase β: continues to PASS; if it ever FAILs, the gate is broken.
//!
//! Exit 0 = server responded without CONNECTION_CLOSE
//! Exit 1 = CONNECTION_CLOSE received OR no reply within timeout

use tls_conformance_scenarios::{
    drive_handshake_initial, server_tp_bytes_well_formed, PacketBuilder,
};
use rand::RngCore;

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp_bytes = server_tp_bytes_well_formed();

    match drive_handshake_initial(builder, &tp_bytes) {
        Ok(None) => {
            // Server replied with a non-CC initial — handshake progressed normally.
            std::process::exit(0);
        }
        Ok(Some(cc)) => {
            eprintln!(
                "tls_sanity_handshake: unexpected CONNECTION_CLOSE error_code=0x{:x} \
                 frame_type=0x{:02x} reason={:?}",
                cc.error_code, cc.frame_type, cc.reason,
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("tls_sanity_handshake: handshake failed: {}", e);
            std::process::exit(1);
        }
    }
}
