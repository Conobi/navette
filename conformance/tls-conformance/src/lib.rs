//! Shared helpers for the TLS-conformance scenario binaries.
//!
//! Each scenario binary `main()` builds adversarial QUIC payloads via
//! `quic_packet::PacketBuilder`, drives a single handshake exchange against
//! the navette server at `server_addr()`, parses the resulting CONNECTION_CLOSE,
//! and exits 0 on the expected error/alert OR 1 otherwise (per AC-2 RED-capture
//! semantics).

pub mod quic_packet;

use std::net::{SocketAddr, Ipv4Addr};
pub use quic_packet::{
    ConnectionClose, KeysHandle, LongHeader, PacketBuilder, Role, ShortHeader,
    decode_varint, encode_varint, initial_keys, parse_connection_close,
    parse_long_header, parse_short_header,
};

/// Returns the navette server's UDP address.
///
/// Reads `TLS_SERVER_PORT` from the environment; defaults to 4433.
/// Always returns 127.0.0.1:<port>.
pub fn server_addr() -> SocketAddr {
    let port = std::env::var("TLS_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(4433);
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Verifies a parsed CONNECTION_CLOSE is a CRYPTO_ERROR (frame_type=0x1c,
/// error_code in 0x0100..=0x01ff per RFC 9001 §4.8) AND the low byte (the TLS
/// alert code) is in `allowed`.
///
/// Used by every C6 scenario binary to satisfy AC-3.alert's
/// "low byte ∈ {RFC, 50}" check. Returns `Ok(())` on match, `Err(diagnostic)`
/// otherwise.
pub fn assert_crypto_error_low_byte(cc: &ConnectionClose, allowed: &[u8]) -> Result<(), String> {
    if cc.frame_type != 0x1c {
        return Err(format!(
            "expected transport CONNECTION_CLOSE (frame_type=0x1c), got 0x{:02x}",
            cc.frame_type,
        ));
    }
    let code = cc.error_code;
    if !(0x0100..=0x01ff).contains(&code) {
        return Err(format!(
            "expected CRYPTO_ERROR range 0x0100..=0x01ff, got 0x{:x}",
            code,
        ));
    }
    let low = (code & 0xff) as u8;
    if !allowed.contains(&low) {
        return Err(format!(
            "expected CRYPTO_ERROR low byte ∈ {:?}, got {} (full code 0x{:x})",
            allowed, low, code,
        ));
    }
    Ok(())
}

/// Verifies a parsed CONNECTION_CLOSE is transport-CC with
/// TRANSPORT_PARAMETER_ERROR (0x08 per RFC 9000 §20.1) AND the GUARD-TAG
/// bracketed string is a substring of the reason phrase.
///
/// Used by C1 (transport-parameter) scenario binaries. Returns `Ok(())` on
/// match, `Err(diagnostic)` otherwise.
pub fn assert_transport_param_error_with_tag(
    cc: &ConnectionClose,
    tag: &str,
) -> Result<(), String> {
    if cc.frame_type != 0x1c {
        return Err(format!(
            "expected transport CONNECTION_CLOSE (frame_type=0x1c), got 0x{:02x}",
            cc.frame_type,
        ));
    }
    if cc.error_code != 0x08 {
        return Err(format!(
            "expected TRANSPORT_PARAMETER_ERROR (0x08), got 0x{:x}",
            cc.error_code,
        ));
    }
    if !cc.reason.contains(tag) {
        return Err(format!(
            "expected reason to contain {:?}, got {:?}",
            tag, cc.reason,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addr_reads_port_env() {
        std::env::set_var("TLS_SERVER_PORT", "5555");
        assert_eq!(server_addr().port(), 5555);
        std::env::remove_var("TLS_SERVER_PORT");
        assert_eq!(server_addr().port(), 4433);
    }
}
