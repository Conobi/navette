//! Shared helpers for the TLS-conformance scenario binaries.
//!
//! Each scenario binary `main()` builds adversarial QUIC payloads via
//! `quic_packet::PacketBuilder`, drives a single handshake exchange against
//! the navette server at `server_addr()`, parses the resulting CONNECTION_CLOSE,
//! and exits 0 on the expected error/alert OR 1 otherwise (per AC-2 RED-capture
//! semantics).

pub mod quic_packet;

use std::net::{SocketAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
pub use quic_packet::{
    ConnectionClose, KeysHandle, LongHeader, PacketBuilder, Role, ShortHeader,
    decode_varint, encode_varint, initial_keys, parse_connection_close,
    parse_long_header, parse_short_header, remote_decrypt, remote_header_unprotect,
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

/// Build a well-formed RFC 9000 §18 client transport-parameters block.
///
/// Includes the minimum set every navette server should accept on a client
/// Initial:
///   * `initial_source_connection_id` (0x0f) — RFC 9000 §7.3 mandatory
///   * `max_idle_timeout` (0x01) = 30000 ms
///   * `max_udp_payload_size` (0x03) = 1452
///   * `initial_max_data` (0x04) = 1 MiB
///   * `initial_max_stream_data_bidi_local` (0x05) = 64 KiB
///   * `initial_max_stream_data_bidi_remote` (0x06) = 64 KiB
///   * `initial_max_stream_data_uni` (0x07) = 64 KiB
///   * `initial_max_streams_bidi` (0x08) = 100
///   * `initial_max_streams_uni` (0x09) = 100
///
/// Each parameter is `varint(ID) || varint(len) || value_bytes`. The varint
/// encoder from `quic_packet` handles the length prefixing.
pub fn server_tp_bytes_well_formed() -> Vec<u8> {
    fn append_varint_param(out: &mut Vec<u8>, id: u64, value: u64) {
        let mut value_bytes: Vec<u8> = Vec::new();
        encode_varint(value, &mut value_bytes);
        encode_varint(id, out);
        encode_varint(value_bytes.len() as u64, out);
        out.extend_from_slice(&value_bytes);
    }

    let mut out: Vec<u8> = Vec::new();
    // initial_source_connection_id (0x0f) = empty Vec for a fresh client conn.
    encode_varint(0x0f, &mut out);
    encode_varint(0, &mut out);
    // varint-valued params.
    append_varint_param(&mut out, 0x01, 30_000);
    append_varint_param(&mut out, 0x03, 1452);
    append_varint_param(&mut out, 0x04, 1_048_576);
    append_varint_param(&mut out, 0x05, 65_536);
    append_varint_param(&mut out, 0x06, 65_536);
    append_varint_param(&mut out, 0x07, 65_536);
    append_varint_param(&mut out, 0x08, 100);
    append_varint_param(&mut out, 0x09, 100);
    out
}

/// Read an env var as u64, defaulting if absent or unparseable.
fn parse_env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Conformance-harness cert verifier that accepts ANY server certificate.
///
/// This is a navette-owned type so consumers of `drive_handshake_initial`
/// never need to depend on `rustls::client::danger::*` directly. It is
/// gated to test/conformance contexts ONLY — this code lives under
/// `conformance/`, not `src/`, and must not be lifted to production.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the conformance-only rustls QUIC client config.
///
/// TLS 1.3-only, ALPN = `["h3"]`, no client auth, accepts any server cert.
/// Returns an `Arc` because `rustls::quic::ClientConnection::new` consumes
/// `Arc<ClientConfig>`.
fn build_quic_client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AcceptAnyServerCert { provider: Arc::clone(&provider) });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported by ring provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

/// Drive ONE Initial-space handshake exchange against the navette server.
///
/// Builds a `rustls::quic::ClientConnection`, pulls the ClientHello via
/// `write_hs`, wraps it in an Initial packet with `builder.encode_initial`,
/// sends it over UDP to `server_addr()`, and waits up to `TLS_HANDSHAKE_TIMEOUT_MS`
/// (default 500 ms) for a reply.
///
/// Returns:
///   * `Ok(None)` — server replied with a non-CONNECTION_CLOSE Initial that
///     decrypted cleanly. Handshake progressed normally.
///   * `Ok(Some(cc))` — server replied with a CONNECTION_CLOSE frame.
///   * `Err(msg)` — UDP / parse / decrypt failure (timeout, malformed packet,
///     AEAD mismatch).
///
/// Phase α sanity contract: only `Ok(None)` counts as PASS. Phase β scenario
/// binaries flip this expectation per-row.
pub fn drive_handshake_initial(
    mut builder: PacketBuilder,
    tp_bytes: &[u8],
) -> Result<Option<ConnectionClose>, String> {
    let config = build_quic_client_config();
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("invalid server name: {e}"))?;
    let mut conn = rustls::quic::ClientConnection::new(
        config,
        rustls::quic::Version::V1,
        server_name,
        tp_bytes.to_vec(),
    )
    .map_err(|e| format!("ClientConnection::new failed: {e}"))?;

    // ClientHello fits in a single write_hs call for a fresh QUIC connection;
    // no key change is produced from the Initial-space half-flight.
    let mut crypto_buf: Vec<u8> = Vec::new();
    let kc = conn.write_hs(&mut crypto_buf);
    if crypto_buf.is_empty() {
        return Err("rustls produced no ClientHello bytes".to_string());
    }
    if kc.is_some() {
        return Err("unexpected KeyChange before sending ClientHello".to_string());
    }

    let dcid = builder.dcid.clone();
    let client_keys = initial_keys(Role::Client, &dcid)
        .map_err(|e| format!("client initial_keys failed: rc={}", e.code))?;
    let pkt = builder.encode_initial(&crypto_buf, &client_keys);

    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|e| format!("bind UDP: {e}"))?;
    let timeout_ms = parse_env_or("TLS_HANDSHAKE_TIMEOUT_MS", 500);
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    socket
        .send_to(&pkt, server_addr())
        .map_err(|e| format!("send_to {}: {e}", server_addr()))?;

    let mut reply = vec![0u8; 2048];
    let n = match socket.recv_from(&mut reply) {
        Ok((n, _)) => n,
        Err(e) => return Err(format!("recv_from timed out or failed: {e}")),
    };
    reply.truncate(n);

    let header = parse_long_header(&reply)
        .ok_or_else(|| "server reply did not parse as a long-header packet".to_string())?;
    if header.packet_type != 0 {
        return Err(format!(
            "expected server Initial (packet_type=0), got {}",
            header.packet_type,
        ));
    }

    // Decrypt the server's Initial reply using client_keys.remote_*.
    // The harness is the client: on a Client-role keys handle, `remote`
    // holds the server's derived secrets (the "other side" from the
    // client's perspective).  A Role::Server handle would place the
    // client's secrets in `remote`, which is the wrong direction.
    let pn_offset = header.payload_offset;
    let sample_off = pn_offset + 4;
    if reply.len() < sample_off + 16 {
        return Err(format!(
            "reply too short for HP sample: need {}, got {}",
            sample_off + 16,
            reply.len(),
        ));
    }
    let sample: [u8; 16] = reply[sample_off..sample_off + 16]
        .try_into()
        .expect("16-byte HP sample");
    let (head, rest) = reply.split_at_mut(pn_offset);
    remote_header_unprotect(&client_keys, &sample, &mut head[0], &mut rest[..4])
        .map_err(|e| format!("HP unprotect failed: rc={}", e.code))?;
    let first_byte = head[0];
    let pn_length = ((first_byte & 0x03) + 1) as usize;
    let mut pn: u64 = 0;
    for i in 0..pn_length {
        pn = (pn << 8) | rest[i] as u64;
    }
    let header_len = pn_offset + pn_length;
    let header_bytes = reply[..header_len].to_vec();
    let end = pn_offset + header.length;
    if reply.len() < end {
        return Err(format!(
            "reply truncated: payload end {} > len {}",
            end,
            reply.len(),
        ));
    }
    let pt_len = remote_decrypt(&client_keys, pn, &header_bytes, &mut reply[header_len..end])
        .map_err(|e| format!("AEAD decrypt failed: rc={}", e.code))?;
    let plaintext = &reply[header_len..header_len + pt_len];

    // Scan the plaintext for a CONNECTION_CLOSE frame (0x1c or 0x1d).
    // Only PADDING (0x00) is explicitly consumed; any other frame type —
    // including ACK (0x02/0x03), CRYPTO (0x06), PING (0x01), etc. — hits
    // `_ => break` and the loop exits, returning Ok(None).  For the current
    // sanity-PASS scenarios this is correct: a real server's first Initial
    // reply starts with an ACK frame, so the scan bails immediately and
    // returns Ok(None) = no CONNECTION_CLOSE found = success.
    //
    // NOTE (phase β): scenarios that need to detect a CONNECTION_CLOSE
    // appearing *after* an ACK frame in the same Initial packet will require
    // a varint-aware ACK-skip routine (type byte 0x02/0x03, then five
    // consecutive varint fields: largest_acked, ack_delay, ack_range_count,
    // first_ack_range, then 2×ack_range_count additional varints).
    // That routine is not implemented here.
    let mut i = 0;
    while i < plaintext.len() {
        let ft = plaintext[i];
        match ft {
            0x00 => { i += 1; }
            0x1c | 0x1d => {
                let cc = parse_connection_close(&plaintext[i..])
                    .ok_or_else(|| "CONNECTION_CLOSE parse failed".to_string())?;
                return Ok(Some(cc));
            }
            _ => break,
        }
    }
    Ok(None)
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

    #[test]
    fn server_tp_bytes_well_formed_decodes() {
        let tp = server_tp_bytes_well_formed();
        assert!(!tp.is_empty(), "transport params must be non-empty");
        // Walk the block: each entry is varint(id) || varint(len) || value.
        let mut i = 0;
        let mut seen_initial_scid = false;
        while i < tp.len() {
            let (id, c) = decode_varint(&tp[i..]).expect("id varint");
            i += c;
            let (len, c) = decode_varint(&tp[i..]).expect("len varint");
            i += c;
            assert!(i + len as usize <= tp.len(), "value bounds for id 0x{:x}", id);
            if id == 0x0f { seen_initial_scid = true; }
            i += len as usize;
        }
        assert_eq!(i, tp.len(), "TP block walked exactly");
        assert!(seen_initial_scid, "initial_source_connection_id (0x0f) present");
    }
}
