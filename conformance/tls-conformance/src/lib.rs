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
use std::time::{Duration, Instant};
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

/// Build the conformance-only rustls QUIC client config with a caller-supplied
/// ALPN list.
///
/// TLS 1.3-only, no client auth, accepts any server cert. Each entry in `alpn`
/// is copied into `ClientConfig::alpn_protocols`. Pass `&[b"h3"]` for the
/// normal handshake path or `&[]` to drive F27 (empty ALPN → server emits
/// `no_application_protocol` alert 120).
///
/// Returns an `Arc` because `rustls::quic::ClientConnection::new` consumes
/// `Arc<ClientConfig>`.
pub fn build_quic_client_config_with_alpn(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AcceptAnyServerCert { provider: Arc::clone(&provider) });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported by ring provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// Drive ONE Initial-space handshake exchange against the navette server.
///
/// Builds a `rustls::quic::ClientConnection`, pulls the ClientHello via
/// `write_hs`, wraps it in an Initial packet with `builder.encode_initial`,
/// sends it over UDP to `server_addr()`, and waits up to `TLS_HANDSHAKE_TIMEOUT_MS`
/// (default 500 ms) for a reply.
///
/// Uses ALPN = `["h3"]`. For F27 (empty ALPN) use
/// `drive_handshake_initial_no_alpn`.
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
    builder: PacketBuilder,
    tp_bytes: &[u8],
) -> Result<Option<ConnectionClose>, String> {
    let config = build_quic_client_config_with_alpn(&[b"h3"]);
    drive_handshake_initial_inner(builder, tp_bytes, config)
}

/// F27 variant of `drive_handshake_initial` that supplies a `ClientConfig`
/// with an empty `alpn_protocols`. The navette server's QUIC config requires
/// `h3`; the TLS layer must emit `no_application_protocol` (alert 120) which
/// surfaces as a CRYPTO_ERROR CONNECTION_CLOSE with low byte 120 (or 50 if
/// rustls couldn't extract a specific alert).
pub fn drive_handshake_initial_no_alpn(
    builder: PacketBuilder,
    tp_bytes: &[u8],
) -> Result<Option<ConnectionClose>, String> {
    let config = build_quic_client_config_with_alpn(&[]);
    drive_handshake_initial_inner(builder, tp_bytes, config)
}

/// Shared body for the Initial-flight drivers. Caller picks the ALPN by
/// supplying a fully-built `ClientConfig`; everything downstream (UDP send,
/// reply decrypt, CONNECTION_CLOSE scan) is identical across variants.
fn drive_handshake_initial_inner(
    mut builder: PacketBuilder,
    tp_bytes: &[u8],
    config: Arc<rustls::ClientConfig>,
) -> Result<Option<ConnectionClose>, String> {
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
    //
    // A real navette server's first Initial reply typically leads with an
    // ACK (0x02/0x03) before the CONNECTION_CLOSE frame, so the scanner has
    // to varint-skip ACK frames per RFC 9000 §19.3:
    //
    //   ACK Frame {
    //     Type (i) = 0x02..0x03,
    //     Largest Acknowledged (i),
    //     ACK Delay (i),
    //     ACK Range Count (i) = N,
    //     First ACK Range (i),
    //     ACK Range (..) ...,  -- N pairs of (Gap, ACK Range Length)
    //     [ECN Counts (..)],   -- 3 varints only when Type = 0x03
    //   }
    //
    // PADDING (0x00) and PING (0x01) are also consumed (single byte each
    // per §19.1 / §19.2). Any other frame type (CRYPTO, NEW_CONNECTION_ID,
    // HANDSHAKE_DONE, etc.) is non-fatal but unparsable here — we bail and
    // return Ok(None) so the caller can decide.
    let mut i = 0;
    while i < plaintext.len() {
        let ft = plaintext[i];
        match ft {
            // PADDING / PING — single byte, no payload.
            0x00 | 0x01 => { i += 1; }
            // ACK / ACK_ECN — varint-skip per RFC 9000 §19.3.
            0x02 | 0x03 => {
                let with_ecn = ft == 0x03;
                let mut p = i + 1; // past type byte
                // Largest Acknowledged, ACK Delay.
                let (_largest, n1) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: largest_acked varint truncated".to_string())?;
                p += n1;
                let (_delay, n2) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: ack_delay varint truncated".to_string())?;
                p += n2;
                // ACK Range Count, First ACK Range.
                let (range_count, n3) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: range_count varint truncated".to_string())?;
                p += n3;
                let (_first, n4) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: first_range varint truncated".to_string())?;
                p += n4;
                // Each ACK Range is two varints: Gap, ACK Range Length.
                for _ in 0..range_count {
                    let (_gap, ng) = decode_varint(&plaintext[p..])
                        .ok_or_else(|| "ACK: gap varint truncated".to_string())?;
                    p += ng;
                    let (_len, nl) = decode_varint(&plaintext[p..])
                        .ok_or_else(|| "ACK: range_len varint truncated".to_string())?;
                    p += nl;
                }
                if with_ecn {
                    // ECT0, ECT1, CE counts.
                    for _ in 0..3 {
                        let (_v, nv) = decode_varint(&plaintext[p..])
                            .ok_or_else(|| "ACK_ECN: count varint truncated".to_string())?;
                        p += nv;
                    }
                }
                i = p;
            }
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

/// Encryption epoch for the multi-epoch `drive_handshake_full` driver.
///
/// Only Handshake and 1-RTT need the rustls-derived keys path; Initial uses
/// the dedicated `KeysHandle` from `librustls-mojo` already exercised by
/// `drive_handshake_initial`. The `OneRtt` variant is reserved for future
/// short-header debug logging — not yet plumbed through the receive loop
/// because the 1-RTT drain returns the CC directly without classifying it.
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
enum Epoch { Initial, Handshake, OneRtt }

/// Outcome of feeding a decrypted QUIC plaintext payload to rustls and
/// scanning it for CONNECTION_CLOSE.
///
/// `cc` is `Some(_)` when a 0x1c/0x1d frame is seen in the plaintext. Even
/// when a CC is observed we still drain the remaining frames into rustls so
/// that the FSM remains consistent (mostly defensive; the harness exits
/// shortly after).
struct PlaintextScan {
    cc: Option<ConnectionClose>,
}

/// Encode a single QUIC CRYPTO frame per RFC 9000 §19.6.
///
/// Wire layout: type byte (0x06) + varint(offset) + varint(length) + bytes.
/// The function is pure — no I/O, no global state. Suitable for unit tests.
fn encode_crypto_frame(offset: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 8 + bytes.len());
    out.push(0x06);
    encode_varint(offset, &mut out);
    encode_varint(bytes.len() as u64, &mut out);
    out.extend_from_slice(bytes);
    out
}

/// Encode + send a Handshake-space (long header, type=2) packet whose only
/// payload is a CRYPTO frame at offset 0 carrying `crypto_payload`.
///
/// `pn` is the application-supplied packet number (caller manages the per-
/// epoch counter). HP + AEAD use the rustls `local` keys for the current
/// epoch. The function intentionally does NOT pad the payload — Handshake
/// packets are not subject to the §14.1 1200-byte anti-amplification rule;
/// the server-side accepts shorter Handshakes.
fn build_handshake_packet(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    crypto_payload: &[u8],
    local_keys: &rustls::quic::DirectionalKeys,
) -> Result<Vec<u8>, String> {
    let pn_length: usize = 4;
    let tag_len = local_keys.packet.tag_len();

    // QUIC payload: one CRYPTO frame (type=0x06, offset=0, len, data).
    let mut qp: Vec<u8> = Vec::new();
    qp.push(0x06);
    encode_varint(0, &mut qp);
    encode_varint(crypto_payload.len() as u64, &mut qp);
    qp.extend_from_slice(crypto_payload);

    // Long header up to (not including) Length field.
    let mut hdr: Vec<u8> = Vec::new();
    hdr.push(0b1100_0000 | (0b10 << 4) | ((pn_length as u8) - 1)); // type=Handshake
    hdr.extend_from_slice(&1u32.to_be_bytes()); // QUIC v1
    hdr.push(dcid.len() as u8); hdr.extend_from_slice(dcid);
    hdr.push(scid.len() as u8); hdr.extend_from_slice(scid);
    // Length = PN + payload + tag.
    let length = pn_length + qp.len() + tag_len;
    encode_varint(length as u64, &mut hdr);
    let pn_offset = hdr.len();
    hdr.extend_from_slice(&(pn as u32).to_be_bytes());

    let header_len = hdr.len();
    let mut pkt: Vec<u8> = Vec::with_capacity(header_len + qp.len() + tag_len);
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(&qp);
    // Reserve tag tail (filled by encrypt_in_place's returned Tag).
    let plaintext_end = header_len + qp.len();

    let header_bytes = pkt[..header_len].to_vec();
    let tag = local_keys.packet.encrypt_in_place(
        pn, &header_bytes, &mut pkt[header_len..plaintext_end],
    ).map_err(|e| format!("rustls encrypt_in_place (Handshake): {e:?}"))?;
    pkt.extend_from_slice(tag.as_ref());

    // HP — sample is 16 bytes starting pn_offset + 4 (per RFC 9001 §5.4.2).
    let so = pn_offset + 4;
    if pkt.len() < so + 16 {
        return Err("Handshake packet too short for HP sample".into());
    }
    let sample: [u8; 16] = pkt[so..so + 16].try_into().expect("HP sample 16B");
    let (head, rest) = pkt.split_at_mut(pn_offset);
    local_keys.header
        .encrypt_in_place(&sample, &mut head[0], &mut rest[..pn_length])
        .map_err(|e| format!("rustls HP encrypt (Handshake): {e:?}"))?;
    Ok(pkt)
}

/// Build a 1-RTT short-header packet carrying a single CRYPTO frame at the
/// given offset. Uses rustls's 1-RTT local keys (`one_rtt.local.packet` for
/// AEAD, `one_rtt.local.header` for HP).
///
/// Short-header layout (RFC 9000 §17.3): first byte `0b0100_00xx` where xx is
/// pn_length - 1 = 3 (we always use 4-byte PNs to match `build_handshake_packet`).
/// Then DCID (no SCID, no length, no version, no token in short-header). Then
/// pn_length-byte PN. Then encrypted payload. Then 16-byte tag.
fn build_short_header_crypto_packet(
    dcid: &[u8],
    pn: u64,
    crypto_frame_bytes: &[u8],
    one_rtt_local: &rustls::quic::DirectionalKeys,
) -> Result<Vec<u8>, String> {
    let pn_length: usize = 4;
    let tag_len = one_rtt_local.packet.tag_len();

    // First byte: 0b0100_0011 → fixed bits 0/1 set, type=Short(0), spin=0,
    // reserved=00, key_phase=0, pn_len = 4-1 = 3 (bits 0-1).
    let first_byte: u8 = 0b0100_0000 | ((pn_length as u8) - 1);

    let mut hdr: Vec<u8> = Vec::with_capacity(1 + dcid.len() + pn_length);
    hdr.push(first_byte);
    hdr.extend_from_slice(dcid);
    let pn_offset = hdr.len();
    hdr.extend_from_slice(&(pn as u32).to_be_bytes());

    let header_len = hdr.len();
    let mut pkt: Vec<u8> = Vec::with_capacity(header_len + crypto_frame_bytes.len() + tag_len);
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(crypto_frame_bytes);
    let plaintext_end = header_len + crypto_frame_bytes.len();

    let header_bytes = pkt[..header_len].to_vec();
    let tag = one_rtt_local.packet.encrypt_in_place(
        pn, &header_bytes, &mut pkt[header_len..plaintext_end],
    ).map_err(|e| format!("rustls encrypt_in_place (1-RTT): {e:?}"))?;
    pkt.extend_from_slice(tag.as_ref());

    // HP — sample is 16 bytes starting pn_offset + 4 (matches Handshake).
    let so = pn_offset + 4;
    if pkt.len() < so + 16 {
        return Err("1-RTT packet too short for HP sample".into());
    }
    let sample: [u8; 16] = pkt[so..so + 16].try_into().expect("HP sample 16B");
    let (head, rest) = pkt.split_at_mut(pn_offset);
    one_rtt_local.header
        .encrypt_in_place(&sample, &mut head[0], &mut rest[..pn_length])
        .map_err(|e| format!("rustls HP encrypt_in_place (1-RTT): {e:?}"))?;

    Ok(pkt)
}

/// Decrypt a single Handshake-space (long header, type=2) packet whose bytes
/// occupy `buf[..pkt_len]`, returning the plaintext payload as a freshly-
/// allocated `Vec`.
///
/// `header` is the parsed long header for this packet (so the caller can
/// reuse the already-walked layout). `remote_keys` are the rustls `remote`
/// keys for the matching epoch. The function performs HP-unprotect then
/// AEAD-decrypt; both operations are done in place on a local copy of the
/// packet so the caller's buffer is left untouched for the next iteration.
fn decrypt_long_with_rustls(
    pkt: &[u8],
    header: &LongHeader,
    remote_keys: &rustls::quic::DirectionalKeys,
) -> Result<Vec<u8>, String> {
    let mut buf = pkt.to_vec();
    let pn_offset = header.payload_offset;
    let so = pn_offset + 4;
    if buf.len() < so + 16 {
        return Err(format!(
            "packet too short for HP sample: need {}, got {}",
            so + 16, buf.len(),
        ));
    }
    let sample: [u8; 16] = buf[so..so + 16].try_into().expect("HP sample 16B");
    let (head, rest) = buf.split_at_mut(pn_offset);
    remote_keys.header
        .decrypt_in_place(&sample, &mut head[0], &mut rest[..4])
        .map_err(|e| format!("rustls HP decrypt: {e:?}"))?;
    let pn_length = ((head[0] & 0x03) + 1) as usize;
    let header_len = pn_offset + pn_length;
    let mut pn: u64 = 0;
    for i in 0..pn_length {
        pn = (pn << 8) | buf[pn_offset + i] as u64;
    }
    let header_bytes = buf[..header_len].to_vec();
    let end = pn_offset + header.length;
    if buf.len() < end {
        return Err(format!(
            "packet truncated: payload end {} > buf len {}", end, buf.len(),
        ));
    }
    let pt = remote_keys.packet
        .decrypt_in_place(pn, &header_bytes, &mut buf[header_len..end])
        .map_err(|e| format!("rustls AEAD decrypt: {e:?}"))?;
    Ok(pt.to_vec())
}

/// Decrypt a short-header (1-RTT) packet whose bytes occupy `buf[..pkt_len]`.
///
/// `dcid_len` MUST match the local CID length advertised at handshake time —
/// short headers do not encode the DCID length on the wire (RFC 9000 §17.3.1).
/// For this harness the navette server uses 8-byte CIDs and the client picks
/// the SCID, so we know dcid_len up front from `builder.scid.len()`.
fn decrypt_short_with_rustls(
    pkt: &[u8],
    dcid_len: usize,
    remote_keys: &rustls::quic::DirectionalKeys,
) -> Result<Vec<u8>, String> {
    if pkt.is_empty() || pkt[0] & 0x80 != 0 {
        return Err("not a short-header packet".into());
    }
    let pn_offset = 1 + dcid_len;
    let so = pn_offset + 4;
    if pkt.len() < so + 16 {
        return Err(format!(
            "1-RTT packet too short for HP sample: need {}, got {}",
            so + 16, pkt.len(),
        ));
    }
    let mut buf = pkt.to_vec();
    let sample: [u8; 16] = buf[so..so + 16].try_into().expect("HP sample 16B");
    let (head, rest) = buf.split_at_mut(pn_offset);
    remote_keys.header
        .decrypt_in_place(&sample, &mut head[0], &mut rest[..4])
        .map_err(|e| format!("rustls HP decrypt (1-RTT): {e:?}"))?;
    let pn_length = ((head[0] & 0x03) + 1) as usize;
    let header_len = pn_offset + pn_length;
    let mut pn: u64 = 0;
    for i in 0..pn_length {
        pn = (pn << 8) | buf[pn_offset + i] as u64;
    }
    let header_bytes = buf[..header_len].to_vec();
    let pt = remote_keys.packet
        .decrypt_in_place(pn, &header_bytes, &mut buf[header_len..])
        .map_err(|e| format!("rustls AEAD decrypt (1-RTT): {e:?}"))?;
    Ok(pt.to_vec())
}

/// Walk a decrypted QUIC plaintext payload, feeding any CRYPTO frames to
/// `conn.read_hs` and returning the first CONNECTION_CLOSE observed.
///
/// Recognised frame types (RFC 9000 §19):
///   * 0x00 PADDING and 0x01 PING — single-byte, skipped.
///   * 0x02/0x03 ACK / ACK_ECN — varint-walked per §19.3.
///   * 0x06 CRYPTO — extracted, data fed to rustls.
///   * 0x1c/0x1d CONNECTION_CLOSE — parsed and surfaced.
///   * 0x18 NEW_CONNECTION_ID — varint-walked so we don't bail on the
///     server's NCID emissions in 1-RTT. We don't need to apply them
///     anywhere since the harness never migrates.
///   * 0x1e HANDSHAKE_DONE — single byte; ignored.
///
/// Anything else terminates the walk early (no further frames inspected in
/// this packet). That's intentional — the harness only needs to find the CC;
/// unknown frames are not a hard error.
fn scan_plaintext_into_rustls(
    plaintext: &[u8],
    conn: &mut rustls::quic::ClientConnection,
) -> Result<PlaintextScan, String> {
    let mut i = 0;
    while i < plaintext.len() {
        let ft = plaintext[i];
        match ft {
            0x00 | 0x01 => { i += 1; }
            0x02 | 0x03 => {
                let with_ecn = ft == 0x03;
                let mut p = i + 1;
                let (_largest, n1) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: largest_acked varint truncated".to_string())?;
                p += n1;
                let (_delay, n2) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: ack_delay varint truncated".to_string())?;
                p += n2;
                let (range_count, n3) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: range_count varint truncated".to_string())?;
                p += n3;
                let (_first, n4) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "ACK: first_range varint truncated".to_string())?;
                p += n4;
                for _ in 0..range_count {
                    let (_gap, ng) = decode_varint(&plaintext[p..])
                        .ok_or_else(|| "ACK: gap varint truncated".to_string())?;
                    p += ng;
                    let (_len, nl) = decode_varint(&plaintext[p..])
                        .ok_or_else(|| "ACK: range_len varint truncated".to_string())?;
                    p += nl;
                }
                if with_ecn {
                    for _ in 0..3 {
                        let (_v, nv) = decode_varint(&plaintext[p..])
                            .ok_or_else(|| "ACK_ECN: count varint truncated".to_string())?;
                        p += nv;
                    }
                }
                i = p;
            }
            0x06 => {
                let mut p = i + 1;
                let (_off, n_off) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "CRYPTO: offset varint truncated".to_string())?;
                p += n_off;
                let (len, n_len) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "CRYPTO: length varint truncated".to_string())?;
                p += n_len;
                let len = len as usize;
                if plaintext.len() < p + len {
                    return Err("CRYPTO: data slice truncated".to_string());
                }
                // Feed the TLS plaintext to rustls for this epoch.
                conn.read_hs(&plaintext[p..p + len])
                    .map_err(|e| format!("rustls read_hs failed: {e:?}"))?;
                i = p + len;
            }
            0x18 => {
                // NEW_CONNECTION_ID: seq, retire_prior_to, len, cid[len], reset_token[16].
                let mut p = i + 1;
                let (_seq, na) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "NCID: seq truncated".to_string())?;
                p += na;
                let (_rpt, nb) = decode_varint(&plaintext[p..])
                    .ok_or_else(|| "NCID: retire_prior_to truncated".to_string())?;
                p += nb;
                let cid_len = *plaintext.get(p)
                    .ok_or_else(|| "NCID: cid len byte missing".to_string())? as usize;
                p += 1;
                if plaintext.len() < p + cid_len + 16 {
                    return Err("NCID: cid+token tail truncated".to_string());
                }
                i = p + cid_len + 16;
            }
            0x1c | 0x1d => {
                let cc = parse_connection_close(&plaintext[i..])
                    .ok_or_else(|| "CONNECTION_CLOSE parse failed".to_string())?;
                return Ok(PlaintextScan { cc: Some(cc) });
            }
            0x1e => { i += 1; } // HANDSHAKE_DONE
            _ => break,
        }
    }
    Ok(PlaintextScan { cc: None })
}

/// Drain rustls's pending `write_hs` output, sending each batch over UDP in
/// the correct epoch and materialising any `KeyChange` events.
///
/// Per rustls 0.23 docs, a single `write_hs` call emits bytes for at most one
/// epoch and may EITHER produce only bytes OR produce a `KeyChange` (after
/// which the NEXT `write_hs` call uses the new epoch's keys). The outer
/// `loop` drains until `write_hs` returns no bytes and no KeyChange.
///
/// We pick the send-side epoch from the materialised key cache: no Handshake
/// keys yet → still on Initial; Handshake keys present but no 1-RTT yet →
/// Handshake (client Finished); 1-RTT present → post-handshake (rustls may
/// produce NewSessionTicket but the harness has no business with that).
fn pump_rustls_write_hs(
    conn: &mut rustls::quic::ClientConnection,
    socket: &UdpSocket,
    server: &SocketAddr,
    builder: &mut PacketBuilder,
    dcid: &[u8],
    scid: &[u8],
    initial_keys_h: &KeysHandle,
    handshake_keys: &mut Option<rustls::quic::Keys>,
    one_rtt_keys: &mut Option<rustls::quic::Keys>,
    hs_send_pn: &mut u64,
) -> Result<(), String> {
    loop {
        let mut out = Vec::new();
        let kc = conn.write_hs(&mut out);
        if out.is_empty() && kc.is_none() { return Ok(()); }

        if !out.is_empty() {
            if handshake_keys.is_none() {
                // Initial-write epoch.
                let pkt = builder.encode_initial(&out, initial_keys_h);
                socket.send_to(&pkt, server)
                    .map_err(|e| format!("send Initial (pump): {e}"))?;
            } else if one_rtt_keys.is_none() {
                // Handshake-write epoch: client Finished.
                let hs = handshake_keys.as_ref().unwrap();
                let pkt = build_handshake_packet(
                    dcid, scid, *hs_send_pn, &out, &hs.local,
                )?;
                socket.send_to(&pkt, server)
                    .map_err(|e| format!("send Handshake: {e}"))?;
                *hs_send_pn = hs_send_pn.wrapping_add(1);
            }
            // 1-RTT post-handshake bytes (e.g. NewSessionTicket): dropped.
        }

        match kc {
            Some(rustls::quic::KeyChange::Handshake { keys }) => {
                *handshake_keys = Some(keys);
            }
            Some(rustls::quic::KeyChange::OneRtt { keys, next: _ }) => {
                *one_rtt_keys = Some(keys);
            }
            None => {}
        }
    }
}

/// Drive a multi-epoch QUIC handshake (Initial + Handshake [+ 1-RTT scan])
/// against the navette server, surfacing the first CONNECTION_CLOSE observed.
///
/// Unlike `drive_handshake_initial`, this driver advances rustls's QUIC TLS
/// state machine through Handshake-epoch CRYPTO so the server reaches
/// `_on_handshake_complete` (where navette validates the client's transport
/// parameters). That is where C1 scenarios (F02-F09) expect to receive a
/// `TRANSPORT_PARAMETER_ERROR` CONNECTION_CLOSE. After handshake completes
/// successfully the driver also drains 1-RTT for ~250 ms to catch any late
/// validation-emitted CC that lands after the Handshake-space flight.
///
/// Public API contract — identical shape to `drive_handshake_initial`:
///   * `Ok(None)` — handshake completed (no CC observed in any epoch).
///   * `Ok(Some(cc))` — a CC frame was parsed in Initial / Handshake / 1-RTT.
///   * `Err(msg)` — UDP / parse / decrypt error.
///
/// Implementation notes:
///   * Initial-space keys come from `librustls-mojo` (`KeysHandle`) and use
///     the existing `PacketBuilder::encode_initial` path — preserves the
///     same wire layout `drive_handshake_initial` already exercises.
///   * Handshake-space and 1-RTT keys come from rustls's `KeyChange` events
///     surfaced by `write_hs`. We never hand these to `librustls-mojo` —
///     the rustls `Keys::local.{header,packet}` traits are used directly to
///     encrypt outbound Handshake CRYPTO and to decrypt server replies in
///     both Handshake and 1-RTT space.
///   * UDP datagrams may coalesce multiple QUIC packets (RFC 9000 §12.2);
///     the receive loop walks the buffer header-by-header until exhausted.
pub fn drive_handshake_full(
    mut builder: PacketBuilder,
    tp_bytes: &[u8],
) -> Result<Option<ConnectionClose>, String> {
    let config = build_quic_client_config_with_alpn(&[b"h3"]);
    drive_handshake_full_inner(&mut builder, tp_bytes, config)
}

/// Internal shared body so future scenarios with non-h3 ALPN can reuse the
/// multi-epoch flow without re-deriving it. Mirrors the
/// `drive_handshake_initial_inner` factoring.
fn drive_handshake_full_inner(
    builder: &mut PacketBuilder,
    tp_bytes: &[u8],
    config: Arc<rustls::ClientConfig>,
) -> Result<Option<ConnectionClose>, String> {
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("invalid server name: {e}"))?;
    let mut conn = rustls::quic::ClientConnection::new(
        config, rustls::quic::Version::V1, server_name, tp_bytes.to_vec(),
    ).map_err(|e| format!("ClientConnection::new failed: {e}"))?;

    let dcid = builder.dcid.clone();
    let scid = builder.scid.clone();
    let initial_keys_h = initial_keys(Role::Client, &dcid)
        .map_err(|e| format!("client initial_keys failed: rc={}", e.code))?;

    // Bind + connect a UDP socket.
    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|e| format!("bind UDP: {e}"))?;
    let timeout_ms = parse_env_or("TLS_HANDSHAKE_TIMEOUT_MS", 500);
    let read_to = Duration::from_millis(timeout_ms);
    socket.set_read_timeout(Some(read_to))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let server = server_addr();

    // === Step 1: send Initial flight (ClientHello). ===
    let mut crypto_buf: Vec<u8> = Vec::new();
    let kc = conn.write_hs(&mut crypto_buf);
    if crypto_buf.is_empty() {
        return Err("rustls produced no ClientHello bytes".to_string());
    }
    if kc.is_some() {
        return Err("unexpected KeyChange before sending ClientHello".to_string());
    }
    let pkt = builder.encode_initial(&crypto_buf, &initial_keys_h);
    socket.send_to(&pkt, server)
        .map_err(|e| format!("send Initial: {e}"))?;

    // Per-epoch outgoing PNs for the rustls-key paths. Initial-space PNs are
    // managed inside `PacketBuilder`.
    let mut hs_send_pn: u64 = 0;

    // Rustls-derived keys, materialised on KeyChange events.
    let mut handshake_keys: Option<rustls::quic::Keys> = None;
    let mut one_rtt_keys: Option<rustls::quic::Keys> = None;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms * 4);
    let mut buf = vec![0u8; 4096];

    // === Step 2: drive the handshake until completion OR CC OR timeout. ===
    loop {
        if Instant::now() >= deadline { break; }
        if !conn.is_handshaking() { break; }

        let n = match socket.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(e) => return Err(format!("recv_from: {e}")),
        };
        let datagram = &buf[..n];

        // A datagram may carry coalesced QUIC packets (RFC 9000 §12.2).
        // Walk header-by-header until the bytes are consumed.
        let mut offset = 0;
        while offset < datagram.len() {
            let rest = &datagram[offset..];
            if rest.is_empty() { break; }
            let is_long = rest[0] & 0x80 != 0;
            if !is_long {
                // 1-RTT in mid-flight is unexpected during handshake; bail
                // on this datagram (server should never emit 1-RTT before
                // we've sent our Finished). Surface as Ok(None) progression
                // rather than a hard error so the outer loop can re-poll.
                break;
            }
            let header = parse_long_header(rest)
                .ok_or_else(|| "malformed long header".to_string())?;
            let pkt_len = header.payload_offset + header.length;
            if rest.len() < pkt_len {
                return Err(format!(
                    "coalesced packet truncated: need {} bytes, have {}",
                    pkt_len, rest.len(),
                ));
            }
            let pkt = &rest[..pkt_len];

            let (epoch, plaintext) = match header.packet_type {
                0 => {
                    // Initial — decrypt with librustls-mojo client_keys.remote.
                    let plaintext = decrypt_initial_inplace(pkt, &header, &initial_keys_h)?;
                    (Epoch::Initial, plaintext)
                }
                2 => {
                    // Coalesced Initial→Handshake: the Initial packet just
                    // walked may have surfaced a KeyChange::Handshake via
                    // write_hs that we haven't drained yet. Pump now so the
                    // Handshake-epoch keys are materialised before we try
                    // to decrypt this packet.
                    if handshake_keys.is_none() {
                        pump_rustls_write_hs(
                            &mut conn, &socket, &server,
                            builder, &dcid, &scid, &initial_keys_h,
                            &mut handshake_keys, &mut one_rtt_keys,
                            &mut hs_send_pn,
                        )?;
                    }
                    let keys = handshake_keys.as_ref().ok_or_else(||
                        "server sent Handshake before we received KeyChange::Handshake".to_string()
                    )?;
                    let plaintext = decrypt_long_with_rustls(pkt, &header, &keys.remote)?;
                    (Epoch::Handshake, plaintext)
                }
                _ => {
                    // Retry (3) / 0-RTT (1): not exercised by these scenarios.
                    offset += pkt_len;
                    continue;
                }
            };
            // Feed into rustls + scan for CC.
            let scan = scan_plaintext_into_rustls(&plaintext, &mut conn)?;
            if let Some(cc) = scan.cc { return Ok(Some(cc)); }
            let _ = epoch; // currently informational only.

            offset += pkt_len;
        }

        // Pump rustls: write_hs may produce client bytes for the current
        // write epoch AND/OR a KeyChange event signalling that future
        // writes/reads use the new epoch's keys. Drain until quiescent.
        pump_rustls_write_hs(
            &mut conn, &socket, &server,
            builder, &dcid, &scid, &initial_keys_h,
            &mut handshake_keys, &mut one_rtt_keys,
            &mut hs_send_pn,
        )?;
    }

    // === Step 3: post-handshake 1-RTT drain for late-arriving CC. ===
    //
    // navette validates client transport parameters inside
    // `_on_handshake_complete`, which runs on the server right after it
    // ingests the client's Finished. The resulting CC may surface in
    // Handshake or 1-RTT space depending on flush timing. We've already
    // scanned every Handshake-space packet we saw above; drain 1-RTT for
    // ~250 ms here in case the CC trails the Handshake-space flight.
    let drain_deadline = Instant::now() + Duration::from_millis(
        parse_env_or("TLS_ONERTT_DRAIN_MS", 250)
    );
    socket.set_read_timeout(Some(Duration::from_millis(50))).ok();
    while Instant::now() < drain_deadline {
        let n = match socket.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(_) => break,
        };
        let datagram = &buf[..n];
        let mut offset = 0;
        while offset < datagram.len() {
            let rest = &datagram[offset..];
            if rest.is_empty() { break; }
            let is_long = rest[0] & 0x80 != 0;
            if !is_long {
                // 1-RTT short header. Need 1-RTT keys to decrypt.
                let Some(keys) = one_rtt_keys.as_ref() else { break; };
                let plaintext = match decrypt_short_with_rustls(rest, scid.len(), &keys.remote) {
                    Ok(p) => p,
                    Err(_) => break, // wrong PN length / bad sample — give up on this datagram
                };
                let scan = scan_plaintext_into_rustls(&plaintext, &mut conn)?;
                if let Some(cc) = scan.cc { return Ok(Some(cc)); }
                // Short header has no Length field — assume one packet per datagram.
                break;
            }
            let header = parse_long_header(rest)
                .ok_or_else(|| "malformed long header in 1-RTT drain".to_string())?;
            let pkt_len = header.payload_offset + header.length;
            if rest.len() < pkt_len { break; }
            let pkt = &rest[..pkt_len];
            let plaintext_res = match header.packet_type {
                0 => decrypt_initial_inplace(pkt, &header, &initial_keys_h),
                2 => {
                    if let Some(hk) = handshake_keys.as_ref() {
                        decrypt_long_with_rustls(pkt, &header, &hk.remote)
                    } else {
                        Err("late Handshake but no handshake keys".to_string())
                    }
                }
                _ => { offset += pkt_len; continue; }
            };
            if let Ok(plaintext) = plaintext_res {
                let scan = scan_plaintext_into_rustls(&plaintext, &mut conn)?;
                if let Some(cc) = scan.cc { return Ok(Some(cc)); }
            }
            offset += pkt_len;
        }
    }
    Ok(None)
}

/// Identifies the QUIC encryption epoch a CRYPTO frame is encrypted at.
///
/// Distinguishes the two injection sites the F25/F26/F29 scenarios need.
/// `Handshake` substitutes for the client's natural Finished (the Finished
/// bytes rustls would emit are drained but not sent). `OneRtt` is appended
/// after the handshake completes normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InjectionEpoch {
    /// Handshake epoch (long-header packet type 2). Used by F25, F29.
    /// SUBSTITUTES for the client's Finished — natural Finished is NOT sent.
    Handshake,
    /// 1-RTT epoch (short header). Used by F26.
    /// APPENDED after handshake completion — natural Finished IS sent first.
    OneRtt,
}

/// Adversarial TLS record bytes to inject as the payload of a single CRYPTO
/// frame at `epoch`. The bytes are written verbatim — the helper does not
/// validate or wrap them. Callers prepare the record body (e.g. the 5-byte
/// `18 00 00 01 00` KeyUpdate record).
pub struct Injection {
    pub epoch: InjectionEpoch,
    pub bytes: Vec<u8>,
}

/// Drive a multi-epoch handshake and inject an adversarial CRYPTO frame at
/// the specified epoch. Returns the first CONNECTION_CLOSE observed.
///
/// `Handshake` mode: pumps Initial → drains write_hs until handshake_keys
/// materialise, DISCARDING any Finished bytes rustls emits; sends a single
/// Handshake-epoch packet at CRYPTO offset 0 carrying `inj.bytes`; drains
/// for CC.
///
/// `OneRtt` mode: drives full handshake (natural Finished sent), waits for
/// 1-RTT keys; sends an additional short-header packet at 1-RTT CRYPTO
/// offset 0; drains for CC within the post-completion window.
///
/// Returns `Err` if `inj.bytes.len() > 1100` (RFC 9000 §14.1 budget).
pub fn drive_handshake_with_injection(
    builder: PacketBuilder,
    tp_bytes: &[u8],
    inj: Injection,
) -> Result<Option<ConnectionClose>, String> {
    if inj.bytes.len() > 1100 {
        return Err(format!(
            "injection bytes exceed Handshake MTU; got {} bytes",
            inj.bytes.len(),
        ));
    }
    let config = build_quic_client_config_with_alpn(&[b"h3"]);
    drive_handshake_with_injection_inner(builder, tp_bytes, inj, config)
}

/// Drain rustls's pending `write_hs` output but do NOT send any
/// Handshake-epoch bytes (the client Finished is discarded). Initial-epoch
/// bytes are still sent so rustls's state machine stays consistent with the
/// server's view of the Initial flight.
///
/// Used by the `Handshake` injection mode: we need the handshake_keys to be
/// materialised on the client side (so rustls treats the handshake as
/// progressed), but the server must NEVER see the natural Finished — instead
/// it sees our adversarial CRYPTO frame at Handshake-epoch offset 0.
fn pump_rustls_write_hs_discarding_finished(
    conn: &mut rustls::quic::ClientConnection,
    socket: &UdpSocket,
    server: &SocketAddr,
    builder: &mut PacketBuilder,
    initial_keys_h: &KeysHandle,
    handshake_keys: &mut Option<rustls::quic::Keys>,
    one_rtt_keys: &mut Option<rustls::quic::Keys>,
) -> Result<(), String> {
    loop {
        let mut out = Vec::new();
        let kc = conn.write_hs(&mut out);
        if out.is_empty() && kc.is_none() { return Ok(()); }

        if !out.is_empty() {
            if handshake_keys.is_none() {
                // Initial-write epoch: ClientHello fragments / retransmissions.
                let pkt = builder.encode_initial(&out, initial_keys_h);
                socket.send_to(&pkt, server)
                    .map_err(|e| format!("send Initial (pump-discarding): {e}"))?;
            }
            // Handshake-epoch bytes (Finished) and any 1-RTT post-handshake
            // bytes: DROPPED. The whole point of the substitution mode is
            // that the server must not see the natural Finished.
        }

        match kc {
            Some(rustls::quic::KeyChange::Handshake { keys }) => {
                *handshake_keys = Some(keys);
            }
            Some(rustls::quic::KeyChange::OneRtt { keys, next: _ }) => {
                *one_rtt_keys = Some(keys);
            }
            None => {}
        }
    }
}

/// Internal shared body for `drive_handshake_with_injection`.
///
/// Mirrors `drive_handshake_full_inner` but with two behavioural differences:
///   * In `Handshake` mode, when the server's Initial reply lands and rustls
///     surfaces `KeyChange::Handshake`, we use the discarding pump so the
///     natural Finished is never sent. We then build a single Handshake-epoch
///     packet whose CRYPTO frame at offset 0 carries `inj.bytes` instead.
///   * In `OneRtt` mode, we drive the handshake to natural completion (the
///     real pump emits the real Finished); once `one_rtt_keys` materialise we
///     send an additional short-header packet whose payload is a 1-RTT CRYPTO
///     frame at offset 0 carrying `inj.bytes`.
fn drive_handshake_with_injection_inner(
    mut builder: PacketBuilder,
    tp_bytes: &[u8],
    inj: Injection,
    config: Arc<rustls::ClientConfig>,
) -> Result<Option<ConnectionClose>, String> {
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("invalid server name: {e}"))?;
    let mut conn = rustls::quic::ClientConnection::new(
        config, rustls::quic::Version::V1, server_name, tp_bytes.to_vec(),
    ).map_err(|e| format!("ClientConnection::new failed: {e}"))?;

    let dcid = builder.dcid.clone();
    let scid = builder.scid.clone();
    let initial_keys_h = initial_keys(Role::Client, &dcid)
        .map_err(|e| format!("client initial_keys failed: rc={}", e.code))?;

    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|e| format!("bind UDP: {e}"))?;
    let timeout_ms = parse_env_or("TLS_HANDSHAKE_TIMEOUT_MS", 500);
    let read_to = Duration::from_millis(timeout_ms);
    socket.set_read_timeout(Some(read_to))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let server = server_addr();

    // === Step 1: send Initial flight (ClientHello). ===
    let mut crypto_buf: Vec<u8> = Vec::new();
    let kc = conn.write_hs(&mut crypto_buf);
    if crypto_buf.is_empty() {
        return Err("rustls produced no ClientHello bytes".to_string());
    }
    if kc.is_some() {
        return Err("unexpected KeyChange before sending ClientHello".to_string());
    }
    let pkt = builder.encode_initial(&crypto_buf, &initial_keys_h);
    socket.send_to(&pkt, server)
        .map_err(|e| format!("send Initial: {e}"))?;

    let mut hs_send_pn: u64 = 0;
    let mut one_rtt_send_pn: u64 = 0;
    let mut handshake_keys: Option<rustls::quic::Keys> = None;
    let mut one_rtt_keys: Option<rustls::quic::Keys> = None;
    // Set to true once we have injected our adversarial packet at the
    // requested epoch; subsequent loop iterations only drain for CC.
    let mut injected = false;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms * 4);
    let mut buf = vec![0u8; 4096];

    // === Step 2: drive handshake while watching for injection trigger. ===
    loop {
        if Instant::now() >= deadline { break; }
        // The connection may report `is_handshaking()` == false either
        // because it completed naturally (OneRtt mode) or because we
        // already injected and rustls considers itself done. In either
        // case we break only after we've actually injected.
        if !conn.is_handshaking() && injected { break; }

        let n = match socket.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                // No traffic in this window. If we have what we need to
                // inject, push the adversarial record now and proceed to
                // drain. Otherwise the deadline above will fire.
                if !injected && handshake_keys.is_some() {
                    inject_now(
                        &inj,
                        &socket, &server,
                        &dcid, &scid,
                        &mut hs_send_pn, &mut one_rtt_send_pn,
                        handshake_keys.as_ref(),
                        one_rtt_keys.as_ref(),
                    )?;
                    injected = true;
                }
                continue;
            }
            Err(e) => return Err(format!("recv_from: {e}")),
        };
        let datagram = &buf[..n];

        let mut offset = 0;
        while offset < datagram.len() {
            let rest = &datagram[offset..];
            if rest.is_empty() { break; }
            let is_long = rest[0] & 0x80 != 0;
            if !is_long { break; }
            let header = parse_long_header(rest)
                .ok_or_else(|| "malformed long header".to_string())?;
            let pkt_len = header.payload_offset + header.length;
            if rest.len() < pkt_len {
                return Err(format!(
                    "coalesced packet truncated: need {} bytes, have {}",
                    pkt_len, rest.len(),
                ));
            }
            let pkt = &rest[..pkt_len];

            let plaintext = match header.packet_type {
                0 => decrypt_initial_inplace(pkt, &header, &initial_keys_h)?,
                2 => {
                    if handshake_keys.is_none() {
                        // Drain write_hs to materialise the handshake keys
                        // before attempting to decrypt this Handshake packet.
                        match inj.epoch {
                            InjectionEpoch::Handshake => {
                                pump_rustls_write_hs_discarding_finished(
                                    &mut conn, &socket, &server,
                                    &mut builder, &initial_keys_h,
                                    &mut handshake_keys, &mut one_rtt_keys,
                                )?;
                            }
                            InjectionEpoch::OneRtt => {
                                pump_rustls_write_hs(
                                    &mut conn, &socket, &server,
                                    &mut builder, &dcid, &scid, &initial_keys_h,
                                    &mut handshake_keys, &mut one_rtt_keys,
                                    &mut hs_send_pn,
                                )?;
                            }
                        }
                    }
                    let keys = handshake_keys.as_ref().ok_or_else(||
                        "server sent Handshake before we received KeyChange::Handshake".to_string()
                    )?;
                    decrypt_long_with_rustls(pkt, &header, &keys.remote)?
                }
                _ => { offset += pkt_len; continue; }
            };
            let scan = scan_plaintext_into_rustls(&plaintext, &mut conn)?;
            if let Some(cc) = scan.cc { return Ok(Some(cc)); }

            offset += pkt_len;
        }

        // Pump rustls per the requested mode.
        match inj.epoch {
            InjectionEpoch::Handshake => {
                pump_rustls_write_hs_discarding_finished(
                    &mut conn, &socket, &server,
                    &mut builder, &initial_keys_h,
                    &mut handshake_keys, &mut one_rtt_keys,
                )?;
            }
            InjectionEpoch::OneRtt => {
                pump_rustls_write_hs(
                    &mut conn, &socket, &server,
                    &mut builder, &dcid, &scid, &initial_keys_h,
                    &mut handshake_keys, &mut one_rtt_keys,
                    &mut hs_send_pn,
                )?;
            }
        }

        // Inject as soon as the relevant epoch keys are available.
        if !injected {
            let ready = match inj.epoch {
                InjectionEpoch::Handshake => handshake_keys.is_some(),
                InjectionEpoch::OneRtt => one_rtt_keys.is_some(),
            };
            if ready {
                inject_now(
                    &inj,
                    &socket, &server,
                    &dcid, &scid,
                    &mut hs_send_pn, &mut one_rtt_send_pn,
                    handshake_keys.as_ref(),
                    one_rtt_keys.as_ref(),
                )?;
                injected = true;
            }
        }
    }

    // === Step 3: post-injection drain for CC (Handshake + 1-RTT). ===
    let drain_deadline = Instant::now() + Duration::from_millis(
        parse_env_or("TLS_ONERTT_DRAIN_MS", 250)
    );
    socket.set_read_timeout(Some(Duration::from_millis(50))).ok();
    while Instant::now() < drain_deadline {
        let n = match socket.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(_) => break,
        };
        let datagram = &buf[..n];
        let mut offset = 0;
        while offset < datagram.len() {
            let rest = &datagram[offset..];
            if rest.is_empty() { break; }
            let is_long = rest[0] & 0x80 != 0;
            if !is_long {
                let Some(keys) = one_rtt_keys.as_ref() else { break; };
                let plaintext = match decrypt_short_with_rustls(rest, scid.len(), &keys.remote) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let scan = scan_plaintext_into_rustls(&plaintext, &mut conn)?;
                if let Some(cc) = scan.cc { return Ok(Some(cc)); }
                break;
            }
            let header = parse_long_header(rest)
                .ok_or_else(|| "malformed long header in drain".to_string())?;
            let pkt_len = header.payload_offset + header.length;
            if rest.len() < pkt_len { break; }
            let pkt = &rest[..pkt_len];
            let plaintext_res = match header.packet_type {
                0 => decrypt_initial_inplace(pkt, &header, &initial_keys_h),
                2 => {
                    if let Some(hk) = handshake_keys.as_ref() {
                        decrypt_long_with_rustls(pkt, &header, &hk.remote)
                    } else {
                        Err("late Handshake but no handshake keys".to_string())
                    }
                }
                _ => { offset += pkt_len; continue; }
            };
            if let Ok(plaintext) = plaintext_res {
                let scan = scan_plaintext_into_rustls(&plaintext, &mut conn)?;
                if let Some(cc) = scan.cc { return Ok(Some(cc)); }
            }
            offset += pkt_len;
        }
    }
    Ok(None)
}

/// Build and send the adversarial CRYPTO frame at the requested epoch.
///
/// Handshake mode uses `build_handshake_packet` with `crypto_payload` set to
/// the adversarial TLS record (it embeds a CRYPTO frame at offset 0 by
/// construction). 1-RTT mode wraps the bytes in `encode_crypto_frame` and
/// hands them to `build_short_header_crypto_packet`.
fn inject_now(
    inj: &Injection,
    socket: &UdpSocket,
    server: &SocketAddr,
    dcid: &[u8],
    scid: &[u8],
    hs_send_pn: &mut u64,
    one_rtt_send_pn: &mut u64,
    handshake_keys: Option<&rustls::quic::Keys>,
    one_rtt_keys: Option<&rustls::quic::Keys>,
) -> Result<(), String> {
    match inj.epoch {
        InjectionEpoch::Handshake => {
            let hs = handshake_keys.ok_or_else(||
                "Handshake injection requested before Handshake keys materialised".to_string()
            )?;
            let pkt = build_handshake_packet(
                dcid, scid, *hs_send_pn, &inj.bytes, &hs.local,
            )?;
            socket.send_to(&pkt, server)
                .map_err(|e| format!("send Handshake injection: {e}"))?;
            *hs_send_pn = hs_send_pn.wrapping_add(1);
        }
        InjectionEpoch::OneRtt => {
            let or = one_rtt_keys.ok_or_else(||
                "1-RTT injection requested before 1-RTT keys materialised".to_string()
            )?;
            let frame = encode_crypto_frame(0, &inj.bytes);
            let pkt = build_short_header_crypto_packet(
                dcid, *one_rtt_send_pn, &frame, &or.local,
            )?;
            socket.send_to(&pkt, server)
                .map_err(|e| format!("send 1-RTT injection: {e}"))?;
            *one_rtt_send_pn = one_rtt_send_pn.wrapping_add(1);
        }
    }
    Ok(())
}

/// Decrypt an Initial-space packet with the harness's `KeysHandle` (the
/// librustls-mojo Initial keys derived off the client-chosen DCID). Mirrors
/// the inlined block at the bottom of `drive_handshake_initial_inner` but
/// returns the plaintext as a `Vec` so it composes with `scan_plaintext_into_rustls`.
fn decrypt_initial_inplace(
    pkt: &[u8],
    header: &LongHeader,
    keys: &KeysHandle,
) -> Result<Vec<u8>, String> {
    let mut reply = pkt.to_vec();
    let pn_offset = header.payload_offset;
    let sample_off = pn_offset + 4;
    if reply.len() < sample_off + 16 {
        return Err(format!(
            "Initial reply too short for HP sample: need {}, got {}",
            sample_off + 16, reply.len(),
        ));
    }
    let sample: [u8; 16] = reply[sample_off..sample_off + 16]
        .try_into().expect("16-byte HP sample");
    let (head, rest) = reply.split_at_mut(pn_offset);
    remote_header_unprotect(keys, &sample, &mut head[0], &mut rest[..4])
        .map_err(|e| format!("Initial HP unprotect failed: rc={}", e.code))?;
    let first_byte = head[0];
    let pn_length = ((first_byte & 0x03) + 1) as usize;
    let mut pn: u64 = 0;
    for i in 0..pn_length { pn = (pn << 8) | rest[i] as u64; }
    let header_len = pn_offset + pn_length;
    let header_bytes = reply[..header_len].to_vec();
    let end = pn_offset + header.length;
    if reply.len() < end {
        return Err(format!(
            "Initial reply truncated: payload end {} > len {}", end, reply.len(),
        ));
    }
    let pt_len = remote_decrypt(keys, pn, &header_bytes, &mut reply[header_len..end])
        .map_err(|e| format!("Initial AEAD decrypt failed: rc={}", e.code))?;
    Ok(reply[header_len..header_len + pt_len].to_vec())
}

/// Adversarial TP block builders for the C1 (transport-parameter validation)
/// scenarios.
///
/// Each helper returns a raw RFC 9000 §18 wire-encoded TP block ready to feed
/// into `drive_handshake_initial`. Layout per entry is
/// `varint(id) || varint(len) || value_bytes`; multiple entries are simply
/// concatenated. The IDs used here are drawn from the §18.2 registry — the
/// values flagged "server-only" must NEVER appear in a client transport-params
/// extension, which is precisely what F03/F04/F05/F06 verify.
pub mod adversarial_tp {
    use super::{encode_varint, server_tp_bytes_well_formed};

    /// F02 — `initial_source_connection_id` (0x0f) absent.
    ///
    /// RFC 9000 §7.3 mandates this parameter on a client Initial; a fresh
    /// connection that omits it must be rejected with TRANSPORT_PARAMETER_ERROR.
    /// We build the block from scratch (rather than starting from the
    /// well-formed baseline) so we can selectively drop entry 0x0f while
    /// keeping the rest of the §18 minimums in place.
    pub fn f02_missing_initial_scid() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        // varint-valued params — same set as `server_tp_bytes_well_formed`,
        // minus the deliberately-omitted 0x0f.
        push_varint_tp(&mut out, 0x01, 30_000);        // max_idle_timeout
        push_varint_tp(&mut out, 0x03, 1452);          // max_udp_payload_size
        push_varint_tp(&mut out, 0x04, 1_048_576);     // initial_max_data
        push_varint_tp(&mut out, 0x05, 65_536);        // initial_max_stream_data_bidi_local
        push_varint_tp(&mut out, 0x06, 65_536);        // initial_max_stream_data_bidi_remote
        push_varint_tp(&mut out, 0x07, 65_536);        // initial_max_stream_data_uni
        push_varint_tp(&mut out, 0x08, 100);           // initial_max_streams_bidi
        push_varint_tp(&mut out, 0x09, 100);           // initial_max_streams_uni
        // initial_source_connection_id (0x0f) deliberately OMITTED.
        out
    }

    /// F03 — well-formed block PLUS `original_destination_connection_id` (0x00).
    ///
    /// RFC 9000 §18.2: server-only. A client emitting this parameter is a
    /// protocol violation; server must close with TRANSPORT_PARAMETER_ERROR.
    /// Value is an 8-byte placeholder connection-ID (zeros).
    pub fn f03_original_dcid_forbidden() -> Vec<u8> {
        let mut out = server_tp_bytes_well_formed();
        push_tp(&mut out, 0x00, vec![0u8; 8]);
        out
    }

    /// F04 — well-formed block PLUS `preferred_address` (0x0d).
    ///
    /// RFC 9000 §18.2: server-only. Wire layout (§18.2):
    ///   4-byte IPv4 address || 2-byte IPv4 port ||
    ///   16-byte IPv6 address || 2-byte IPv6 port ||
    ///   1-byte Connection ID length || N-byte Connection ID ||
    ///   16-byte stateless reset token
    ///
    /// We use a 1-byte CID (the smallest length navette's parser accepts —
    /// RFC 9000 §17.2 limits CIDs to 1..=20 bytes in v1 long headers, and
    /// navette's `_parse_preferred_address` enforces that lower bound while
    /// walking the sub-structure). A 0-byte CID would surface a different
    /// error ("CID length must be 1..20, got 0") before reaching the
    /// `validate_client_transport_params` step that flags the server-only
    /// parameter — which is what this scenario is designed to exercise.
    pub fn f04_preferred_addr_forbidden() -> Vec<u8> {
        let mut out = server_tp_bytes_well_formed();
        let mut val: Vec<u8> = Vec::with_capacity(42);
        val.extend_from_slice(&[127, 0, 0, 1]);   // IPv4
        val.extend_from_slice(&[0x10, 0xbb]);     // IPv4 port (4283)
        val.extend_from_slice(&[0u8; 16]);        // IPv6 (zeros)
        val.extend_from_slice(&[0x10, 0xbb]);     // IPv6 port
        val.push(1);                              // CID length = 1
        val.push(0);                              // CID bytes (1 byte)
        val.extend_from_slice(&[0u8; 16]);        // stateless reset token
        debug_assert_eq!(val.len(), 42, "preferred_address with 1-byte CID");
        push_tp(&mut out, 0x0d, val);
        out
    }

    /// F05 — well-formed block PLUS `retry_source_connection_id` (0x10).
    ///
    /// RFC 9000 §18.2: server-only (set only when the server sent a Retry).
    /// 8-byte placeholder value.
    pub fn f05_retry_scid_forbidden() -> Vec<u8> {
        let mut out = server_tp_bytes_well_formed();
        push_tp(&mut out, 0x10, vec![0u8; 8]);
        out
    }

    /// F06 — well-formed block PLUS `stateless_reset_token` (0x02).
    ///
    /// RFC 9000 §18.2: server-only, paired with a server-issued connection ID.
    /// Fixed 16-byte length per §10.3.
    pub fn f06_stateless_reset_forbidden() -> Vec<u8> {
        let mut out = server_tp_bytes_well_formed();
        push_tp(&mut out, 0x02, vec![0u8; 16]);
        out
    }

    /// F07 — well-formed TP block but with max_udp_payload_size = 1100 (below
    /// RFC 9000 §7.4 minimum 1200).
    ///
    /// Rebuilt from scratch (cannot reuse `server_tp_bytes_well_formed` because
    /// that emits 0x03 = 1452); we keep every other §18 minimum in place so the
    /// only violation is the out-of-range max_udp_payload_size.
    pub fn f07_max_udp_payload_below_min() -> Vec<u8> {
        let mut out = Vec::new();
        push_tp(&mut out, 0x01, varint_value(30_000));       // max_idle_timeout
        push_tp(&mut out, 0x03, varint_value(1100));         // max_udp_payload_size (ADVERSARIAL: < 1200)
        push_tp(&mut out, 0x04, varint_value(1_048_576));    // initial_max_data
        push_tp(&mut out, 0x05, varint_value(65_536));       // initial_max_stream_data_bidi_local
        push_tp(&mut out, 0x06, varint_value(65_536));       // initial_max_stream_data_bidi_remote
        push_tp(&mut out, 0x07, varint_value(65_536));       // initial_max_stream_data_uni
        push_tp(&mut out, 0x08, varint_value(100));          // initial_max_streams_bidi
        push_tp(&mut out, 0x09, varint_value(100));          // initial_max_streams_uni
        push_tp(&mut out, 0x0f, Vec::new());                 // initial_source_connection_id (empty, valid)
        out
    }

    /// F08 — well-formed TP block PLUS `ack_delay_exponent` = 21 (above RFC 9000
    /// §7.4 maximum of 20).
    pub fn f08_ack_delay_exponent_above_max() -> Vec<u8> {
        let mut out = server_tp_bytes_well_formed();
        push_tp(&mut out, 0x0a, varint_value(21));
        out
    }

    /// F09 — well-formed TP block PLUS `max_ack_delay` = 16384 (must be strictly
    /// less than 2^14 = 16384 per RFC 9000 §18.2; 16384 itself fails the check).
    pub fn f09_max_ack_delay_above_threshold() -> Vec<u8> {
        let mut out = server_tp_bytes_well_formed();
        push_tp(&mut out, 0x0b, varint_value(16384));
        out
    }

    /// Append a TP entry whose value is itself a varint (covers the integer-
    /// valued params in §18.2).
    fn push_varint_tp(out: &mut Vec<u8>, id: u64, value: u64) {
        let mut value_bytes: Vec<u8> = Vec::new();
        encode_varint(value, &mut value_bytes);
        push_tp(out, id, value_bytes);
    }

    /// Append a TP entry as `varint(id) || varint(len) || value`.
    ///
    /// Single helper used by every adversarial builder. `value` is an opaque
    /// byte vector; callers that need varint-encoded values pre-encode via
    /// `varint_value` or use `push_varint_tp`.
    fn push_tp(out: &mut Vec<u8>, id: u64, value: Vec<u8>) {
        encode_varint(id, out);
        encode_varint(value.len() as u64, out);
        out.extend_from_slice(&value);
    }

    /// Encode a u64 as a QUIC variable-length integer and return the bytes.
    fn varint_value(v: u64) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        encode_varint(v, &mut buf);
        buf
    }
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

    /// Walk a TP block and return the set of parameter IDs it contains plus
    /// total bytes consumed (must equal `tp.len()`). Used by the adversarial
    /// helpers' tests below.
    fn collect_tp_ids(tp: &[u8]) -> (Vec<u64>, usize) {
        let mut ids: Vec<u64> = Vec::new();
        let mut i = 0;
        while i < tp.len() {
            let (id, c) = decode_varint(&tp[i..]).expect("id varint");
            i += c;
            let (len, c) = decode_varint(&tp[i..]).expect("len varint");
            i += c;
            assert!(i + len as usize <= tp.len(), "value bounds for id 0x{:x}", id);
            ids.push(id);
            i += len as usize;
        }
        (ids, i)
    }

    #[test]
    fn f02_omits_initial_scid_only() {
        let tp = super::adversarial_tp::f02_missing_initial_scid();
        let (ids, consumed) = collect_tp_ids(&tp);
        assert_eq!(consumed, tp.len(), "F02 TP block walks cleanly");
        assert!(!ids.contains(&0x0f), "F02 must omit initial_source_connection_id");
        // Every other §18 minimum still present so the rejection is unambiguous.
        for required in [0x01u64, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09] {
            assert!(ids.contains(&required), "F02 keeps id 0x{:x}", required);
        }
    }

    #[test]
    fn f03_appends_original_dcid() {
        let tp = super::adversarial_tp::f03_original_dcid_forbidden();
        let (ids, consumed) = collect_tp_ids(&tp);
        assert_eq!(consumed, tp.len(), "F03 TP block walks cleanly");
        assert!(ids.contains(&0x0f), "F03 keeps initial_source_connection_id");
        assert!(ids.contains(&0x00), "F03 must include original_destination_connection_id");
    }

    #[test]
    fn f04_appends_preferred_address_with_42_byte_value() {
        let tp = super::adversarial_tp::f04_preferred_addr_forbidden();
        let (ids, consumed) = collect_tp_ids(&tp);
        assert_eq!(consumed, tp.len(), "F04 TP block walks cleanly");
        assert!(ids.contains(&0x0d), "F04 must include preferred_address");
        // Re-walk to locate the 0x0d entry and confirm its value length.
        // 42 bytes = 24 (IPv4+port+IPv6+port) + 1 (CID len) + 1 (CID bytes) + 16 (reset token).
        let mut i = 0;
        while i < tp.len() {
            let (id, c) = decode_varint(&tp[i..]).unwrap();
            i += c;
            let (len, c) = decode_varint(&tp[i..]).unwrap();
            i += c;
            if id == 0x0d {
                assert_eq!(len, 42, "preferred_address with 1-byte CID");
                break;
            }
            i += len as usize;
        }
    }

    #[test]
    fn f05_appends_retry_scid() {
        let tp = super::adversarial_tp::f05_retry_scid_forbidden();
        let (ids, consumed) = collect_tp_ids(&tp);
        assert_eq!(consumed, tp.len(), "F05 TP block walks cleanly");
        assert!(ids.contains(&0x0f), "F05 keeps initial_source_connection_id");
        assert!(ids.contains(&0x10), "F05 must include retry_source_connection_id");
    }

    #[test]
    fn f06_appends_stateless_reset_token() {
        let tp = super::adversarial_tp::f06_stateless_reset_forbidden();
        let (ids, consumed) = collect_tp_ids(&tp);
        assert_eq!(consumed, tp.len(), "F06 TP block walks cleanly");
        assert!(ids.contains(&0x0f), "F06 keeps initial_source_connection_id");
        assert!(ids.contains(&0x02), "F06 must include stateless_reset_token");
    }

    /// Walk a TP block, calling the closure with (id, len, value_slice) for
    /// each entry. Used by F07/F08/F09 helper tests to inspect individual
    /// parameter values.
    fn walk_tp<F: FnMut(u64, usize, &[u8])>(tp: &[u8], mut f: F) {
        let mut i = 0;
        while i < tp.len() {
            let (id, c) = decode_varint(&tp[i..]).expect("id varint");
            i += c;
            let (len, c) = decode_varint(&tp[i..]).expect("len varint");
            i += c;
            let len = len as usize;
            assert!(i + len <= tp.len(), "value bounds for id 0x{:x}", id);
            f(id, len, &tp[i..i + len]);
            i += len;
        }
    }

    #[test]
    fn f07_emits_max_udp_payload_1100() {
        let tp = super::adversarial_tp::f07_max_udp_payload_below_min();
        let mut found = false;
        walk_tp(&tp, |id, len, value| {
            if id == 0x03 {
                // 1100 as 2-byte QUIC varint: top 2 bits = 01 → 0x4000 | 1100 = 0x444C
                assert_eq!(len, 2, "max_udp_payload_size 1100 encodes as 2-byte varint");
                assert_eq!(value, &[0x44, 0x4c], "1100 big-endian 2-byte varint");
                found = true;
            }
        });
        assert!(found, "TP id 0x03 missing");
    }

    #[test]
    fn f08_appends_ack_delay_exp_21() {
        let base = server_tp_bytes_well_formed();
        let tp = super::adversarial_tp::f08_ack_delay_exponent_above_max();
        // 21 fits in a 1-byte varint; entry = 1 (id 0x0a) + 1 (len=1) + 1 (value) = 3 bytes
        assert_eq!(tp.len(), base.len() + 3, "one appended 0x0a entry = 3 bytes");
        let mut found = false;
        walk_tp(&tp, |id, _len, value| {
            if id == 0x0a {
                assert_eq!(value, &[21], "ack_delay_exponent value is 21");
                found = true;
            }
        });
        assert!(found, "appended 0x0a not found");
    }

    #[test]
    fn build_quic_client_config_with_alpn_propagates_list() {
        let cfg = build_quic_client_config_with_alpn(&[b"h3"]);
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec()]);

        let empty = build_quic_client_config_with_alpn(&[]);
        assert!(
            empty.alpn_protocols.is_empty(),
            "F27 driver must produce a config with zero ALPN entries",
        );

        let multi = build_quic_client_config_with_alpn(&[b"h3", b"h2"]);
        assert_eq!(multi.alpn_protocols, vec![b"h3".to_vec(), b"h2".to_vec()]);
    }

    #[test]
    fn f09_appends_max_ack_delay_16384() {
        let tp = super::adversarial_tp::f09_max_ack_delay_above_threshold();
        let mut found = false;
        walk_tp(&tp, |id, len, value| {
            if id == 0x0b {
                // 16384 as 4-byte QUIC varint: top 2 bits = 10 → 0x80000000 | 0x00004000
                assert_eq!(len, 4, "max_ack_delay 16384 encodes as 4-byte varint");
                assert_eq!(value, &[0x80, 0x00, 0x40, 0x00], "16384 big-endian 4-byte varint");
                found = true;
            }
        });
        assert!(found, "appended 0x0b not found");
    }

    #[test]
    fn encode_crypto_frame_offset_zero() {
        // type=0x06, offset=0 (1-byte varint), length=5 (1-byte varint), bytes
        let out = encode_crypto_frame(0, &[0x18, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(out, vec![0x06, 0x00, 0x05, 0x18, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn encode_crypto_frame_offset_large() {
        // offset=200 → 2-byte varint 0x40c8; length=4 → 1-byte 0x04
        let out = encode_crypto_frame(200, &[0x05, 0x00, 0x00, 0x00]);
        assert_eq!(out, vec![0x06, 0x40, 0xc8, 0x04, 0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn injection_size_check_rejects_oversize() {
        let builder = PacketBuilder::new(vec![1; 8], vec![2; 8]);
        let big = vec![0u8; 1200];
        let inj = Injection { epoch: InjectionEpoch::Handshake, bytes: big };
        let res = drive_handshake_with_injection(builder, &server_tp_bytes_well_formed(), inj);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("MTU"), "expected MTU error, got: {}", err);
    }
}
