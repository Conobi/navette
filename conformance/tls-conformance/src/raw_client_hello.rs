//! Hand-assembled TLS 1.3 ClientHello bytes for adversarial QUIC scenarios
//! that need to omit or malform individual extensions.
//!
//! `rustls::quic::ClientConnection::new` always wraps the supplied transport
//! parameters in `Some(...)` internally; there is no API path to make the
//! emitted ClientHello OMIT the `quic_transport_parameters` extension. To
//! test the RFC 9001 §8.2 missing-extension rejection (F28), we bypass
//! `ClientConnection` and build the CH byte stream ourselves.
//!
//! The builder produces a single TLS 1.3 ClientHello *handshake message*
//! (handshake type 0x01 + uint24 length + body). It is NOT wrapped in a
//! TLS record — QUIC carries TLS handshake messages directly in CRYPTO
//! frames (RFC 9001 §4.1).
//!
//! Layout (RFC 8446 §4.1.2):
//!
//! ```text
//!   ClientHello {
//!     legacy_version              uint16  (0x0303)
//!     random                      uint8[32]
//!     legacy_session_id           opaque<0..32>   (empty for QUIC)
//!     cipher_suites               uint16<2..2^16-2>
//!     legacy_compression_methods  opaque<1..2^8-1> (= 0x00)
//!     extensions                  Extension extensions<8..2^16-1>
//!   }
//! ```
//!
//! All length prefixes are big-endian per the RFC. The `tls_codec`
//! dependency (declared in Cargo.toml) is the standard Rust library for
//! TLS 1.3 wire encoding; here we use only its presence to lock in the
//! 0.4.x line for future scenarios that may want its derive macros.

use rand::RngCore;

/// TLS extension codepoints used by `ClientHelloOmittingQuicTp` (RFC 8446
/// §4.2 and RFC 9001 §8.2). The deliberately-omitted
/// `quic_transport_parameters` codepoint (0x39) is listed for grep-ability
/// and is referenced by the unit test below.
mod ext {
    pub const SERVER_NAME:                    u16 = 0x0000;
    pub const SUPPORTED_GROUPS:               u16 = 0x000a;
    pub const APPLICATION_LAYER_PROTO_NEG:    u16 = 0x0010;
    pub const SIGNATURE_ALGORITHMS:           u16 = 0x000d;
    pub const SUPPORTED_VERSIONS:             u16 = 0x002b;
    pub const KEY_SHARE:                      u16 = 0x0033;
    /// The codepoint we deliberately OMIT for F28.
    #[allow(dead_code)]
    pub const QUIC_TRANSPORT_PARAMETERS:      u16 = 0x0039;
}

/// Builder for a TLS 1.3 ClientHello that lacks the
/// `quic_transport_parameters` extension. Every other extension required
/// to reach the server-side check is included (server_name, ALPN,
/// supported_versions, supported_groups, signature_algorithms, key_share).
///
/// Defaults match the navette TLS-conformance harness:
///   * `server_name = "localhost"`
///   * `alpn = b"h3"`
///   * cipher_suite = TLS_AES_128_GCM_SHA256 (0x1301)
///   * named group = x25519 (0x001d) with a 32-byte all-zero public key
///     (the server never gets to use it — it rejects the CH first)
pub struct ClientHelloOmittingQuicTp {
    pub server_name: String,
    pub alpn: Vec<u8>,
}

impl Default for ClientHelloOmittingQuicTp {
    fn default() -> Self {
        Self { server_name: "localhost".to_string(), alpn: b"h3".to_vec() }
    }
}

/// Push a big-endian `u16` to `out`.
fn put_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_be_bytes()); }

/// Push a big-endian `u24` (3 bytes) to `out`.
fn put_u24(out: &mut Vec<u8>, v: u32) {
    debug_assert!(v < (1 << 24), "u24 overflow");
    out.push(((v >> 16) & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push((v & 0xff) as u8);
}

/// Emit a single TLS extension `extension_type || uint16(len) || body`.
fn push_extension(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    put_u16(out, ext_type);
    put_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// Build the `server_name` extension body (RFC 6066 §3): a 2-byte length-
/// prefixed list of `(NameType=0, uint16(name_len), name)` entries.
fn build_sni_body(server_name: &str) -> Vec<u8> {
    let name = server_name.as_bytes();
    let entry_len = 1 + 2 + name.len();   // type(1) + len(2) + name
    let mut body = Vec::with_capacity(2 + entry_len);
    put_u16(&mut body, entry_len as u16); // ServerNameList length
    body.push(0x00);                       // name_type = host_name(0)
    put_u16(&mut body, name.len() as u16); // HostName length
    body.extend_from_slice(name);
    body
}

/// Build the `application_layer_protocol_negotiation` extension body
/// (RFC 7301 §3.1): a 2-byte length-prefixed list of `(uint8(len), proto)`
/// entries. We always emit exactly one ALPN entry.
fn build_alpn_body(alpn: &[u8]) -> Vec<u8> {
    let entry_len = 1 + alpn.len();        // u8 len + proto bytes
    let mut body = Vec::with_capacity(2 + entry_len);
    put_u16(&mut body, entry_len as u16);
    body.push(alpn.len() as u8);
    body.extend_from_slice(alpn);
    body
}

/// Build the `supported_versions` extension body (RFC 8446 §4.2.1) for the
/// CH path: a 1-byte length-prefixed list of uint16 versions. We list
/// TLS 1.3 only (0x0304).
fn build_supported_versions_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(3);
    body.push(2);          // list length in bytes (one u16 entry)
    put_u16(&mut body, 0x0304); // TLS 1.3
    body
}

/// Build the `supported_groups` extension body (RFC 8446 §4.2.7): a 2-byte
/// length-prefixed list of uint16 NamedGroup values. We list x25519 only.
fn build_supported_groups_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    put_u16(&mut body, 2);      // list length in bytes
    put_u16(&mut body, 0x001d); // x25519
    body
}

/// Build the `signature_algorithms` extension body (RFC 8446 §4.2.3): a
/// 2-byte length-prefixed list of uint16 SignatureScheme values. We list
/// the schemes rustls's default provider supports for TLS 1.3 — the
/// server never gets to use them but the CH parser checks the list is
/// non-empty.
fn build_signature_algorithms_body() -> Vec<u8> {
    let schemes: &[u16] = &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0401, // rsa_pkcs1_sha256
    ];
    let bytes_len = schemes.len() * 2;
    let mut body = Vec::with_capacity(2 + bytes_len);
    put_u16(&mut body, bytes_len as u16);
    for s in schemes { put_u16(&mut body, *s); }
    body
}

/// Build the `key_share` extension body (RFC 8446 §4.2.8) for the CH path:
/// a 2-byte length-prefixed list of `KeyShareEntry { group, key_exchange<1..2^16-1> }`.
/// We emit a single entry for x25519 with a 32-byte all-zero public key.
/// The server will derive an HKDF shared secret from this and a real key,
/// but it never gets that far for F28 — the CH-parse failure happens first.
fn build_key_share_body() -> Vec<u8> {
    let key_exchange = [0u8; 32];
    let entry_len = 2 + 2 + key_exchange.len();
    let mut body = Vec::with_capacity(2 + entry_len);
    put_u16(&mut body, entry_len as u16); // client_shares length
    put_u16(&mut body, 0x001d);            // x25519
    put_u16(&mut body, key_exchange.len() as u16);
    body.extend_from_slice(&key_exchange);
    body
}

impl ClientHelloOmittingQuicTp {
    /// Serialize the ClientHello to its on-the-wire bytes.
    ///
    /// Return value is a TLS handshake message: 1 byte handshake type
    /// (0x01 = ClientHello) + 3 bytes uint24 length + body. Suitable for
    /// dropping into a QUIC CRYPTO frame at Initial-epoch offset 0.
    ///
    /// The 32-byte `random` field is filled with cryptographic randomness
    /// via `rand::thread_rng()`; this matters only for not colliding with a
    /// recent CH that might still be in the server's anti-replay window.
    pub fn build(&self) -> Result<Vec<u8>, String> {
        if self.server_name.is_empty() {
            return Err("server_name must be non-empty".into());
        }
        if self.alpn.is_empty() {
            return Err("alpn must be non-empty".into());
        }

        // --- ClientHello body ---
        let mut body: Vec<u8> = Vec::with_capacity(512);

        // legacy_version (TLS 1.2 sentinel for backwards-compat fronting).
        put_u16(&mut body, 0x0303);

        // random — 32 random bytes.
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);
        body.extend_from_slice(&random);

        // legacy_session_id — empty for QUIC (RFC 9001 §8.4).
        body.push(0);

        // cipher_suites — TLS_AES_128_GCM_SHA256 only.
        put_u16(&mut body, 2);      // list length in bytes
        put_u16(&mut body, 0x1301);

        // legacy_compression_methods — null only.
        body.push(1);
        body.push(0x00);

        // --- extensions block ---
        let mut exts: Vec<u8> = Vec::with_capacity(256);
        push_extension(&mut exts, ext::SERVER_NAME,
                       &build_sni_body(&self.server_name));
        push_extension(&mut exts, ext::SUPPORTED_VERSIONS,
                       &build_supported_versions_body());
        push_extension(&mut exts, ext::SUPPORTED_GROUPS,
                       &build_supported_groups_body());
        push_extension(&mut exts, ext::SIGNATURE_ALGORITHMS,
                       &build_signature_algorithms_body());
        push_extension(&mut exts, ext::KEY_SHARE,
                       &build_key_share_body());
        push_extension(&mut exts, ext::APPLICATION_LAYER_PROTO_NEG,
                       &build_alpn_body(&self.alpn));
        // NOTE: ext::QUIC_TRANSPORT_PARAMETERS (0x0039) deliberately OMITTED.
        // This is the whole point of the F28 scenario — the server must
        // detect the absence and emit a `missing_extension` alert per
        // RFC 9001 §8.2.

        put_u16(&mut body, exts.len() as u16);
        body.extend_from_slice(&exts);

        // --- Wrap in TLS handshake message header (RFC 8446 §4) ---
        let mut hs: Vec<u8> = Vec::with_capacity(4 + body.len());
        hs.push(0x01);                  // HandshakeType = client_hello
        put_u24(&mut hs, body.len() as u32);
        hs.extend_from_slice(&body);
        Ok(hs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the serialized handshake starts with the ClientHello
    /// handshake-type byte.
    #[test]
    fn raw_ch_starts_with_handshake_type_client_hello() {
        let ch = ClientHelloOmittingQuicTp::default().build().unwrap();
        assert!(!ch.is_empty(), "CH must be non-empty");
        assert_eq!(ch[0], 0x01, "TLS HandshakeType = ClientHello (0x01)");
    }

    /// Inv-1 for the builder: the serialized CH MUST NOT contain a
    /// `quic_transport_parameters` extension (codepoint 0x0039). We scan
    /// for the 2-byte sequence 0x00 0x39 anywhere in the bytes; a false
    /// positive inside an opaque length field is theoretically possible
    /// but vanishingly unlikely for the small CH bodies we build here.
    #[test]
    fn raw_ch_does_not_contain_quic_tp_extension() {
        let ch = ClientHelloOmittingQuicTp::default().build().unwrap();
        assert!(
            !ch.windows(2).any(|w| w == [0x00, 0x39]),
            "quic_transport_parameters codepoint (0x0039) leaked into CH bytes",
        );
    }

    /// The serialized handshake's uint24 length field must match the body
    /// length. Off-by-one here would surface as a TLS decode error on the
    /// server long before the missing-extension check fires.
    #[test]
    fn raw_ch_length_field_matches_body() {
        let ch = ClientHelloOmittingQuicTp::default().build().unwrap();
        assert!(ch.len() >= 4, "CH must include 4-byte handshake header");
        let declared = ((ch[1] as usize) << 16)
                     | ((ch[2] as usize) << 8)
                     | (ch[3] as usize);
        assert_eq!(declared, ch.len() - 4, "uint24 length matches body");
    }

    /// The ClientHello must include every extension that the navette TLS
    /// stack needs to walk PAST before reaching the missing-TP check.
    /// We verify that each codepoint (other than 0x0039) appears in the
    /// byte stream.
    #[test]
    fn raw_ch_contains_required_extensions() {
        let ch = ClientHelloOmittingQuicTp::default().build().unwrap();
        let required: &[(u16, &str)] = &[
            (ext::SERVER_NAME, "server_name"),
            (ext::SUPPORTED_VERSIONS, "supported_versions"),
            (ext::SUPPORTED_GROUPS, "supported_groups"),
            (ext::SIGNATURE_ALGORITHMS, "signature_algorithms"),
            (ext::KEY_SHARE, "key_share"),
            (ext::APPLICATION_LAYER_PROTO_NEG, "alpn"),
        ];
        for (code, name) in required {
            let needle = code.to_be_bytes();
            assert!(
                ch.windows(2).any(|w| w == needle),
                "required extension {name} (0x{code:04x}) missing from CH",
            );
        }
    }
}
