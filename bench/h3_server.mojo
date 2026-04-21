# bench/h3_server.mojo
#
# HTTP/3 QUIC benchmark server for HttpArena on port 8443 (UDP).
#
# Uses raw UDP syscalls, QuicConnection wrapped in H3CoroServer, and
# bench_h3_body_fn for request handling. Pattern adapted from interop/server.mojo.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections import Dict

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.quic.packet import parse_packet_header
from src.h3.h3_coro_server import H3CoroServer
from bench.handler import bench_h3_body_fn, StaticEntry, _load_static_files
from interop.file_io import read_file, getenv_opt
from interop.udp import udp_bind, udp_recvfrom, udp_sendto, udp_poll, monotonic_us


# ── helpers ─────────────────────────────────────────────────────────────


def _addr_to_key(addr: List[UInt8]) -> String:
    """Convert raw 16-byte sockaddr to a string key for connection demux."""
    var key = String()
    for i in range(len(addr)):
        var b = Int(addr[i])
        comptime HEX: String = "0123456789abcdef"
        var hex_bytes = HEX.as_bytes()
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


def _extract_dcid(data: Span[UInt8, _]) raises -> List[UInt8]:
    """Extract the DCID from an incoming QUIC packet.

    For long-header packets (Initial):
      byte 0: header byte (high bit set)
      bytes 1-4: version
      byte 5: DCID length
      bytes 6..6+dcid_len: DCID

    For short-header packets, we use parse_packet_header with a
    default CID length of 8.
    """
    if len(data) < 6:
        raise "_extract_dcid: packet too short"

    var first = Int(data[0])
    if (first & 0x80) != 0:
        # Long header — extract DCID directly.
        var dcid_len = Int(data[5])
        if len(data) < 6 + dcid_len:
            raise "_extract_dcid: packet too short for DCID"
        var dcid = List[UInt8](capacity=dcid_len)
        for i in range(dcid_len):
            dcid.append(data[6 + i])
        return dcid^
    else:
        # Short header — use parser with assumed 8-byte CID.
        var result = parse_packet_header(data, 8)
        return List[UInt8](copy=result[0].dcid)


def _create_server_config(
    lib_ptr: UnsafePointer[RustlsLibrary, MutAnyOrigin],
    alpn: String,
    certs_dir: String,
) raises -> Int32:
    """Create a QUIC server TLS config from PEM files in certs_dir."""
    var cert_data = read_file(certs_dir + "/cert.pem")
    var key_data = read_file(certs_dir + "/priv.key")

    var cert_len = len(cert_data)
    var key_len = len(key_data)

    var cert_buf = _heap_alloc[UInt8](cert_len).as_any_origin()
    for i in range(cert_len):
        cert_buf[i] = cert_data[i]

    var key_buf = _heap_alloc[UInt8](key_len).as_any_origin()
    for i in range(key_len):
        key_buf[i] = key_data[i]

    # ALPN: raw protocol name bytes.
    var alpn_bytes = alpn.as_bytes()
    var alpn_wire_len = len(alpn_bytes)
    var alpn_buf = _heap_alloc[UInt8](alpn_wire_len).as_any_origin()
    for i in range(len(alpn_bytes)):
        alpn_buf[i] = alpn_bytes[i]

    var out_handle = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_server_config_new(
        cert_buf, Int32(cert_len),
        key_buf, Int32(key_len),
        alpn_buf, Int32(alpn_wire_len),
        out_handle,
    )

    var config_handle = out_handle[0]
    cert_buf.free()
    key_buf.free()
    alpn_buf.free()
    out_handle.free()

    if rc != Int32(0):
        raise "quic_server_config_new failed: " + lib_ptr[].last_error()

    return config_handle


# ── main ────────────────────────────────────────────────────────────────


def main() raises:
    # Configuration from environment.
    var certs_opt = getenv_opt("CERTS_DIR")
    var certs_dir = certs_opt.value() if certs_opt else String("/certs")
    var static_opt = getenv_opt("STATIC_DIR")
    var static_dir = static_opt.value() if static_opt else String("/data/static")

    # Load static file cache.
    var cache = _load_static_files(static_dir)
    var cache_ptr = _heap_alloc[Dict[String, StaticEntry]](1).as_any_origin()
    cache_ptr.init_pointee_move(cache^)
    var extra_data = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(cache_ptr)
    )

    # Load TLS library.
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    # Create server TLS config with h3 ALPN.
    var server_config = _create_server_config(lib_ptr.as_any_origin(), "h3", certs_dir)

    # Bind UDP socket on port 8443.
    var port = 8443
    var udp_fd = udp_bind(port)
    print("bench-h3: listening on UDP :" + String(port))

    # Connection state — parallel lists keyed by remote address.
    var conn_keys = List[String]()
    var conn_h3s = List[UnsafePointer[H3CoroServer, MutAnyOrigin]]()
    var conn_addrs = List[List[UInt8]]()

    # Event loop.
    while True:
        # Poll with a short timeout for retransmits.
        var timeout_ms = 50
        var readable = udp_poll(udp_fd, timeout_ms)
        var now = monotonic_us()

        if readable:
            var result = udp_recvfrom(udp_fd)
            var data = result[0].copy()
            var addr = result[1].copy()
            var addr_key = _addr_to_key(addr)

            # Find existing connection for this peer.
            var conn_idx = -1
            for i in range(len(conn_keys)):
                if conn_keys[i] == addr_key:
                    conn_idx = i
                    break

            if conn_idx == -1:
                # New peer — extract DCID and create QuicConnection + H3CoroServer.
                try:
                    var dcid = _extract_dcid(Span(data))
                    var orig_dcid = List[UInt8](copy=dcid)
                    var client_dcid = List[UInt8](copy=dcid)
                    var params = default_transport_params()

                    var quic = QuicConnection.server(
                        lib_addr, server_config, params,
                        Span(orig_dcid), Span(client_dcid), now,
                    )

                    var h3_ptr = _heap_alloc[H3CoroServer](1).as_any_origin()
                    h3_ptr.init_pointee_move(
                        H3CoroServer(
                            quic=quic^,
                            body_fn=bench_h3_body_fn,
                            extra_data=extra_data,
                        )
                    )

                    conn_idx = len(conn_keys)
                    conn_keys.append(addr_key)
                    conn_h3s.append(h3_ptr)
                    conn_addrs.append(List[UInt8](copy=addr))
                except e:
                    print("bench-h3: failed to create connection: " + String(e))
                    continue

            # Feed the datagram to the H3CoroServer.
            if conn_h3s[conn_idx]:
                try:
                    conn_h3s[conn_idx][].feed_datagram(Span(data), now)
                except e:
                    print("bench-h3: feed_datagram error: " + String(e))

        # Drive all connections: drain outgoing datagrams, handle timeouts.
        now = monotonic_us()
        for ci in range(len(conn_keys)):
            if not conn_h3s[ci]:
                continue

            # Drain outgoing datagrams.
            try:
                var out = conn_h3s[ci][].drain_datagrams(now)
                for di in range(len(out)):
                    udp_sendto(udp_fd, Span(out[di]), Span(conn_addrs[ci]))
            except e:
                print("bench-h3: drain_datagrams error: " + String(e))

            # Check if connection should be closed and clean up.
            if conn_h3s[ci][].should_close():
                print("bench-h3: connection closed for conn " + String(ci))
                conn_h3s[ci].destroy_pointee()
                conn_h3s[ci].free()
                conn_h3s[ci] = UnsafePointer[H3CoroServer, MutAnyOrigin]()
