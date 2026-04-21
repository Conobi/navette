# interop/server.mojo
#
# QUIC Interop Runner server binary.
#
# Reads TESTCASE env var, binds UDP :443, accepts QUIC connections,
# serves files from /www via HTTP/0.9.
#
# Supported test cases: handshake, transfer.
# Deferred (exit 127): retry, http3.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections import Optional

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection, QuicEvent
from src.quic.trans_param import TransportParams, default_transport_params
from src.quic.packet import parse_packet_header
from interop.file_io import read_file, getenv, getenv_opt, setenv
from interop.http09 import http09_serve
from interop.udp import udp_bind, udp_recvfrom, udp_sendto, udp_poll, monotonic_us, udp_close


# ── helpers ─────────────────────────────────────────────────────────────


def _addr_to_key(addr: List[UInt8]) -> String:
    """Convert raw 16-byte sockaddr to a string key for connection demux."""
    var key = String()
    for i in range(len(addr)):
        var b = Int(addr[i])
        # Encode each byte as two hex chars.
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
) raises -> Int32:
    """Create a QUIC server TLS config from /certs/ PEM files."""
    var cert_data = read_file("/certs/cert.pem")
    var key_data = read_file("/certs/priv.key")

    var cert_len = len(cert_data)
    var key_len = len(key_data)

    var cert_buf = _heap_alloc[UInt8](cert_len).as_any_origin()
    for i in range(cert_len):
        cert_buf[i] = cert_data[i]

    var key_buf = _heap_alloc[UInt8](key_len).as_any_origin()
    for i in range(key_len):
        key_buf[i] = key_data[i]

    # Encode ALPN: length-prefixed wire format.
    var alpn_bytes = alpn.as_bytes()
    var alpn_wire_len = 1 + len(alpn_bytes)
    var alpn_buf = _heap_alloc[UInt8](alpn_wire_len).as_any_origin()
    alpn_buf[0] = UInt8(len(alpn_bytes))
    for i in range(len(alpn_bytes)):
        alpn_buf[1 + i] = alpn_bytes[i]

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


# ── stream buffering ────────────────────────────────────────────────────


def _has_crlf(data: List[UInt8]) -> Bool:
    """Check if data contains \\r\\n."""
    if len(data) < 2:
        return False
    for i in range(len(data) - 1):
        if data[i] == UInt8(ord("\r")) and data[i + 1] == UInt8(ord("\n")):
            return True
    return False


# ── main ────────────────────────────────────────────────────────────────


def main() raises:
    var testcase = getenv("TESTCASE")

    # Only support handshake and transfer for now. Retry and http3 deferred.
    if testcase != "handshake" and testcase != "transfer":
        _ = external_call["exit", Int32](Int32(127))

    # Load TLS library.
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    # SSLKEYLOGFILE — rustls reads this env var automatically.
    # Nothing extra needed; just ensure it's set in the environment.

    # Create server TLS config with hq-interop ALPN.
    var server_config = _create_server_config(lib_ptr.as_any_origin(), "hq-interop")

    # Bind UDP socket on port 443.
    var udp_fd = udp_bind(443)
    print("interop-server: listening on :443, testcase=" + testcase)

    # Connection state — parallel lists (Dict iteration not supported in 0.26.2).
    var conn_keys = List[String]()
    var conn_ptrs = List[UnsafePointer[QuicConnection, MutAnyOrigin]]()
    var conn_addrs = List[List[UInt8]]()

    # Per-stream request buffers: indexed by (conn_index * 65536 + stream_id).
    # We use parallel lists for stream buffers too.
    var stream_buf_keys = List[UInt64]()
    var stream_buf_vals = List[List[UInt8]]()

    # Event loop.
    while True:
        # Compute timeout from all connections.
        var timeout_ms = 50  # Default poll timeout.
        var now = monotonic_us()
        for ci in range(len(conn_keys)):
            if not conn_ptrs[ci]:
                continue
            var t = conn_ptrs[ci][].timeout(now)
            if t.__bool__():
                var t_ms = Int(t.value() / 1000)
                if t_ms < timeout_ms:
                    timeout_ms = max(t_ms, 1)

        var readable = udp_poll(udp_fd, timeout_ms)
        now = monotonic_us()

        if readable:
            var result = udp_recvfrom(udp_fd)
            var data = result[0].copy()
            var addr = result[1].copy()
            var addr_key = _addr_to_key(addr)

            # Find or create connection for this peer.
            var conn_idx = -1
            for i in range(len(conn_keys)):
                if conn_keys[i] == addr_key:
                    conn_idx = i
                    break

            if conn_idx == -1:
                # New peer — extract DCID from Initial packet and create connection.
                try:
                    var dcid = _extract_dcid(Span(data))
                    var orig_dcid = List[UInt8](copy=dcid)
                    var client_dcid = List[UInt8](copy=dcid)
                    var params = default_transport_params()

                    var conn_ptr = _heap_alloc[QuicConnection](1).as_any_origin()
                    conn_ptr.init_pointee_move(
                        QuicConnection.server(
                            lib_addr, server_config, params,
                            Span(orig_dcid), Span(client_dcid), now,
                        )
                    )

                    conn_idx = len(conn_keys)
                    conn_keys.append(addr_key)
                    conn_ptrs.append(conn_ptr)
                    conn_addrs.append(List[UInt8](copy=addr))
                except e:
                    # Could not parse packet — skip.
                    print("interop-server: failed to create connection: " + String(e))
                    continue

            if conn_ptrs[conn_idx]:
                try:
                    conn_ptrs[conn_idx][].recv(Span(data), now)
                except e:
                    print("interop-server: recv error: " + String(e))

        # Drive all connections: send datagrams, handle events.
        now = monotonic_us()
        for ci in range(len(conn_keys)):
            if not conn_ptrs[ci]:
                continue

            # Send outgoing datagrams.
            try:
                var out = conn_ptrs[ci][].send(now)
                for di in range(len(out)):
                    udp_sendto(udp_fd, Span(out[di]), Span(conn_addrs[ci]))
            except e:
                print("interop-server: send error: " + String(e))

            # Handle events.
            while True:
                var ev_opt = conn_ptrs[ci][].poll()
                if not ev_opt.__bool__():
                    break
                var ev = ev_opt.value().copy()

                if ev.type_id == QuicEvent.STREAM_READABLE or ev.type_id == QuicEvent.STREAM_OPENED:
                    var stream_id = ev.stream_id
                    # Read stream data.
                    try:
                        var rd = conn_ptrs[ci][].recv_stream_data(stream_id)
                        var chunk = rd[0].copy()
                        var fin = rd[1]

                        if len(chunk) == 0 and not fin:
                            continue

                        # Find or create stream buffer.
                        var buf_key = UInt64(ci) * 65536 + stream_id
                        var buf_idx = -1
                        for si in range(len(stream_buf_keys)):
                            if stream_buf_keys[si] == buf_key:
                                buf_idx = si
                                break

                        if buf_idx == -1:
                            buf_idx = len(stream_buf_keys)
                            stream_buf_keys.append(buf_key)
                            stream_buf_vals.append(List[UInt8]())

                        # Append chunk to buffer.
                        for bi in range(len(chunk)):
                            stream_buf_vals[buf_idx].append(chunk[bi])

                        # Check if we have a complete request (\r\n) or FIN.
                        if _has_crlf(stream_buf_vals[buf_idx]) or fin:
                            http09_serve(
                                conn_ptrs[ci][],
                                stream_id,
                                Span(stream_buf_vals[buf_idx]),
                                "/www",
                            )
                            # Clear buffer after serving.
                            stream_buf_vals[buf_idx] = List[UInt8]()
                    except e:
                        print(
                            "interop-server: stream "
                            + String(stream_id)
                            + " error: "
                            + String(e)
                        )

                elif ev.type_id == QuicEvent.HANDSHAKE_COMPLETE:
                    print("interop-server: handshake complete for conn " + String(ci))

                elif ev.type_id == QuicEvent.CONNECTION_CLOSED:
                    print("interop-server: connection closed for conn " + String(ci))

            # Check if connection is closed and clean up.
            if conn_ptrs[ci][].is_closed():
                conn_ptrs[ci].destroy_pointee()
                conn_ptrs[ci].free()
                conn_ptrs[ci] = UnsafePointer[QuicConnection, MutAnyOrigin]()

        # Check if all connections are closed (and we had at least one).
        # For the interop runner, we just keep listening.
