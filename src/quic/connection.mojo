# src/quic/connection.mojo
#
# QuicConnection — sans-I/O QUIC state machine.
#
# Orchestrates packet protection, packet number spaces, loss recovery,
# crypto streams, and the TLS handshake via FFI into librustls_mojo.
#
# Usage:
#   var conn = QuicConnection.client(lib_addr, cfg, "example.com", tp, now)
#   var datagrams = conn.send(now)       # Initial with ClientHello
#   conn.recv(response_bytes, now)       # Feed server reply
#   var ev = conn.poll()                 # HANDSHAKE_COMPLETE, etc.

from std.collections import Dict, Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.tls.lib import RustlsLibrary
from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from src.quic.error import QuicTransportError, NO_ERROR, PROTOCOL_VIOLATION
from src.quic.frame import (
    Frame,
    AckFrame,
    CryptoFrame,
    ConnectionCloseFrame,
    parse_frames,
    serialize_frames,
    FRAME_PADDING,
    FRAME_PING,
    FRAME_ACK,
    FRAME_ACK_ECN,
    FRAME_CRYPTO,
    FRAME_CONNECTION_CLOSE_TRANSPORT,
    FRAME_CONNECTION_CLOSE_APP,
    FRAME_HANDSHAKE_DONE,
    FRAME_NEW_TOKEN,
    FRAME_NEW_CONNECTION_ID,
    FRAME_RETIRE_CONNECTION_ID,
)
from src.quic.packet import (
    PacketType,
    PacketHeader,
    parse_packet_header,
    serialize_long_header,
    serialize_short_header,
    pn_decode,
    pn_truncate,
    pn_encode_length,
    MIN_INITIAL_PACKET_SIZE,
)
from src.quic.trans_param import (
    TransportParams,
    parse_transport_params,
    serialize_transport_params,
)
from src.quic.pn_space import (
    EncryptionLevel,
    packet_type_to_space,
    PacketNumberSpace,
    SentPacket,
)
from src.quic.recovery import Recovery
from src.quic.crypto_stream import CryptoStream
from src.quic.packet_protect import PacketProtect

# ── Connection state bitflags ────────────────────────────────────────

comptime CONN_HANDSHAKING: UInt8 = 0x01
comptime CONN_ESTABLISHED: UInt8 = 0x02
comptime CONN_ADDR_VALIDATED: UInt8 = 0x04
comptime CONN_INITIAL_DISCARDED: UInt8 = 0x08
comptime CONN_HS_DISCARDED: UInt8 = 0x10
comptime CONN_CLOSING: UInt8 = 0x20
comptime CONN_DRAINING: UInt8 = 0x40
comptime CONN_CLOSED: UInt8 = 0x80

# ── Constants ────────────────────────────────────────────────────────

comptime _AEAD_TAG_LEN: Int = 16
comptime _WRITE_HS_BUF_SIZE: Int = 4096
comptime _TP_BUF_SIZE: Int = 1024
comptime _MAX_CRYPTO_FRAME_SIZE: Int = 1200


# ── QuicEvent ────────────────────────────────────────────────────────


struct QuicEvent(Copyable, Movable):
    """Event emitted by QuicConnection for the application layer."""

    comptime HANDSHAKE_COMPLETE: UInt8 = 1
    comptime CONNECTION_CLOSED: UInt8 = 2
    comptime PEER_TRANSPORT_PARAMS: UInt8 = 3

    var type_id: UInt8
    var error_code: UInt64
    var reason: String
    var transport_params: Optional[TransportParams]

    def __init__(out self, type_id: UInt8):
        self.type_id = type_id
        self.error_code = UInt64(0)
        self.reason = String("")
        self.transport_params = None

    def __init__(out self, *, other: Self):
        self.type_id = other.type_id
        self.error_code = other.error_code
        self.reason = other.reason
        self.transport_params = other.transport_params.copy()

    def __init__(out self, *, deinit take: Self):
        self.type_id = take.type_id
        self.error_code = take.error_code
        self.reason = take.reason^
        self.transport_params = take.transport_params^

    @staticmethod
    def handshake_complete() -> QuicEvent:
        return QuicEvent(QuicEvent.HANDSHAKE_COMPLETE)

    @staticmethod
    def connection_closed(error_code: UInt64, reason: String) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.CONNECTION_CLOSED)
        ev.error_code = error_code
        ev.reason = reason
        return ev^

    @staticmethod
    def peer_transport_params(params: TransportParams) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.PEER_TRANSPORT_PARAMS)
        ev.transport_params = TransportParams(other=params)
        return ev^


# ── QuicConnection ───────────────────────────────────────────────────


struct QuicConnection(Movable):
    """Sans-I/O QUIC connection state machine.

    Call `send()` to get datagrams to transmit, `recv()` to feed incoming
    datagrams, and `poll()` to retrieve events. Use `timeout()` to
    determine when to next call `send()`.
    """

    var is_server: Bool
    var state: UInt8
    var spaces: List[PacketNumberSpace]
    var crypto_streams: List[CryptoStream]
    var recovery: Recovery
    var protect: PacketProtect
    var conn_handle: Int32
    var lib_addr: UInt64
    var local_params: TransportParams
    var peer_params: Optional[TransportParams]
    var local_cid: List[UInt8]
    var peer_cid: List[UInt8]
    var initial_dcid: List[UInt8]
    var bytes_received: UInt64
    var bytes_sent: UInt64
    var events: List[QuicEvent]
    var pending_close: Optional[ConnectionCloseFrame]
    var close_timer: UInt64
    var drain_timer: UInt64
    var idle_timer: UInt64
    var handshake_confirmed: Bool
    var current_level: Int
    var send_handshake_done: Bool
    var last_ack_eliciting_send_time: UInt64

    # ── Move constructor ─────────────────────────────────────────────

    def __init__(out self, *, deinit take: Self):
        self.is_server = take.is_server
        self.state = take.state
        self.spaces = take.spaces^
        self.crypto_streams = take.crypto_streams^
        self.recovery = take.recovery^
        self.protect = take.protect^
        self.conn_handle = take.conn_handle
        self.lib_addr = take.lib_addr
        self.local_params = take.local_params^
        self.peer_params = take.peer_params^
        self.local_cid = take.local_cid^
        self.peer_cid = take.peer_cid^
        self.initial_dcid = take.initial_dcid^
        self.bytes_received = take.bytes_received
        self.bytes_sent = take.bytes_sent
        self.events = take.events^
        self.pending_close = take.pending_close^
        self.close_timer = take.close_timer
        self.drain_timer = take.drain_timer
        self.idle_timer = take.idle_timer
        self.handshake_confirmed = take.handshake_confirmed
        self.current_level = take.current_level
        self.send_handshake_done = take.send_handshake_done
        self.last_ack_eliciting_send_time = take.last_ack_eliciting_send_time

    # ── Private constructor (used by factory methods) ────────────────

    def __init__(
        out self,
        is_server: Bool,
        lib_addr: UInt64,
        conn_handle: Int32,
        local_params: TransportParams,
        local_cid: List[UInt8],
        peer_cid: List[UInt8],
        initial_dcid: List[UInt8],
        now: UInt64,
    ):
        self.is_server = is_server
        self.state = CONN_HANDSHAKING
        self.spaces = List[PacketNumberSpace](capacity=3)
        self.spaces.append(PacketNumberSpace(EncryptionLevel.initial()))
        self.spaces.append(PacketNumberSpace(EncryptionLevel.handshake()))
        self.spaces.append(PacketNumberSpace(EncryptionLevel.application()))
        self.crypto_streams = List[CryptoStream](capacity=3)
        self.crypto_streams.append(CryptoStream())
        self.crypto_streams.append(CryptoStream())
        self.crypto_streams.append(CryptoStream())
        self.recovery = Recovery()
        self.protect = PacketProtect(lib_addr)
        self.conn_handle = conn_handle
        self.lib_addr = lib_addr
        self.local_params = TransportParams(other=local_params)
        self.peer_params = None
        self.local_cid = List[UInt8](copy=local_cid)
        self.peer_cid = List[UInt8](copy=peer_cid)
        self.initial_dcid = List[UInt8](copy=initial_dcid)
        self.bytes_received = UInt64(0)
        self.bytes_sent = UInt64(0)
        self.events = List[QuicEvent]()
        self.pending_close = None
        self.close_timer = UInt64(0)
        self.drain_timer = UInt64(0)
        self.idle_timer = now
        self.handshake_confirmed = False
        self.current_level = 0
        self.send_handshake_done = False
        self.last_ack_eliciting_send_time = UInt64(0)

    # ── Destructor ───────────────────────────────────────────────────

    def __del__(deinit self):
        if self.conn_handle >= 0:
            _ = self._lib()[].quic_conn_free(self.conn_handle)
        # PacketProtect.__del__ handles key cleanup.

    # ── Static factory methods ───────────────────────────────────────

    @staticmethod
    def client(
        lib_addr: UInt64,
        config_handle: Int32,
        server_name: String,
        local_params: TransportParams,
        now: UInt64,
    ) raises -> QuicConnection:
        """Create a QUIC client connection.

        Derives initial keys, creates TLS connection, and drives the
        initial write_hs to generate ClientHello CRYPTO data.
        """
        # 1. Generate random 8-byte DCID and local CID.
        var dcid = _generate_random_cid()
        var local_cid = _generate_random_cid()

        # 2. Serialize local transport params.
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(other=local_params)
        params_copy.initial_scid = List[UInt8](copy=local_cid)
        serialize_transport_params(params_copy, tp_writer)
        var tp_bytes = tp_writer.finish()

        # 3. Create QUIC client TLS connection.
        var sni_bytes = server_name.as_bytes()
        var sni_len = len(sni_bytes)
        var sni_buf = _heap_alloc[UInt8](sni_len).as_any_origin()
        for i in range(sni_len):
            sni_buf[i] = sni_bytes[i]

        var tp_len = len(tp_bytes)
        var tp_buf = _heap_alloc[UInt8](tp_len).as_any_origin()
        for i in range(tp_len):
            tp_buf[i] = tp_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)

        var lib = _get_lib(lib_addr)
        var rc = lib[].quic_client_conn_new(
            config_handle,
            Int32(1),  # QUIC version 1
            sni_buf,
            Int32(sni_len),
            tp_buf,
            Int32(tp_len),
            out_handle,
        )

        sni_buf.free()
        tp_buf.free()

        if rc < 0:
            var err = lib[].last_error()
            out_handle.free()
            raise "quic_client_conn_new failed: " + err

        var conn_handle = out_handle[0]
        out_handle.free()

        if conn_handle < 0:
            raise "quic_client_conn_new returned invalid handle"

        # 4. Build connection object.
        var conn = QuicConnection(
            is_server=False,
            lib_addr=lib_addr,
            conn_handle=conn_handle,
            local_params=params_copy,
            local_cid=local_cid,
            peer_cid=dcid,
            initial_dcid=dcid,
            now=now,
        )

        # 5. Derive initial keys from DCID (client side).
        conn.protect.derive_initial_keys(Span(dcid), is_client=True)

        # 6. Drive initial write_hs to get ClientHello CRYPTO data.
        conn._drive_handshake(now)

        return conn^

    @staticmethod
    def server(
        lib_addr: UInt64,
        config_handle: Int32,
        local_params: TransportParams,
        orig_dcid: Span[UInt8],
        client_dcid: Span[UInt8],
        now: UInt64,
    ) raises -> QuicConnection:
        """Create a QUIC server connection.

        Derives initial keys from the client's DCID and waits for
        the client Initial to drive the handshake.
        """
        # 1. Generate random 8-byte local CID (server's SCID).
        var local_cid = _generate_random_cid()

        # 2. Serialize local transport params.
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(other=local_params)
        params_copy.initial_scid = List[UInt8](copy=local_cid)
        # Server sets original_dcid to prove it received the client's Initial.
        var orig_dcid_list = List[UInt8](capacity=len(orig_dcid))
        for i in range(len(orig_dcid)):
            orig_dcid_list.append(orig_dcid[i])
        params_copy.original_dcid = orig_dcid_list^
        serialize_transport_params(params_copy, tp_writer)
        var tp_bytes = tp_writer.finish()

        # 3. Create QUIC server TLS connection.
        var tp_len = len(tp_bytes)
        var tp_buf = _heap_alloc[UInt8](tp_len).as_any_origin()
        for i in range(tp_len):
            tp_buf[i] = tp_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)

        var lib = _get_lib(lib_addr)
        var rc = lib[].quic_server_conn_new(
            config_handle,
            Int32(1),  # QUIC version 1
            tp_buf,
            Int32(tp_len),
            out_handle,
        )

        tp_buf.free()

        if rc < 0:
            var err = lib[].last_error()
            out_handle.free()
            raise "quic_server_conn_new failed: " + err

        var conn_handle = out_handle[0]
        out_handle.free()

        if conn_handle < 0:
            raise "quic_server_conn_new returned invalid handle"

        # 4. Build peer_cid from orig_dcid.
        var peer_cid = List[UInt8](capacity=len(orig_dcid))
        for i in range(len(orig_dcid)):
            peer_cid.append(orig_dcid[i])

        # 5. Build initial_dcid from client_dcid.
        var initial_dcid = List[UInt8](capacity=len(client_dcid))
        for i in range(len(client_dcid)):
            initial_dcid.append(client_dcid[i])

        # 6. Build connection object.
        var conn = QuicConnection(
            is_server=True,
            lib_addr=lib_addr,
            conn_handle=conn_handle,
            local_params=params_copy,
            local_cid=local_cid,
            peer_cid=peer_cid,
            initial_dcid=initial_dcid,
            now=now,
        )

        # 7. Derive initial keys from client's DCID (server side).
        conn.protect.derive_initial_keys(client_dcid, is_client=False)

        # 8. Server address validation deferred until Handshake decrypt.

        return conn^

    # ── Receive path ─────────────────────────────────────────────────

    def recv(mut self, datagram: Span[UInt8], now: UInt64) raises:
        """Process an incoming UDP datagram.

        Parses coalesced packets, decrypts payloads, dispatches frames,
        and drives the TLS handshake as needed.
        """
        self.bytes_received += UInt64(len(datagram))
        self.idle_timer = now

        var offset = 0
        while offset < len(datagram):
            # 1. Copy remaining bytes into a working buffer.
            var remaining = List[UInt8](capacity=len(datagram) - offset)
            for i in range(offset, len(datagram)):
                remaining.append(datagram[i])

            # 2. Parse packet header.
            var header_result = parse_packet_header(
                Span(remaining), len(self.local_cid)
            )
            var header = header_result.get[0, PacketHeader]()
            var header_end = header_result.get[1, Int]()

            # 3. Map to PN space.
            var space_idx = packet_type_to_space(header.packet_type)
            if space_idx < 0:
                break  # VN, Retry — skip for M3b

            if not self.protect.has_keys(space_idx):
                break  # Can't decrypt without keys

            # 4. Determine packet boundary.
            var pkt_len: Int
            if header.is_long_header:
                pkt_len = header.pn_offset + Int(header.payload_length)
            else:
                pkt_len = len(remaining)

            if pkt_len > len(remaining):
                break  # Truncated packet

            # 5. Copy packet bytes for in-place operations.
            var pkt_buf = List[UInt8](capacity=pkt_len)
            for i in range(pkt_len):
                pkt_buf.append(remaining[i])

            # 6. Unprotect header.
            var hp_result = self.protect.unprotect_header(
                space_idx, pkt_buf, header.pn_offset
            )
            var first_byte = hp_result.get[0, UInt8]()
            var pn_length = hp_result.get[1, Int]()

            # 7. Decode packet number.
            var truncated_pn = UInt64(0)
            for i in range(pn_length):
                truncated_pn = (truncated_pn << 8) | UInt64(
                    pkt_buf[header.pn_offset + i]
                )
            var largest = UInt64(0)
            if self.spaces[space_idx].largest_recv_pn >= 0:
                largest = UInt64(self.spaces[space_idx].largest_recv_pn)
            var full_pn = pn_decode(truncated_pn, pn_length, largest)

            # 8. Decrypt payload.
            var header_len = header.pn_offset + pn_length
            var plaintext = self.protect.decrypt_payload(
                space_idx, full_pn, header_len, pkt_buf
            )

            # 9. Server validates address on first Handshake decrypt.
            if self.is_server and space_idx == 1 and (self.state & CONN_ADDR_VALIDATED) == 0:
                self.state = self.state | CONN_ADDR_VALIDATED

            # 10. Parse and dispatch frames.
            var reader = ByteReader(Span(plaintext))
            var frames = parse_frames(reader)
            var ack_eliciting = False
            for i in range(len(frames)):
                if frames[i].is_ack_eliciting():
                    ack_eliciting = True
                self._dispatch_frame(frames[i], space_idx, now)

            # 11. Update PN space.
            self.spaces[space_idx].on_packet_received(full_pn, ack_eliciting)

            # 12. Drive handshake after CRYPTO processing.
            self._drive_handshake(now)

            offset += pkt_len

    # ── Frame dispatch ───────────────────────────────────────────────

    def _dispatch_frame(
        mut self, frame: Frame, space_idx: Int, now: UInt64
    ) raises:
        """Route a parsed frame to its handler."""
        var tid = frame.type_id

        # PADDING: no-op
        if tid == FRAME_PADDING:
            return

        # PING: no-op (ack_eliciting tracked by caller)
        if tid == FRAME_PING:
            return

        # ACK
        if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
            if frame._ack:
                var ack_frame = frame._ack.value()
                self._handle_ack(ack_frame, space_idx, now)
            return

        # CRYPTO
        if tid == FRAME_CRYPTO:
            if frame._crypto:
                var cf = frame._crypto.value()
                self.crypto_streams[space_idx].receive(
                    cf.offset, Span(cf.data)
                )
            return

        # CONNECTION_CLOSE
        if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
            if frame._conn_close:
                var cc = frame._conn_close.value()
                self.state = self.state | CONN_DRAINING
                # Start drain timer: 3 * PTO.
                var pto = self.recovery.pto_timeout(
                    self.local_params.max_ack_delay * 1000
                )
                self.drain_timer = now + 3 * pto
                # Build reason string from bytes.
                var reason = String("")
                for i in range(len(cc.reason)):
                    reason += chr(Int(cc.reason[i]))
                self.events.append(
                    QuicEvent.connection_closed(cc.error_code, reason)
                )
            return

        # HANDSHAKE_DONE (client receives from server)
        if tid == FRAME_HANDSHAKE_DONE:
            if not self.is_server:
                self.handshake_confirmed = True
                self.state = self.state | CONN_ESTABLISHED
                self._discard_handshake_space()
                self.events.append(QuicEvent.handshake_complete())
            return

        # NEW_TOKEN, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID: minimal handling
        if tid == FRAME_NEW_TOKEN:
            return  # Ignore for M3b
        if tid == FRAME_NEW_CONNECTION_ID:
            return  # Minimal — store in future
        if tid == FRAME_RETIRE_CONNECTION_ID:
            return  # Minimal — acknowledge in future

        # Stream-level frames: silently ignore for M3b.
        return

    # ── ACK handling ─────────────────────────────────────────────────

    def _handle_ack(
        mut self, ack_frame: AckFrame, space_idx: Int, now: UInt64
    ) raises:
        """Process an ACK frame: update recovery, detect losses."""
        # Get newly acked packets.
        var acked = self.spaces[space_idx].on_ack_received(ack_frame)

        if len(acked) == 0:
            return

        # Update RTT from the largest newly acked packet.
        var largest_acked_pn = ack_frame.largest_ack
        # Find the sent packet matching largest_ack for RTT.
        for i in range(len(acked)):
            if acked[i].pn == largest_acked_pn:
                var rtt_sample = now - acked[i].time_sent
                if now >= acked[i].time_sent:
                    # Convert ack_delay using peer's exponent when available.
                    var ade = self.local_params.ack_delay_exponent
                    var mad = self.local_params.max_ack_delay
                    if self.peer_params:
                        ade = self.peer_params.value().ack_delay_exponent
                        mad = self.peer_params.value().max_ack_delay
                    var ack_delay_us = ack_frame.ack_delay * (
                        UInt64(1) << ade
                    )
                    var max_ack_delay_us = mad * 1000
                    self.recovery.update_rtt(
                        rtt_sample,
                        ack_delay_us,
                        max_ack_delay_us,
                        self.handshake_confirmed,
                    )
                break

        # Release bytes for acked packets.
        for i in range(len(acked)):
            self.recovery.on_packet_acked(acked[i].size, acked[i].in_flight)

        # Reset PTO count.
        self.recovery.on_ack_received()

        # Client confirms handshake when it receives ACK for 1-RTT packet.
        if not self.is_server and space_idx == 2 and not self.handshake_confirmed:
            self._on_handshake_complete(now)

        # Detect lost packets.
        self._detect_losses(space_idx, now)

    # ── Loss detection ───────────────────────────────────────────────

    def _detect_losses(mut self, space_idx: Int, now: UInt64) raises:
        """Check for lost packets in the given PN space."""
        if self.spaces[space_idx].largest_acked_pn < 0:
            return

        # Collect sent packet info for loss detection.
        var sent_pns = List[Int]()
        var sent_times = List[UInt64]()
        var sent_in_flight = List[Bool]()

        for entry in self.spaces[space_idx].sent_packets.items():
            sent_pns.append(entry.key)
            sent_times.append(entry.value.time_sent)
            sent_in_flight.append(entry.value.in_flight)

        var lost_pns = self.recovery.detect_lost_packets(
            sent_pns,
            sent_times,
            sent_in_flight,
            self.spaces[space_idx].largest_acked_pn,
            now,
        )

        # Process lost packets.
        for i in range(len(lost_pns)):
            var pn_key = lost_pns[i]
            if pn_key in self.spaces[space_idx].sent_packets:
                var lost_pkt = SentPacket(
                    other=self.spaces[space_idx].sent_packets[pn_key]
                )
                self.recovery.on_packet_lost(lost_pkt.size, lost_pkt.in_flight)

                # Re-queue CRYPTO frames for retransmission.
                for f in range(len(lost_pkt.frames)):
                    if lost_pkt.frames[f].is_crypto():
                        if lost_pkt.frames[f]._crypto:
                            var cf = lost_pkt.frames[f]._crypto.value()
                            self.crypto_streams[space_idx].write(Span(cf.data))

                _ = self.spaces[space_idx].sent_packets.pop(pn_key)

    # ── Handshake driver ─────────────────────────────────────────────

    def _drive_handshake(mut self, now: UInt64) raises:
        """Drain crypto data and feed/read from TLS state machine."""
        if self.conn_handle < 0:
            return

        var lib = self._lib()

        # 1. Drain contiguous CRYPTO bytes from each space's crypto_stream
        #    and feed them to the TLS engine.
        for level in range(3):
            if self.crypto_streams[level].has_pending():
                var crypto_data = self.crypto_streams[level].drain()
                if len(crypto_data) > 0:
                    var data_buf = _heap_alloc[UInt8](
                        len(crypto_data)
                    ).as_any_origin()
                    for i in range(len(crypto_data)):
                        data_buf[i] = crypto_data[i]

                    var rc = lib[].quic_conn_read_hs(
                        self.conn_handle,
                        data_buf,
                        Int32(len(crypto_data)),
                    )
                    data_buf.free()

                    if rc < 0:
                        raise (
                            "quic_conn_read_hs failed: " + lib[].last_error()
                        )

        # 2. Loop write_hs to drain TLS output.
        var out_buf = _heap_alloc[UInt8](_WRITE_HS_BUF_SIZE).as_any_origin()
        var out_written = _heap_alloc[Int32](1).as_any_origin()
        var out_kc = _heap_alloc[UInt8](1).as_any_origin()

        while True:
            out_written[0] = Int32(0)
            out_kc[0] = UInt8(0)

            var rc = lib[].quic_conn_write_hs(
                self.conn_handle,
                out_buf,
                Int32(_WRITE_HS_BUF_SIZE),
                out_written,
                out_kc,
            )

            if rc < 0:
                var err = lib[].last_error()
                out_buf.free()
                out_written.free()
                out_kc.free()
                raise "quic_conn_write_hs failed: " + err

            var kc = out_kc[0]
            var written = Int(out_written[0])

            # Handle key change BEFORE processing the data.
            # kc: 0=none, 1=Handshake keys ready, 2=1-RTT keys ready.
            if kc != UInt8(0):
                var keys_handle_buf = _heap_alloc[Int32](1).as_any_origin()
                keys_handle_buf[0] = Int32(-1)

                var take_rc = lib[].quic_conn_take_keys(
                    self.conn_handle, keys_handle_buf
                )

                if take_rc < 0:
                    var err = lib[].last_error()
                    keys_handle_buf.free()
                    out_buf.free()
                    out_written.free()
                    out_kc.free()
                    raise "quic_conn_take_keys failed: " + err

                var new_keys = keys_handle_buf[0]
                keys_handle_buf.free()

                if kc == UInt8(1):
                    # Handshake keys.
                    self.protect.set_keys(1, new_keys)
                    self.current_level = 1
                elif kc == UInt8(2):
                    # 1-RTT (Application) keys.
                    self.protect.set_keys(2, new_keys)
                    self.current_level = 2

            # Append TLS bytes to the NEW level's crypto_stream send_buf.
            if written > 0:
                # Determine which level these bytes target.
                var target_level = self.current_level
                var tls_data = List[UInt8](capacity=written)
                for i in range(written):
                    tls_data.append(out_buf[i])
                self.crypto_streams[target_level].write(Span(tls_data))
            else:
                break  # No more TLS output

        out_buf.free()
        out_written.free()
        out_kc.free()

        # 3. Check if handshake is complete.
        var hs_state = lib[].quic_conn_is_handshaking(self.conn_handle)
        if hs_state == Int32(0):
            # Handshake complete.
            self._on_handshake_complete(now)

    def _on_handshake_complete(mut self, now: UInt64) raises:
        """Called when TLS reports handshake is complete."""
        if (self.state & CONN_ESTABLISHED) != 0:
            return  # Already processed

        # Clear HANDSHAKING flag.
        self.state = self.state & ~CONN_HANDSHAKING

        # Read peer transport params.
        var tp_buf = _heap_alloc[UInt8](_TP_BUF_SIZE).as_any_origin()
        var tp_written = _heap_alloc[Int32](1).as_any_origin()
        tp_written[0] = Int32(0)

        var lib = self._lib()
        var rc = lib[].quic_conn_transport_params(
            self.conn_handle,
            tp_buf,
            Int32(_TP_BUF_SIZE),
            tp_written,
        )

        if rc == Int32(0) and Int(tp_written[0]) > 0:
            var tp_len = Int(tp_written[0])
            var tp_bytes = List[UInt8](capacity=tp_len)
            for i in range(tp_len):
                tp_bytes.append(tp_buf[i])

            var peer_tp = parse_transport_params(Span(tp_bytes))
            self.peer_params = TransportParams(other=peer_tp)
            self.events.append(QuicEvent.peer_transport_params(peer_tp))

        tp_buf.free()
        tp_written.free()

        if self.is_server:
            # Server: set ESTABLISHED, discard Initial & Handshake, queue HANDSHAKE_DONE.
            self.state = self.state | CONN_ESTABLISHED
            self.handshake_confirmed = True
            self._discard_initial_space()
            self._discard_handshake_space()
            self.send_handshake_done = True
            self.events.append(QuicEvent.handshake_complete())
        else:
            # Client: wait for HANDSHAKE_DONE frame from server.
            # Discard Initial space now since we have Handshake keys.
            self._discard_initial_space()

    # ── Space discard helpers ────────────────────────────────────────

    def _discard_initial_space(mut self) raises:
        """Discard Initial packet number space and keys."""
        if (self.state & CONN_INITIAL_DISCARDED) != 0:
            return
        self.state = self.state | CONN_INITIAL_DISCARDED

        var discarded = self.spaces[0].discard()
        for i in range(len(discarded)):
            self.recovery.on_packet_lost(discarded[i].size, discarded[i].in_flight)

        self.protect.discard_keys(0)

    def _discard_handshake_space(mut self) raises:
        """Discard Handshake packet number space and keys."""
        if (self.state & CONN_HS_DISCARDED) != 0:
            return
        self.state = self.state | CONN_HS_DISCARDED

        var discarded = self.spaces[1].discard()
        for i in range(len(discarded)):
            self.recovery.on_packet_lost(
                discarded[i].size, discarded[i].in_flight
            )

        self.protect.discard_keys(1)

    # ── Send path ────────────────────────────────────────────────────

    def send(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Build and return datagrams to send.

        Coalesces packets from multiple encryption levels into a single
        datagram when possible. Pads Initial datagrams to 1200 bytes.
        """
        var datagrams = List[List[UInt8]]()
        if (self.state & CONN_DRAINING) != 0 or (self.state & CONN_CLOSED) != 0:
            return datagrams^

        # Check timers.
        self._check_timers(now)

        # Build one datagram with coalesced packets.
        var datagram = List[UInt8]()
        var has_initial = False

        for space_idx in range(3):
            if not self.protect.has_keys(space_idx):
                continue

            # Anti-amplification check (server only, before address validated).
            if self.is_server and not self._addr_validated():
                if self.bytes_sent + UInt64(len(datagram)) + 100 > 3 * self.bytes_received:
                    break

            var frames = self._build_frames_for_space(space_idx, now)
            if len(frames) == 0:
                continue

            # For Initial packets, add PADDING frames inside the AEAD-protected
            # payload so the datagram reaches MIN_INITIAL_PACKET_SIZE (1200).
            if space_idx == 0:
                # Estimate header overhead: long header + PN + AEAD tag.
                # Long header ≈ 1+4+1+DCID+1+SCID+varint(token_len)+token+varint(payload_len)
                # Conservative estimate: 7 + len(peer_cid) + len(local_cid) + 2 + 4
                var hdr_overhead = 7 + len(self.peer_cid) + len(self.local_cid) + 2
                var pn_est = 4  # max PN length
                var tag_len = _AEAD_TAG_LEN

                # Serialize current frames to measure payload size.
                var est_writer = ByteWriter()
                serialize_frames(frames, est_writer)
                var est_payload = est_writer.finish()
                var current_total = hdr_overhead + pn_est + len(est_payload) + tag_len + len(datagram)

                if current_total < 1200:
                    var pad_needed = 1200 - current_total
                    for _ in range(pad_needed):
                        frames.append(Frame.padding())

            # Serialize frames.
            var writer = ByteWriter()
            serialize_frames(frames, writer)
            var payload = writer.finish()

            # Encode PN.
            var pn = self.spaces[space_idx].alloc_pn()
            var largest_acked = UInt64(0)
            if self.spaces[space_idx].largest_acked_pn >= 0:
                largest_acked = UInt64(self.spaces[space_idx].largest_acked_pn)
            var pn_len = pn_encode_length(pn, largest_acked)

            # Build header + encrypt + protect.
            var pkt = self._build_packet(space_idx, pn, pn_len, payload)
            var pkt_size = len(pkt)

            datagram.extend(pkt^)

            if space_idx == 0:
                has_initial = True

            # Client discards Initial on first Handshake send (M5).
            if not self.is_server and space_idx == 1 and (self.state & CONN_INITIAL_DISCARDED) == 0 and self.protect.has_keys(1):
                self._discard_initial_space()

            # Record sent packet.
            var is_ack_eliciting = _has_ack_eliciting(frames)
            var sent = SentPacket(
                pn=pn,
                time_sent=now,
                ack_eliciting=is_ack_eliciting,
                in_flight=True,
                size=pkt_size,
                frames=frames,
            )
            self.spaces[space_idx].on_packet_sent(sent)
            self.recovery.on_packet_sent(pkt_size, True)

            # Track last ack-eliciting send time for PTO.
            if is_ack_eliciting:
                self.last_ack_eliciting_send_time = now

        if len(datagram) > 0:
            self.bytes_sent += UInt64(len(datagram))
            datagrams.append(datagram^)

        return datagrams^

    # ── Frame building ───────────────────────────────────────────────

    def _build_frames_for_space(
        mut self, space_idx: Int, now: UInt64
    ) raises -> List[Frame]:
        """Collect frames to send for a given PN space."""
        var frames = List[Frame]()

        # ACK frame (if needed).
        var maybe_ack = self.spaces[space_idx].build_ack_frame(UInt64(0))
        if maybe_ack:
            frames.append(Frame.ack(maybe_ack.value()))

        # CRYPTO frames from the crypto stream's send_buf.
        var crypto_frames = self.crypto_streams[space_idx].pending_crypto_frames(
            _MAX_CRYPTO_FRAME_SIZE
        )
        for i in range(len(crypto_frames)):
            frames.append(Frame.crypto(crypto_frames[i]))

        # Advance send offset for queued crypto data.
        if len(crypto_frames) > 0:
            var total_crypto = UInt64(0)
            for i in range(len(crypto_frames)):
                total_crypto += UInt64(len(crypto_frames[i].data))
            self.crypto_streams[space_idx].advance_send(total_crypto)

        # HANDSHAKE_DONE (server, Application space, once).
        if self.send_handshake_done and space_idx == 2 and self.is_server:
            frames.append(Frame.handshake_done())
            self.send_handshake_done = False

        # CONNECTION_CLOSE (if closing).
        if (self.state & CONN_CLOSING) != 0 and self.pending_close:
            frames.append(
                Frame.connection_close(self.pending_close.value())
            )

        return frames^

    # ── Packet building ──────────────────────────────────────────────

    def _build_packet(
        mut self,
        space_idx: Int,
        pn: UInt64,
        pn_len: Int,
        payload: List[UInt8],
    ) raises -> List[UInt8]:
        """Build a complete encrypted QUIC packet.

        1. Serialize header.
        2. Write PN bytes.
        3. AEAD encrypt the frame payload.
        4. Apply header protection.
        """
        var payload_ciphertext_len = len(payload) + _AEAD_TAG_LEN

        if space_idx == 0 or space_idx == 1:
            # Long header (Initial or Handshake).
            var header = PacketHeader()
            header.is_long_header = True
            header.version = UInt32(1)
            header.dcid = List[UInt8](copy=self.peer_cid)
            header.scid = List[UInt8](copy=self.local_cid)

            if space_idx == 0:
                header.packet_type = PacketType.initial()
                # Token is empty for M3b (no retry support yet).
                header.token = List[UInt8]()
            else:
                header.packet_type = PacketType.handshake()

            # payload_length = pn_len + ciphertext + tag.
            header.payload_length = UInt64(pn_len + payload_ciphertext_len)

            # Serialize header.
            var hw = ByteWriter()
            serialize_long_header(header, hw)
            var header_bytes = hw.finish()

            # Set PN length in the first byte (lower 2 bits = pn_len - 1).
            header_bytes[0] = (header_bytes[0] & 0xFC) | UInt8(pn_len - 1)

            # Record pn_offset (where PN bytes start).
            var pn_offset = len(header_bytes)

            # Append PN bytes.
            var truncated = pn_truncate(pn, pn_len)
            for i in range(pn_len):
                var shift = UInt64((pn_len - 1 - i) * 8)
                header_bytes.append(UInt8((truncated >> shift) & 0xFF))

            # Encrypt payload.
            var header_span = Span(header_bytes)
            var ciphertext = self.protect.encrypt_payload(
                space_idx, pn, header_span, Span(payload)
            )

            # Assemble full packet: header + PN + ciphertext.
            var packet = List[UInt8](
                capacity=len(header_bytes) + len(ciphertext)
            )
            for i in range(len(header_bytes)):
                packet.append(header_bytes[i])
            for i in range(len(ciphertext)):
                packet.append(ciphertext[i])

            # Apply header protection.
            self.protect.protect_header(
                space_idx, packet, pn_offset, pn_len
            )

            return packet^

        else:
            # Short header (1-RTT / Application).
            var hw = ByteWriter()
            serialize_short_header(Span(self.peer_cid), hw)
            var header_bytes = hw.finish()

            # Set PN length in the first byte (lower 2 bits = pn_len - 1).
            header_bytes[0] = (header_bytes[0] & 0xFC) | UInt8(pn_len - 1)

            # Record pn_offset.
            var pn_offset = len(header_bytes)

            # Append PN bytes.
            var truncated = pn_truncate(pn, pn_len)
            for i in range(pn_len):
                var shift = UInt64((pn_len - 1 - i) * 8)
                header_bytes.append(UInt8((truncated >> shift) & 0xFF))

            # Encrypt payload.
            var header_span = Span(header_bytes)
            var ciphertext = self.protect.encrypt_payload(
                space_idx, pn, header_span, Span(payload)
            )

            # Assemble full packet.
            var packet = List[UInt8](
                capacity=len(header_bytes) + len(ciphertext)
            )
            for i in range(len(header_bytes)):
                packet.append(header_bytes[i])
            for i in range(len(ciphertext)):
                packet.append(ciphertext[i])

            # Apply header protection.
            self.protect.protect_header(
                space_idx, packet, pn_offset, pn_len
            )

            return packet^

    # ── Timers ───────────────────────────────────────────────────────

    def timeout(self) -> Optional[UInt64]:
        """Return the earliest deadline among PTO, idle, close/drain timers.

        Returns None if no timer is active.
        """
        var earliest = Optional[UInt64](None)

        # PTO timer — skip when server is amplification-limited (M7).
        if not (self.is_server and (self.state & CONN_ADDR_VALIDATED) == 0):
            # Only arm PTO if we have sent ack-eliciting packets.
            if self.last_ack_eliciting_send_time > 0:
                var max_ack_delay_us = self.local_params.max_ack_delay * 1000
                var pto = self.recovery.pto_timeout(max_ack_delay_us)
                var pto_deadline = self.last_ack_eliciting_send_time + pto
                earliest = pto_deadline
            elif not self.is_server:
                # Client anti-deadlock: arm PTO from idle_timer even without sends.
                var max_ack_delay_us = self.local_params.max_ack_delay * 1000
                var pto = self.recovery.pto_timeout(max_ack_delay_us)
                var pto_deadline = self.idle_timer + pto
                earliest = pto_deadline

        # Idle timer — use effective min(local, peer) (M8).
        var local_idle = self.local_params.max_idle_timeout
        var peer_idle = UInt64(0)
        if self.peer_params:
            peer_idle = self.peer_params.value().max_idle_timeout
        var effective_idle = UInt64(0)
        if local_idle == 0 and peer_idle == 0:
            effective_idle = UInt64(0)  # disabled
        elif local_idle == 0:
            effective_idle = peer_idle
        elif peer_idle == 0:
            effective_idle = local_idle
        else:
            effective_idle = local_idle
            if peer_idle < effective_idle:
                effective_idle = peer_idle
        if effective_idle > 0:
            var idle_deadline = self.idle_timer + effective_idle * 1000
            if earliest:
                if idle_deadline < earliest.value():
                    earliest = idle_deadline
            else:
                earliest = idle_deadline

        # Close timer.
        if self.close_timer > 0:
            if earliest:
                if self.close_timer < earliest.value():
                    earliest = self.close_timer
            else:
                earliest = self.close_timer

        # Drain timer.
        if self.drain_timer > 0:
            if earliest:
                if self.drain_timer < earliest.value():
                    earliest = self.drain_timer
            else:
                earliest = self.drain_timer

        return earliest^

    def _check_timers(mut self, now: UInt64):
        """Check and handle expired timers."""
        # Drain timer.
        if self.drain_timer > 0 and now >= self.drain_timer:
            self.state = self.state | CONN_CLOSED
            self.drain_timer = UInt64(0)
            return

        # Close timer.
        if self.close_timer > 0 and now >= self.close_timer:
            self.state = self.state | CONN_CLOSED
            self.close_timer = UInt64(0)
            return

        # Idle timeout — use effective min(local, peer).
        var local_idle = self.local_params.max_idle_timeout
        var peer_idle = UInt64(0)
        if self.peer_params:
            peer_idle = self.peer_params.value().max_idle_timeout
        var effective_idle = UInt64(0)
        if local_idle == 0 and peer_idle == 0:
            effective_idle = UInt64(0)
        elif local_idle == 0:
            effective_idle = peer_idle
        elif peer_idle == 0:
            effective_idle = local_idle
        else:
            effective_idle = local_idle
            if peer_idle < effective_idle:
                effective_idle = peer_idle
        if effective_idle > 0:
            var idle_deadline = self.idle_timer + effective_idle * 1000
            if now >= idle_deadline:
                self.state = self.state | CONN_CLOSED
                self.events.append(
                    QuicEvent.connection_closed(UInt64(0), String("idle timeout"))
                )

    # ── Public API ───────────────────────────────────────────────────

    def poll(mut self) -> Optional[QuicEvent]:
        """Return the next pending event, or None."""
        if len(self.events) > 0:
            # Pop the first event.
            var ev = self.events[0]
            var new_events = List[QuicEvent]()
            for i in range(1, len(self.events)):
                new_events.append(self.events[i]^)
            self.events = new_events^
            return ev^
        return None

    def close(mut self, error_code: UInt64, reason: String, now: UInt64):
        """Initiate a graceful connection close."""
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        self.state = self.state | CONN_CLOSING
        # Set close timer: 3 * PTO.
        var max_ack_delay_us = self.local_params.max_ack_delay * 1000
        var pto = self.recovery.pto_timeout(max_ack_delay_us)
        self.close_timer = now + 3 * pto
        var reason_bytes = List[UInt8]()
        var reason_str_bytes = reason.as_bytes()
        for i in range(len(reason_str_bytes)):
            reason_bytes.append(reason_str_bytes[i])
        var cc = ConnectionCloseFrame()
        cc.is_transport = True
        cc.error_code = error_code
        cc.frame_type = UInt64(0)
        cc.reason = reason_bytes^
        self.pending_close = cc^

    def is_established(self) -> Bool:
        """True if the handshake is complete and the connection is usable."""
        return (self.state & CONN_ESTABLISHED) != 0

    def is_closed(self) -> Bool:
        """True if the connection has fully terminated."""
        return (self.state & CONN_CLOSED) != 0

    def is_draining(self) -> Bool:
        """True if the connection is in the draining state."""
        return (self.state & CONN_DRAINING) != 0

    # ── Internal helpers ─────────────────────────────────────────────

    def _addr_validated(self) -> Bool:
        """True if the peer address has been validated."""
        return (self.state & CONN_ADDR_VALIDATED) != 0

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self.lib_addr)
        )


# ── Module-level helpers ─────────────────────────────────────────────


def _get_lib(
    lib_addr: UInt64,
) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
    return UnsafePointer[RustlsLibrary, MutAnyOrigin](
        unsafe_from_address=Int(lib_addr)
    )


def _generate_random_cid() raises -> List[UInt8]:
    """Generate a random 8-byte connection ID via Python os.urandom."""
    var os = Python.import_module("os")
    var rand_bytes = os.urandom(8)
    var cid = List[UInt8](capacity=8)
    for i in range(8):
        cid.append(UInt8(Int(rand_bytes[i])))
    return cid^


def _has_ack_eliciting(frames: List[Frame]) -> Bool:
    """Check if any frame in the list is ack-eliciting."""
    for i in range(len(frames)):
        if frames[i].is_ack_eliciting():
            return True
    return False
