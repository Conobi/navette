# src/quic/trans_param.mojo
# QUIC transport parameter codec — RFC 9000 Section 18.

from std.collections import Dict, Optional
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from navette.quic.guard_tags import (
    GUARD_TAG_TP_INITIAL_SCID_MISSING,
    GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN,
    GUARD_TAG_TP_PREFERRED_ADDR_FORBIDDEN,
    GUARD_TAG_TP_RETRY_SCID_FORBIDDEN,
    GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN,
)


# ── Transport parameter IDs (RFC 9000 §18.2) ────────────────────────

comptime TP_ORIGINAL_DCID: UInt64 = 0x00
comptime TP_MAX_IDLE_TIMEOUT: UInt64 = 0x01
comptime TP_STATELESS_RESET_TOKEN: UInt64 = 0x02
comptime TP_MAX_UDP_PAYLOAD_SIZE: UInt64 = 0x03
comptime TP_INITIAL_MAX_DATA: UInt64 = 0x04
comptime TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: UInt64 = 0x05
comptime TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: UInt64 = 0x06
comptime TP_INITIAL_MAX_STREAM_DATA_UNI: UInt64 = 0x07
comptime TP_INITIAL_MAX_STREAMS_BIDI: UInt64 = 0x08
comptime TP_INITIAL_MAX_STREAMS_UNI: UInt64 = 0x09
comptime TP_ACK_DELAY_EXPONENT: UInt64 = 0x0A
comptime TP_MAX_ACK_DELAY: UInt64 = 0x0B
comptime TP_DISABLE_ACTIVE_MIGRATION: UInt64 = 0x0C
comptime TP_PREFERRED_ADDRESS: UInt64 = 0x0D
comptime TP_ACTIVE_CONNECTION_ID_LIMIT: UInt64 = 0x0E
comptime TP_INITIAL_SCID: UInt64 = 0x0F
comptime TP_RETRY_SCID: UInt64 = 0x10


# ── PreferredAddress ─────────────────────────────────────────────────

struct PreferredAddress(Copyable, Movable):
    var ipv4_address: List[UInt8]
    var ipv4_port: UInt16
    var ipv6_address: List[UInt8]
    var ipv6_port: UInt16
    var cid: List[UInt8]
    var stateless_reset_token: List[UInt8]

    def __init__(
        out self,
        ipv4_address: List[UInt8],
        ipv4_port: UInt16,
        ipv6_address: List[UInt8],
        ipv6_port: UInt16,
        cid: List[UInt8],
        stateless_reset_token: List[UInt8],
    ):
        self.ipv4_address = ipv4_address.copy()
        self.ipv4_port = ipv4_port
        self.ipv6_address = ipv6_address.copy()
        self.ipv6_port = ipv6_port
        self.cid = cid.copy()
        self.stateless_reset_token = stateless_reset_token.copy()

    def __init__(out self, *, other: Self):
        self.ipv4_address = other.ipv4_address.copy()
        self.ipv4_port = other.ipv4_port
        self.ipv6_address = other.ipv6_address.copy()
        self.ipv6_port = other.ipv6_port
        self.cid = other.cid.copy()
        self.stateless_reset_token = other.stateless_reset_token.copy()

    def __init__(out self, *, deinit take: Self):
        self.ipv4_address = take.ipv4_address^
        self.ipv4_port = take.ipv4_port
        self.ipv6_address = take.ipv6_address^
        self.ipv6_port = take.ipv6_port
        self.cid = take.cid^
        self.stateless_reset_token = take.stateless_reset_token^


# ── TransportParams ──────────────────────────────────────────────────

struct TransportParams(Copyable, Movable):
    var original_dcid: Optional[List[UInt8]]
    var max_idle_timeout: UInt64
    var stateless_reset_token: Optional[List[UInt8]]
    var max_udp_payload_size: UInt64
    var initial_max_data: UInt64
    var initial_max_stream_data_bidi_local: UInt64
    var initial_max_stream_data_bidi_remote: UInt64
    var initial_max_stream_data_uni: UInt64
    var initial_max_streams_bidi: UInt64
    var initial_max_streams_uni: UInt64
    var ack_delay_exponent: UInt64
    var max_ack_delay: UInt64
    var disable_active_migration: Bool
    var preferred_address: Optional[PreferredAddress]
    var active_connection_id_limit: UInt64
    var initial_scid: Optional[List[UInt8]]
    var retry_scid: Optional[List[UInt8]]
    var unknown: Dict[Int, List[UInt8]]

    def __init__(out self):
        self.original_dcid = None
        self.max_idle_timeout = 0
        self.stateless_reset_token = None
        self.max_udp_payload_size = 65527
        self.initial_max_data = 0
        self.initial_max_stream_data_bidi_local = 0
        self.initial_max_stream_data_bidi_remote = 0
        self.initial_max_stream_data_uni = 0
        self.initial_max_streams_bidi = 0
        self.initial_max_streams_uni = 0
        self.ack_delay_exponent = 3
        self.max_ack_delay = 25
        self.disable_active_migration = False
        self.preferred_address = None
        self.active_connection_id_limit = 2
        self.initial_scid = None
        self.retry_scid = None
        self.unknown = Dict[Int, List[UInt8]]()

    def __init__(out self, *, other: Self):
        self.original_dcid = other.original_dcid.copy()
        self.max_idle_timeout = other.max_idle_timeout
        self.stateless_reset_token = other.stateless_reset_token.copy()
        self.max_udp_payload_size = other.max_udp_payload_size
        self.initial_max_data = other.initial_max_data
        self.initial_max_stream_data_bidi_local = other.initial_max_stream_data_bidi_local
        self.initial_max_stream_data_bidi_remote = other.initial_max_stream_data_bidi_remote
        self.initial_max_stream_data_uni = other.initial_max_stream_data_uni
        self.initial_max_streams_bidi = other.initial_max_streams_bidi
        self.initial_max_streams_uni = other.initial_max_streams_uni
        self.ack_delay_exponent = other.ack_delay_exponent
        self.max_ack_delay = other.max_ack_delay
        self.disable_active_migration = other.disable_active_migration
        self.preferred_address = other.preferred_address.copy()
        self.active_connection_id_limit = other.active_connection_id_limit
        self.initial_scid = other.initial_scid.copy()
        self.retry_scid = other.retry_scid.copy()
        self.unknown = other.unknown.copy()

    def __init__(out self, *, deinit take: Self):
        self.original_dcid = take.original_dcid^
        self.max_idle_timeout = take.max_idle_timeout
        self.stateless_reset_token = take.stateless_reset_token^
        self.max_udp_payload_size = take.max_udp_payload_size
        self.initial_max_data = take.initial_max_data
        self.initial_max_stream_data_bidi_local = take.initial_max_stream_data_bidi_local
        self.initial_max_stream_data_bidi_remote = take.initial_max_stream_data_bidi_remote
        self.initial_max_stream_data_uni = take.initial_max_stream_data_uni
        self.initial_max_streams_bidi = take.initial_max_streams_bidi
        self.initial_max_streams_uni = take.initial_max_streams_uni
        self.ack_delay_exponent = take.ack_delay_exponent
        self.max_ack_delay = take.max_ack_delay
        self.disable_active_migration = take.disable_active_migration
        self.preferred_address = take.preferred_address^
        self.active_connection_id_limit = take.active_connection_id_limit
        self.initial_scid = take.initial_scid^
        self.retry_scid = take.retry_scid^
        self.unknown = take.unknown^


# ── Defaults ─────────────────────────────────────────────────────────

def default_transport_params() -> TransportParams:
    return TransportParams()


# ── Helpers ──────────────────────────────────────────────────────────

def _decode_varint_from_bytes(value_bytes: List[UInt8]) raises -> UInt64:
    """Decode a varint from a raw byte list."""
    var reader = ByteReader(Span(value_bytes))
    return varint_decode(reader)


def _encode_varint_param(mut writer: ByteWriter, param_id: UInt64, value: UInt64) raises:
    """Write a varint-valued transport parameter."""
    varint_encode(writer, param_id)
    var vlen = varint_len(value)
    varint_encode(writer, UInt64(vlen))
    varint_encode(writer, value)


def _encode_bytes_param(mut writer: ByteWriter, param_id: UInt64, data: Span[UInt8, _]) raises:
    """Write a bytes-valued transport parameter."""
    varint_encode(writer, param_id)
    varint_encode(writer, UInt64(len(data)))
    writer.write_bytes(data)


def _parse_preferred_address[origin: Origin](
    mut reader: ByteReader[origin],
) raises -> PreferredAddress:
    """Parse the preferred_address sub-structure (RFC 9000 §18.2)."""
    var ipv4_address = reader.read_bytes(4)
    var ipv4_port = reader.read_u16_be()
    var ipv6_address = reader.read_bytes(16)
    var ipv6_port = reader.read_u16_be()
    var cid_len = Int(reader.read_u8())
    if cid_len < 1 or cid_len > 20:
        raise "preferred_address: CID length must be 1..20, got " + String(cid_len)
    var cid = reader.read_bytes(cid_len)
    var srt = reader.read_bytes(16)
    return PreferredAddress(
        ipv4_address=ipv4_address^,
        ipv4_port=ipv4_port,
        ipv6_address=ipv6_address^,
        ipv6_port=ipv6_port,
        cid=cid^,
        stateless_reset_token=srt^,
    )


def _serialize_preferred_address(pa: PreferredAddress, mut writer: ByteWriter) raises:
    """Serialize a PreferredAddress into a ByteWriter (value bytes only)."""
    writer.write_bytes(Span(pa.ipv4_address))
    writer.write_u16_be(pa.ipv4_port)
    writer.write_bytes(Span(pa.ipv6_address))
    writer.write_u16_be(pa.ipv6_port)
    writer.write_u8(UInt8(len(pa.cid)))
    writer.write_bytes(Span(pa.cid))
    writer.write_bytes(Span(pa.stateless_reset_token))


# ── Parse ────────────────────────────────────────────────────────────

def parse_transport_params[origin: Origin](
    buf: Span[UInt8, origin],
) raises -> TransportParams:
    """Parse a sequence of transport parameters from the wire format.

    Wire format: repeated (param_id varint, param_length varint, param_value bytes).
    RFC 9000 Section 18.
    """
    var params = TransportParams()
    var reader = ByteReader(buf)
    var seen = Dict[Int, Bool]()

    while reader.remaining() > 0:
        var param_id = varint_decode(reader)
        var param_len = varint_decode(reader)
        var id_int = Int(param_id)

        # Duplicate detection.
        if id_int in seen:
            raise "duplicate transport parameter: " + String(id_int)
        seen[id_int] = True

        # Read the value bytes.
        var value_bytes = reader.read_bytes(Int(param_len))

        if param_id == TP_ORIGINAL_DCID:
            params.original_dcid = value_bytes^

        elif param_id == TP_MAX_IDLE_TIMEOUT:
            params.max_idle_timeout = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_STATELESS_RESET_TOKEN:
            if len(value_bytes) != 16:
                raise "stateless_reset_token must be 16 bytes"
            params.stateless_reset_token = value_bytes^

        elif param_id == TP_MAX_UDP_PAYLOAD_SIZE:
            params.max_udp_payload_size = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_MAX_DATA:
            params.initial_max_data = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            params.initial_max_stream_data_bidi_local = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            params.initial_max_stream_data_bidi_remote = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_MAX_STREAM_DATA_UNI:
            params.initial_max_stream_data_uni = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_MAX_STREAMS_BIDI:
            params.initial_max_streams_bidi = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_MAX_STREAMS_UNI:
            params.initial_max_streams_uni = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_ACK_DELAY_EXPONENT:
            params.ack_delay_exponent = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_MAX_ACK_DELAY:
            params.max_ack_delay = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_DISABLE_ACTIVE_MIGRATION:
            if len(value_bytes) != 0:
                raise "disable_active_migration must have zero-length value"
            params.disable_active_migration = True

        elif param_id == TP_PREFERRED_ADDRESS:
            var pa_reader = ByteReader(Span(value_bytes))
            params.preferred_address = _parse_preferred_address(pa_reader)

        elif param_id == TP_ACTIVE_CONNECTION_ID_LIMIT:
            params.active_connection_id_limit = _decode_varint_from_bytes(value_bytes)

        elif param_id == TP_INITIAL_SCID:
            params.initial_scid = value_bytes^

        elif param_id == TP_RETRY_SCID:
            params.retry_scid = value_bytes^

        else:
            # Unknown parameter — store for forward compatibility.
            params.unknown[id_int] = value_bytes^

    # Validation (RFC 9000 §18.2).
    if params.max_udp_payload_size < 1200:
        raise "max_udp_payload_size must be >= 1200"
    if params.ack_delay_exponent > 20:
        raise "ack_delay_exponent must be <= 20"
    if params.max_ack_delay >= 16384:
        raise "max_ack_delay must be < 16384"
    if params.active_connection_id_limit < 2:
        raise "active_connection_id_limit must be >= 2"

    return params^


# ── Serialize ────────────────────────────────────────────────────────

def serialize_transport_params(
    params: TransportParams, mut writer: ByteWriter,
) raises:
    """Serialize transport parameters into wire format.

    Omits parameters at their default value. Omits None Optional parameters.
    """
    # CID params (raw bytes).
    if params.original_dcid:
        var cid = params.original_dcid.value().copy()
        _encode_bytes_param(writer, TP_ORIGINAL_DCID, Span(cid))

    if params.initial_scid:
        var cid = params.initial_scid.value().copy()
        _encode_bytes_param(writer, TP_INITIAL_SCID, Span(cid))

    if params.retry_scid:
        var cid = params.retry_scid.value().copy()
        _encode_bytes_param(writer, TP_RETRY_SCID, Span(cid))

    # Stateless reset token (16 bytes).
    if params.stateless_reset_token:
        var tok = params.stateless_reset_token.value().copy()
        _encode_bytes_param(writer, TP_STATELESS_RESET_TOKEN, Span(tok))

    # Integer params — only emit when non-default.
    if params.max_idle_timeout != 0:
        _encode_varint_param(writer, TP_MAX_IDLE_TIMEOUT, params.max_idle_timeout)

    if params.max_udp_payload_size != 65527:
        _encode_varint_param(writer, TP_MAX_UDP_PAYLOAD_SIZE, params.max_udp_payload_size)

    if params.initial_max_data != 0:
        _encode_varint_param(writer, TP_INITIAL_MAX_DATA, params.initial_max_data)

    if params.initial_max_stream_data_bidi_local != 0:
        _encode_varint_param(
            writer,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            params.initial_max_stream_data_bidi_local,
        )

    if params.initial_max_stream_data_bidi_remote != 0:
        _encode_varint_param(
            writer,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            params.initial_max_stream_data_bidi_remote,
        )

    if params.initial_max_stream_data_uni != 0:
        _encode_varint_param(
            writer,
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            params.initial_max_stream_data_uni,
        )

    if params.initial_max_streams_bidi != 0:
        _encode_varint_param(writer, TP_INITIAL_MAX_STREAMS_BIDI, params.initial_max_streams_bidi)

    if params.initial_max_streams_uni != 0:
        _encode_varint_param(writer, TP_INITIAL_MAX_STREAMS_UNI, params.initial_max_streams_uni)

    if params.ack_delay_exponent != 3:
        _encode_varint_param(writer, TP_ACK_DELAY_EXPONENT, params.ack_delay_exponent)

    if params.max_ack_delay != 25:
        _encode_varint_param(writer, TP_MAX_ACK_DELAY, params.max_ack_delay)

    if params.active_connection_id_limit != 2:
        _encode_varint_param(
            writer, TP_ACTIVE_CONNECTION_ID_LIMIT, params.active_connection_id_limit,
        )

    # Zero-length boolean param.
    if params.disable_active_migration:
        varint_encode(writer, TP_DISABLE_ACTIVE_MIGRATION)
        varint_encode(writer, UInt64(0))

    # Preferred address.
    if params.preferred_address:
        var pa = params.preferred_address.value().copy()
        var pa_writer = ByteWriter()
        _serialize_preferred_address(pa, pa_writer)
        var pa_bytes = pa_writer.finish()
        varint_encode(writer, TP_PREFERRED_ADDRESS)
        varint_encode(writer, UInt64(len(pa_bytes)))
        writer.write_bytes(Span(pa_bytes))

    # Unknown parameters (forward compatibility).
    for entry in params.unknown.items():
        varint_encode(writer, UInt64(entry.key))
        varint_encode(writer, UInt64(len(entry.value)))
        writer.write_bytes(Span(entry.value))


# ── Server-side client TP validator ──────────────────────────────────────────

def validate_client_transport_params(params: TransportParams) raises:
    """RFC 9000 §7.3 + §18.2 — server-side validation of client-supplied transport params.

    Invoked AFTER parse_transport_params succeeds, on the server side, to
    assert presence of the required initial_source_connection_id (F02) and
    absence of server-only fields (F03-F06):
      - original_destination_connection_id  (F03)
      - preferred_address                   (F04)
      - retry_source_connection_id          (F05)
      - stateless_reset_token               (F06)

    Range checks for max_udp_payload_size, ack_delay_exponent, and
    max_ack_delay (F07/F08/F09) are intentionally left in the parse path
    so legacy callers do not regress; they will receive their GUARD_TAG
    annotations in a sibling task.

    Exception strings carry the matching GUARD_TAG_TP_* bracketed token so
    the Phase β.6 wiring can route them through close_transport while
    preserving the reason-substring assertion in conformance scenarios.

    Args:
        params: The decoded TransportParams from a peer (typically the
            client) after parse_transport_params returned successfully.

    Raises:
        String exception containing the matching GUARD_TAG_TP_* token on
        the first detected violation. Subsequent fields are not checked.
    """
    if not Bool(params.initial_scid):
        raise String(GUARD_TAG_TP_INITIAL_SCID_MISSING) + ": initial_source_connection_id missing from client TP"
    if Bool(params.original_dcid):
        raise String(GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN) + ": original_destination_connection_id is server-only"
    if Bool(params.preferred_address):
        raise String(GUARD_TAG_TP_PREFERRED_ADDR_FORBIDDEN) + ": preferred_address is server-only"
    if Bool(params.retry_scid):
        raise String(GUARD_TAG_TP_RETRY_SCID_FORBIDDEN) + ": retry_source_connection_id is server-only"
    if Bool(params.stateless_reset_token):
        raise String(GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN) + ": stateless_reset_token is server-only"
