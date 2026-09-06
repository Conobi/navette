# conformance/lib/http1/connection.mojo
#
# HTTP/1.1 connection lifecycle state machine (Pattern D: functional).

from .types import ParseConfig, Header, ParsedRequest, ParsedResponse, ConnectionState, ConnectionResult
from .parser import parse_request
from .response import parse_response
from ._helpers import _iequals, _icontains


# Phase constants
comptime PHASE_IDLE = 0
comptime PHASE_MUST_CLOSE = 1
comptime PHASE_CLOSED = 2
comptime PHASE_UPGRADED = 3
comptime PHASE_ERROR = 4


def _check_connection_header(headers: List[Header], default_keep_alive: Bool) -> Bool:
    """Determine keep-alive from Connection header. Returns True to persist, False to close."""
    for i in range(len(headers)):
        if _iequals(headers[i].name, "connection"):
            if _icontains(headers[i].value, "close"):
                return False
            if _icontains(headers[i].value, "keep-alive"):
                return True
    return default_keep_alive


def _skip_prefix_crlf(wire: List[UInt8], pos: Int, allow_bare_lf: Bool) -> Int:
    """Skip leading CRLF or bare LF bytes. Returns new position."""
    var p = pos
    var wire_len = len(wire)
    while p < wire_len:
        if p + 1 < wire_len and wire[p] == UInt8(0x0D) and wire[p + 1] == UInt8(0x0A):
            p += 2
        elif allow_bare_lf and wire[p] == UInt8(0x0A):
            p += 1
        else:
            break
    return p


def step_request(
    wire: List[UInt8],
    pos: Int,
    state: ConnectionState,
    config: ParseConfig,
) -> Tuple[ConnectionState, ParsedRequest, Int, String]:
    """Parse one request. Returns (new_state, request, new_pos, error)."""
    var new_state = state.copy()

    # Must be IDLE
    if new_state.phase != PHASE_IDLE:
        return (new_state^, ParsedRequest(), pos, String("connection not in IDLE state"))

    # Skip prefix CRLF if allowed
    var start = pos
    if config.strictness.allow_prefix_crlf:
        start = _skip_prefix_crlf(wire, pos, config.strictness.allow_bare_lf)

    # Check if there's anything left after skipping
    if start >= len(wire):
        return (new_state^, ParsedRequest(), pos, String("no data after prefix CRLF skip"))

    # Build slice from start
    var remaining = List[UInt8]()
    for i in range(start, len(wire)):
        remaining.append(wire[i])

    # Parse
    var result = parse_request(remaining, config)
    if not result.ok():
        new_state.phase = PHASE_ERROR
        var err = result.error
        return (new_state^, result^, start, err)

    var new_pos = start + result.bytes_consumed

    # Set version from first message
    if new_state.messages_parsed == 0 and len(new_state.version) == 0:
        new_state.version = result.version
        if result.version == "1.0":
            new_state.keep_alive = False

    # Check Connection header
    new_state.keep_alive = _check_connection_header(result.headers, new_state.keep_alive)

    # Update phase
    if not new_state.keep_alive:
        new_state.phase = PHASE_MUST_CLOSE
    else:
        new_state.phase = PHASE_IDLE

    new_state.messages_parsed += 1
    return (new_state^, result^, new_pos, String(""))


def step_response(
    wire: List[UInt8],
    pos: Int,
    state: ConnectionState,
    request_method: String,
    config: ParseConfig,
) -> Tuple[ConnectionState, ParsedResponse, Int, String]:
    """Parse one response. Returns (new_state, response, new_pos, error)."""
    var new_state = state.copy()

    if new_state.phase != PHASE_IDLE:
        return (new_state^, ParsedResponse(), pos, String("connection not in IDLE state"))

    var start = pos
    if config.strictness.allow_prefix_crlf:
        start = _skip_prefix_crlf(wire, pos, config.strictness.allow_bare_lf)

    if start >= len(wire):
        return (new_state^, ParsedResponse(), pos, String("no data after prefix CRLF skip"))

    var remaining = List[UInt8]()
    for i in range(start, len(wire)):
        remaining.append(wire[i])

    var result = parse_response(remaining, request_method, config)
    if not result.ok():
        new_state.phase = PHASE_ERROR
        var err = result.error
        return (new_state^, result^, start, err)

    var new_pos = start + result.bytes_consumed

    # 1xx informational handling
    if result.status_code >= 100 and result.status_code <= 199:
        if result.status_code == 101:
            new_state.phase = PHASE_UPGRADED
            new_state.keep_alive = False  # UPGRADED means no more HTTP on this connection
            new_state.messages_parsed += 1  # 101 is terminal — counts as a final exchange
        else:
            new_state.phase = PHASE_IDLE  # stay IDLE, wait for final response
        new_state.informational_count += 1
        # DO NOT check Connection header on 1xx (RFC: always ignored)
        return (new_state^, result^, new_pos, String(""))

    # Final response (status >= 200)
    if result.upgrade:
        new_state.phase = PHASE_UPGRADED
        new_state.keep_alive = False  # UPGRADED means no more HTTP on this connection
        new_state.messages_parsed += 1
        return (new_state^, result^, new_pos, String(""))

    # Set version from first final message
    if new_state.messages_parsed == 0 and len(new_state.version) == 0:
        new_state.version = result.version
        if result.version == "1.0":
            new_state.keep_alive = False

    # Check Connection header (only on final responses, NOT 1xx)
    new_state.keep_alive = _check_connection_header(result.headers, new_state.keep_alive)

    if not new_state.keep_alive:
        new_state.phase = PHASE_MUST_CLOSE
    else:
        new_state.phase = PHASE_IDLE

    new_state.messages_parsed += 1
    return (new_state^, result^, new_pos, String(""))


def parse_messages(
    wire: List[UInt8],
    direction: String,
    request_methods: List[String],
    config: ParseConfig,
) -> ConnectionResult:
    """Parse all messages in wire. Returns ConnectionResult."""
    var result = ConnectionResult()
    var state = ConnectionState()
    var pos = 0
    var method_idx = 0
    var wire_len = len(wire)

    while pos < wire_len:
        var old_pos = pos

        # Handle MUST_CLOSE with trailing data
        if state.phase == PHASE_MUST_CLOSE:
            if config.strictness.allow_data_after_close:
                for i in range(pos, wire_len):
                    result.trailing_data.append(wire[i])
                state.phase = PHASE_CLOSED
            else:
                result.error = String("data after Connection: close")
                state.phase = PHASE_ERROR
            break

        # Stop on non-IDLE states; capture trailing data for UPGRADED
        if state.phase == PHASE_UPGRADED:
            for i in range(pos, wire_len):
                result.trailing_data.append(wire[i])
            break
        if state.phase != PHASE_IDLE:
            break

        if direction == "request":
            var step = step_request(wire, pos, state.copy(), config)
            state = step[0].copy()
            var new_pos = step[2]
            var step_error = step[3]
            if len(step_error) > 0:
                result.error = step_error
                break
            result.request_messages.append(step[1].copy())
            pos = new_pos
        elif direction == "response":
            var method = String("GET")
            if method_idx < len(request_methods):
                method = request_methods[method_idx]
            var step = step_response(wire, pos, state.copy(), method, config)
            state = step[0].copy()
            var new_pos = step[2]
            var step_error = step[3]
            if len(step_error) > 0:
                result.error = step_error
                break
            var status_code = step[1].status_code
            result.response_messages.append(step[1].copy())
            pos = new_pos
            # Advance method_idx only for final responses (not 1xx)
            if status_code >= 200:
                method_idx += 1

        # Safety guard: prevent infinite loop
        if pos <= old_pos:
            result.error = String("parser made no progress")
            state.phase = PHASE_ERROR
            break

    result.state = state^
    return result^
