# conformance/oracle/http1/types.mojo
#
# Data types for the HTTP/1.1 request parser.

from navette.h2.header import Header


struct ParserStrictness(Copyable, Movable):
    """Per-rule strictness flags. False = strict (default), True = relax."""
    var allow_bare_lf: Bool
    var allow_bare_cr_in_value: Bool
    var allow_http_09: Bool
    var allow_nonstandard_version: Bool
    var allow_multiple_spaces: Bool
    var allow_obs_fold: Bool
    var allow_space_before_colon: Bool
    var allow_header_value_ctl: Bool
    var allow_target_ctl: Bool
    var ignore_invalid_header_names: Bool
    var allow_non_chunked_te: Bool
    var allow_chunk_extensions: Bool
    var allow_cl_leading_zeros: Bool
    var allow_duplicate_cl: Bool
    var allow_missing_host_11: Bool
    var allow_duplicate_host: Bool
    # Response-specific flags (HC-2a)
    var allow_multiple_spaces_in_status_line: Bool
    var allow_space_before_first_header: Bool
    var allow_missing_crlf_after_chunk: Bool
    var allow_missing_reason_sp: Bool
    var allow_response_cl_te: Bool
    # Connection lifecycle flags (HC-2b)
    var allow_data_after_close: Bool
    var allow_lenient_keep_alive: Bool
    var allow_prefix_crlf: Bool

    def __init__(
        out self,
        allow_bare_lf: Bool = False,
        allow_bare_cr_in_value: Bool = False,
        allow_http_09: Bool = False,
        allow_nonstandard_version: Bool = False,
        allow_multiple_spaces: Bool = False,
        allow_obs_fold: Bool = False,
        allow_space_before_colon: Bool = False,
        allow_header_value_ctl: Bool = False,
        allow_target_ctl: Bool = False,
        ignore_invalid_header_names: Bool = False,
        allow_non_chunked_te: Bool = False,
        allow_chunk_extensions: Bool = False,
        allow_cl_leading_zeros: Bool = False,
        allow_duplicate_cl: Bool = False,
        allow_missing_host_11: Bool = False,
        allow_duplicate_host: Bool = False,
        allow_multiple_spaces_in_status_line: Bool = False,
        allow_space_before_first_header: Bool = False,
        allow_missing_crlf_after_chunk: Bool = False,
        allow_missing_reason_sp: Bool = False,
        allow_response_cl_te: Bool = False,
        allow_data_after_close: Bool = False,
        allow_lenient_keep_alive: Bool = False,
        allow_prefix_crlf: Bool = False,
    ):
        self.allow_bare_lf = allow_bare_lf
        self.allow_bare_cr_in_value = allow_bare_cr_in_value
        self.allow_http_09 = allow_http_09
        self.allow_nonstandard_version = allow_nonstandard_version
        self.allow_multiple_spaces = allow_multiple_spaces
        self.allow_obs_fold = allow_obs_fold
        self.allow_space_before_colon = allow_space_before_colon
        self.allow_header_value_ctl = allow_header_value_ctl
        self.allow_target_ctl = allow_target_ctl
        self.ignore_invalid_header_names = ignore_invalid_header_names
        self.allow_non_chunked_te = allow_non_chunked_te
        self.allow_chunk_extensions = allow_chunk_extensions
        self.allow_cl_leading_zeros = allow_cl_leading_zeros
        self.allow_duplicate_cl = allow_duplicate_cl
        self.allow_missing_host_11 = allow_missing_host_11
        self.allow_duplicate_host = allow_duplicate_host
        self.allow_multiple_spaces_in_status_line = allow_multiple_spaces_in_status_line
        self.allow_space_before_first_header = allow_space_before_first_header
        self.allow_missing_crlf_after_chunk = allow_missing_crlf_after_chunk
        self.allow_missing_reason_sp = allow_missing_reason_sp
        self.allow_response_cl_te = allow_response_cl_te
        self.allow_data_after_close = allow_data_after_close
        self.allow_lenient_keep_alive = allow_lenient_keep_alive
        self.allow_prefix_crlf = allow_prefix_crlf

    def __init__(out self, *, copy: Self):
        self.allow_bare_lf = copy.allow_bare_lf
        self.allow_bare_cr_in_value = copy.allow_bare_cr_in_value
        self.allow_http_09 = copy.allow_http_09
        self.allow_nonstandard_version = copy.allow_nonstandard_version
        self.allow_multiple_spaces = copy.allow_multiple_spaces
        self.allow_obs_fold = copy.allow_obs_fold
        self.allow_space_before_colon = copy.allow_space_before_colon
        self.allow_header_value_ctl = copy.allow_header_value_ctl
        self.allow_target_ctl = copy.allow_target_ctl
        self.ignore_invalid_header_names = copy.ignore_invalid_header_names
        self.allow_non_chunked_te = copy.allow_non_chunked_te
        self.allow_chunk_extensions = copy.allow_chunk_extensions
        self.allow_cl_leading_zeros = copy.allow_cl_leading_zeros
        self.allow_duplicate_cl = copy.allow_duplicate_cl
        self.allow_missing_host_11 = copy.allow_missing_host_11
        self.allow_duplicate_host = copy.allow_duplicate_host
        self.allow_multiple_spaces_in_status_line = copy.allow_multiple_spaces_in_status_line
        self.allow_space_before_first_header = copy.allow_space_before_first_header
        self.allow_missing_crlf_after_chunk = copy.allow_missing_crlf_after_chunk
        self.allow_missing_reason_sp = copy.allow_missing_reason_sp
        self.allow_response_cl_te = copy.allow_response_cl_te
        self.allow_data_after_close = copy.allow_data_after_close
        self.allow_lenient_keep_alive = copy.allow_lenient_keep_alive
        self.allow_prefix_crlf = copy.allow_prefix_crlf

    def __init__(out self, *, deinit move: Self):
        self.allow_bare_lf = move.allow_bare_lf
        self.allow_bare_cr_in_value = move.allow_bare_cr_in_value
        self.allow_http_09 = move.allow_http_09
        self.allow_nonstandard_version = move.allow_nonstandard_version
        self.allow_multiple_spaces = move.allow_multiple_spaces
        self.allow_obs_fold = move.allow_obs_fold
        self.allow_space_before_colon = move.allow_space_before_colon
        self.allow_header_value_ctl = move.allow_header_value_ctl
        self.allow_target_ctl = move.allow_target_ctl
        self.ignore_invalid_header_names = move.ignore_invalid_header_names
        self.allow_non_chunked_te = move.allow_non_chunked_te
        self.allow_chunk_extensions = move.allow_chunk_extensions
        self.allow_cl_leading_zeros = move.allow_cl_leading_zeros
        self.allow_duplicate_cl = move.allow_duplicate_cl
        self.allow_missing_host_11 = move.allow_missing_host_11
        self.allow_duplicate_host = move.allow_duplicate_host
        self.allow_multiple_spaces_in_status_line = move.allow_multiple_spaces_in_status_line
        self.allow_space_before_first_header = move.allow_space_before_first_header
        self.allow_missing_crlf_after_chunk = move.allow_missing_crlf_after_chunk
        self.allow_missing_reason_sp = move.allow_missing_reason_sp
        self.allow_response_cl_te = move.allow_response_cl_te
        self.allow_data_after_close = move.allow_data_after_close
        self.allow_lenient_keep_alive = move.allow_lenient_keep_alive
        self.allow_prefix_crlf = move.allow_prefix_crlf


def strict_mode() -> ParserStrictness:
    """All flags False -- maximum RFC compliance."""
    return ParserStrictness()


def lenient_mode() -> ParserStrictness:
    """Relaxes common legacy compatibility issues, keeps security checks."""
    return ParserStrictness(
        allow_bare_lf=True,
        allow_obs_fold=True,
        allow_space_before_colon=True,
        allow_header_value_ctl=True,
        allow_chunk_extensions=True,
        allow_cl_leading_zeros=True,
        allow_duplicate_cl=True,
        allow_duplicate_host=True,
        allow_missing_reason_sp=True,
        allow_response_cl_te=True,
        allow_lenient_keep_alive=True,
        allow_prefix_crlf=True,
    )


def permissive_mode() -> ParserStrictness:
    """Accepts nearly everything except security invariants. For debugging/WAF."""
    return ParserStrictness(
        allow_bare_lf=True,
        allow_bare_cr_in_value=True,
        allow_http_09=True,
        allow_nonstandard_version=True,
        allow_multiple_spaces=True,
        allow_obs_fold=True,
        allow_space_before_colon=True,
        allow_header_value_ctl=True,
        allow_target_ctl=True,
        ignore_invalid_header_names=True,
        allow_non_chunked_te=True,
        allow_chunk_extensions=True,
        allow_cl_leading_zeros=True,
        allow_duplicate_cl=True,
        allow_missing_host_11=True,
        allow_duplicate_host=True,
        allow_multiple_spaces_in_status_line=True,
        allow_space_before_first_header=True,
        allow_missing_crlf_after_chunk=True,
        allow_missing_reason_sp=True,
        allow_response_cl_te=True,
        allow_data_after_close=True,
        allow_lenient_keep_alive=True,
        allow_prefix_crlf=True,
    )


struct ParseConfig:
    """Controls parser behavior — limits and strictness."""
    var strictness: ParserStrictness
    var max_request_line: Int
    var max_header_count: Int
    var max_header_size: Int
    var max_headers_total: Int
    var max_chunk_size: Int
    var max_body_size: Int

    def __init__(
        out self,
        strictness: ParserStrictness = ParserStrictness(),
        max_request_line: Int = 8192,
        max_header_count: Int = 100,
        max_header_size: Int = 8192,
        max_headers_total: Int = 65536,
        max_chunk_size: Int = 1048576,
        max_body_size: Int = 10485760,
    ):
        self.strictness = strictness.copy()
        self.max_request_line = max_request_line
        self.max_header_count = max_header_count
        self.max_header_size = max_header_size
        self.max_headers_total = max_headers_total
        self.max_chunk_size = max_chunk_size
        self.max_body_size = max_body_size


struct ParsedRequest(Copyable, Movable):
    """Result of parsing an HTTP/1.1 request message."""
    var method: String
    var target: String
    var version: String
    var headers: List[Header]
    var trailers: List[Header]
    var body: List[UInt8]
    var error: String
    var bytes_consumed: Int

    def __init__(out self):
        """Create an empty ParsedRequest (to be filled by the parser)."""
        self.method = String("")
        self.target = String("")
        self.version = String("")
        self.headers = List[Header]()
        self.trailers = List[Header]()
        self.body = List[UInt8]()
        self.error = String("")
        self.bytes_consumed = 0

    def __init__(out self, *, copy: Self):
        self.method = copy.method
        self.target = copy.target
        self.version = copy.version
        self.headers = copy.headers.copy()
        self.trailers = copy.trailers.copy()
        self.body = copy.body.copy()
        self.error = copy.error
        self.bytes_consumed = copy.bytes_consumed

    def __init__(out self, *, deinit move: Self):
        self.method = move.method^
        self.target = move.target^
        self.version = move.version^
        self.headers = move.headers^
        self.trailers = move.trailers^
        self.body = move.body^
        self.error = move.error^
        self.bytes_consumed = move.bytes_consumed

    def ok(self) -> Bool:
        """Returns True if parsing succeeded (no error)."""
        return not self.error


struct ParsedResponse(Copyable, Movable):
    """Result of parsing an HTTP/1.1 response message."""
    var status_code: Int
    var reason: String
    var version: String
    var headers: List[Header]
    var trailers: List[Header]
    var body: List[UInt8]
    var error: String
    var body_terminated_by_close: Bool
    var upgrade: Bool
    var bytes_consumed: Int

    def __init__(out self):
        self.status_code = 0
        self.reason = String("")
        self.version = String("")
        self.headers = List[Header]()
        self.trailers = List[Header]()
        self.body = List[UInt8]()
        self.error = String("")
        self.body_terminated_by_close = False
        self.upgrade = False
        self.bytes_consumed = 0

    def __init__(out self, *, copy: Self):
        self.status_code = copy.status_code
        self.reason = copy.reason
        self.version = copy.version
        self.headers = copy.headers.copy()
        self.trailers = copy.trailers.copy()
        self.body = copy.body.copy()
        self.error = copy.error
        self.body_terminated_by_close = copy.body_terminated_by_close
        self.upgrade = copy.upgrade
        self.bytes_consumed = copy.bytes_consumed

    def __init__(out self, *, deinit move: Self):
        self.status_code = move.status_code
        self.reason = move.reason^
        self.version = move.version^
        self.headers = move.headers^
        self.trailers = move.trailers^
        self.body = move.body^
        self.error = move.error^
        self.body_terminated_by_close = move.body_terminated_by_close
        self.upgrade = move.upgrade
        self.bytes_consumed = move.bytes_consumed

    def ok(self) -> Bool:
        return not self.error


struct ChunkedResult(Movable):
    """Result of decoding a chunked transfer-encoded body."""
    var body: List[UInt8]
    var trailers: List[Header]
    var error: String
    var bytes_consumed: Int

    def __init__(out self):
        self.body = List[UInt8]()
        self.trailers = List[Header]()
        self.error = String("")
        self.bytes_consumed = 0

    def __init__(out self, *, deinit move: Self):
        self.body = move.body^
        self.trailers = move.trailers^
        self.error = move.error^
        self.bytes_consumed = move.bytes_consumed

    def ok(self) -> Bool:
        return not self.error


struct ConnectionState(Copyable, Movable):
    """Connection-level state for multi-message parsing."""
    var phase: Int                  # IDLE=0, MUST_CLOSE=1, CLOSED=2, UPGRADED=3, ERROR=4
    var keep_alive: Bool
    var messages_parsed: Int
    var informational_count: Int
    var version: String

    def __init__(out self):
        self.phase = 0
        self.keep_alive = True
        self.messages_parsed = 0
        self.informational_count = 0
        self.version = String("")

    def __init__(out self, *, copy: Self):
        self.phase = copy.phase
        self.keep_alive = copy.keep_alive
        self.messages_parsed = copy.messages_parsed
        self.informational_count = copy.informational_count
        self.version = copy.version

    def __init__(out self, *, deinit move: Self):
        self.phase = move.phase
        self.keep_alive = move.keep_alive
        self.messages_parsed = move.messages_parsed
        self.informational_count = move.informational_count
        self.version = move.version^

    def copy(self) -> Self:
        return Self(copy=self)


struct ConnectionResult(Movable):
    """Result of parsing multiple messages on a connection."""
    var request_messages: List[ParsedRequest]
    var response_messages: List[ParsedResponse]
    var state: ConnectionState
    var trailing_data: List[UInt8]
    var error: String

    def __init__(out self):
        self.request_messages = List[ParsedRequest]()
        self.response_messages = List[ParsedResponse]()
        self.state = ConnectionState()
        self.trailing_data = List[UInt8]()
        self.error = String("")

    def __init__(out self, *, deinit move: Self):
        self.request_messages = move.request_messages^
        self.response_messages = move.response_messages^
        self.state = move.state^
        self.trailing_data = move.trailing_data^
        self.error = move.error^

    def ok(self) -> Bool:
        return not self.error
