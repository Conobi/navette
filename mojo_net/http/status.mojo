# src/http/status.mojo
#
# HTTP response status code (RFC 9110 Section 15).


struct StatusCode(Copyable, Movable, Writable):
    """HTTP response status code. Wraps a UInt16 with category helpers."""

    var _code: UInt16

    # --- Constructors ---

    def __init__(out self, code: Int):
        """Construct a StatusCode from a numeric code."""
        self._code = UInt16(code)

    def __init__(out self, *, other: Self):
        """Copy constructor."""
        self._code = other._code

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._code = take._code

    # --- Accessors ---

    def code(self) -> UInt16:
        """Return the raw numeric status code."""
        return self._code

    # --- Category helpers ---

    def is_informational(self) -> Bool:
        """Return True if this is a 1xx informational status code."""
        return self._code >= 100 and self._code < 200

    def is_success(self) -> Bool:
        """Return True if this is a 2xx success status code."""
        return self._code >= 200 and self._code < 300

    def is_redirect(self) -> Bool:
        """Return True if this is a 3xx redirect status code."""
        return self._code >= 300 and self._code < 400

    def is_client_error(self) -> Bool:
        """Return True if this is a 4xx client error status code."""
        return self._code >= 400 and self._code < 500

    def is_server_error(self) -> Bool:
        """Return True if this is a 5xx server error status code."""
        return self._code >= 500 and self._code < 600

    # --- Named constructors for common codes ---

    @staticmethod
    def ok() -> Self:
        """Return 200 OK."""
        return Self(200)

    @staticmethod
    def not_found() -> Self:
        """Return 404 Not Found."""
        return Self(404)

    @staticmethod
    def bad_request() -> Self:
        """Return 400 Bad Request."""
        return Self(400)

    @staticmethod
    def internal_server_error() -> Self:
        """Return 500 Internal Server Error."""
        return Self(500)

    @staticmethod
    def bad_gateway() -> Self:
        """Return 502 Bad Gateway."""
        return Self(502)

    @staticmethod
    def gateway_timeout() -> Self:
        """Return 504 Gateway Timeout."""
        return Self(504)

    # --- Equality ---

    def __eq__(self, rhs: Self) -> Bool:
        """Return True if both codes are numerically equal."""
        return self._code == rhs._code

    def __ne__(self, rhs: Self) -> Bool:
        """Return True if the codes differ."""
        return self._code != rhs._code

    # --- String ---

    def write_to[W: Writer](self, mut writer: W):
        """Write the numeric code to the writer."""
        writer.write(String(Int(self._code)))
