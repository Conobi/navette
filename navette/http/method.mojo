# src/http/method.mojo
#
# HTTP request method (RFC 9110 Section 9, RFC 10008).
# Case-sensitive. 10 standard methods + custom variant.

# Tag values for standard methods
comptime _GET = 0
comptime _POST = 1
comptime _PUT = 2
comptime _DELETE = 3
comptime _HEAD = 4
comptime _OPTIONS = 5
comptime _PATCH = 6
comptime _CONNECT = 7
comptime _TRACE = 8
comptime _QUERY = 9
comptime _CUSTOM = 10


struct Method(Copyable, Movable, Writable):
    """HTTP request method.

    Represented as a tagged struct: Int tag for known methods (0-9),
    tag 10 for custom methods with the string stored in _custom.
    Case-sensitive comparison per RFC 9110.
    """
    var _tag: Int
    var _custom: String

    # --- Private constructor ---

    def __init__(out self, *, _tag: Int, _custom: String = ""):
        self._tag = _tag
        self._custom = _custom

    # --- Copy / Move ---

    def __init__(out self, *, other: Self):
        self._tag = other._tag
        self._custom = other._custom

    def __init__(out self, *, deinit take: Self):
        self._tag = take._tag
        self._custom = take._custom^

    # --- Factory methods ---

    @staticmethod
    def get() -> Self:
        return Self(_tag=_GET)

    @staticmethod
    def post() -> Self:
        return Self(_tag=_POST)

    @staticmethod
    def put() -> Self:
        return Self(_tag=_PUT)

    @staticmethod
    def delete() -> Self:
        return Self(_tag=_DELETE)

    @staticmethod
    def head() -> Self:
        return Self(_tag=_HEAD)

    @staticmethod
    def options() -> Self:
        return Self(_tag=_OPTIONS)

    @staticmethod
    def patch() -> Self:
        return Self(_tag=_PATCH)

    @staticmethod
    def connect() -> Self:
        return Self(_tag=_CONNECT)

    @staticmethod
    def trace() -> Self:
        return Self(_tag=_TRACE)

    @staticmethod
    def query() -> Self:
        return Self(_tag=_QUERY)

    @staticmethod
    def custom(name: String) -> Self:
        """Create a custom method. If the name matches a standard method,
        returns the standard variant for correct equality semantics."""
        if name == "GET":
            return Self(_tag=_GET)
        if name == "POST":
            return Self(_tag=_POST)
        if name == "PUT":
            return Self(_tag=_PUT)
        if name == "DELETE":
            return Self(_tag=_DELETE)
        if name == "HEAD":
            return Self(_tag=_HEAD)
        if name == "OPTIONS":
            return Self(_tag=_OPTIONS)
        if name == "PATCH":
            return Self(_tag=_PATCH)
        if name == "CONNECT":
            return Self(_tag=_CONNECT)
        if name == "TRACE":
            return Self(_tag=_TRACE)
        if name == "QUERY":
            return Self(_tag=_QUERY)
        return Self(_tag=_CUSTOM, _custom=name)

    # --- Predicates ---

    def is_get(self) -> Bool:
        return self._tag == _GET

    def is_post(self) -> Bool:
        return self._tag == _POST

    def is_put(self) -> Bool:
        return self._tag == _PUT

    def is_delete(self) -> Bool:
        return self._tag == _DELETE

    def is_head(self) -> Bool:
        return self._tag == _HEAD

    def is_options(self) -> Bool:
        return self._tag == _OPTIONS

    def is_patch(self) -> Bool:
        return self._tag == _PATCH

    def is_connect(self) -> Bool:
        return self._tag == _CONNECT

    def is_trace(self) -> Bool:
        return self._tag == _TRACE

    def is_query(self) -> Bool:
        return self._tag == _QUERY

    def is_custom(self) -> Bool:
        return self._tag == _CUSTOM

    # --- Equality ---

    def __eq__(self, rhs: Self) -> Bool:
        if self._tag != rhs._tag:
            return False
        if self._tag == _CUSTOM:
            return self._custom == rhs._custom
        return True

    def __ne__(self, rhs: Self) -> Bool:
        return not (self == rhs)

    # --- String ---

    def write_to[W: Writer](self, mut writer: W):
        if self._tag == _GET:
            writer.write("GET")
        elif self._tag == _POST:
            writer.write("POST")
        elif self._tag == _PUT:
            writer.write("PUT")
        elif self._tag == _DELETE:
            writer.write("DELETE")
        elif self._tag == _HEAD:
            writer.write("HEAD")
        elif self._tag == _OPTIONS:
            writer.write("OPTIONS")
        elif self._tag == _PATCH:
            writer.write("PATCH")
        elif self._tag == _CONNECT:
            writer.write("CONNECT")
        elif self._tag == _TRACE:
            writer.write("TRACE")
        elif self._tag == _QUERY:
            writer.write("QUERY")
        else:
            writer.write(self._custom)
