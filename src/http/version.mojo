# src/http/version.mojo
#
# HTTP version enum (version-agnostic, RFC 9110).


struct Version(Copyable, Movable, Stringable):
    """HTTP protocol version.

    Represented as an Int tag:
      0 = HTTP/1.0
      1 = HTTP/1.1
      2 = HTTP/2
      3 = HTTP/3
    """
    var _tag: Int

    # Factory constants (use Version.http_1_1() etc.)
    @staticmethod
    def http_1_0() -> Self:
        return Self(_tag=0)

    @staticmethod
    def http_1_1() -> Self:
        return Self(_tag=1)

    @staticmethod
    def http_2() -> Self:
        return Self(_tag=2)

    @staticmethod
    def http_3() -> Self:
        return Self(_tag=3)

    def __init__(out self, *, _tag: Int):
        self._tag = _tag

    def __init__(out self, *, other: Self):
        self._tag = other._tag

    def __init__(out self, *, deinit take: Self):
        self._tag = take._tag

    def __eq__(self, rhs: Self) -> Bool:
        return self._tag == rhs._tag

    def __ne__(self, rhs: Self) -> Bool:
        return self._tag != rhs._tag

    def is_http_1_0(self) -> Bool:
        return self._tag == 0

    def is_http_1_1(self) -> Bool:
        return self._tag == 1

    def is_http_2(self) -> Bool:
        return self._tag == 2

    def is_http_3(self) -> Bool:
        return self._tag == 3

    def __str__(self) -> String:
        if self._tag == 0:
            return "HTTP/1.0"
        if self._tag == 1:
            return "HTTP/1.1"
        if self._tag == 2:
            return "HTTP/2"
        if self._tag == 3:
            return "HTTP/3"
        return "HTTP/unknown"
