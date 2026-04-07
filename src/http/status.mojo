struct StatusCode(Copyable, Movable):
    var _code: UInt16

    def __init__(out self):
        self._code = UInt16(0)

    def __init__(out self, *, other: Self):
        self._code = other._code

    def __init__(out self, *, deinit take: Self):
        self._code = take._code
