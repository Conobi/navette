struct Method(Copyable, Movable):
    var _tag: Int
    var _custom: String

    def __init__(out self):
        self._tag = 0
        self._custom = String("")

    def __init__(out self, *, other: Self):
        self._tag = other._tag
        self._custom = other._custom

    def __init__(out self, *, deinit take: Self):
        self._tag = take._tag
        self._custom = take._custom^
