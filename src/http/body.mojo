struct BodyFrame(Copyable, Movable):
    var _tag: Int
    var _data: List[UInt8]
    var _trailers: List[String]  # placeholder

    def __init__(out self):
        self._tag = 0
        self._data = List[UInt8]()
        self._trailers = List[String]()

    def __init__(out self, *, other: Self):
        self._tag = other._tag
        self._data = other._data.copy()
        self._trailers = other._trailers.copy()

    def __init__(out self, *, deinit take: Self):
        self._tag = take._tag
        self._data = take._data^
        self._trailers = take._trailers^
