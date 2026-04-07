struct Headers(Copyable, Movable):
    var _names: List[String]
    var _values: List[String]

    def __init__(out self):
        self._names = List[String]()
        self._values = List[String]()

    def __init__(out self, *, other: Self):
        self._names = other._names.copy()
        self._values = other._values.copy()

    def __init__(out self, *, deinit take: Self):
        self._names = take._names^
        self._values = take._values^
