# src/h2/header.mojo
#
# A single HTTP header field (name-value pair).
# Used by HPACK encoder/decoder and H2Connection events.


struct Header(Copyable, Movable):
    """A single HTTP header field."""
    var name: String
    var value: String

    def __init__(out self, name: String, value: String):
        self.name = name
        self.value = value

    def __init__(out self, *, other: Self):
        self.name = other.name
        self.value = other.value

    def __init__(out self, *, deinit take: Self):
        self.name = take.name^
        self.value = take.value^
