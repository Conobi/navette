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

    def __init__(out self, *, copy: Self):
        self.name = copy.name
        self.value = copy.value

    def __init__(out self, *, deinit move: Self):
        self.name = move.name^
        self.value = move.value^
