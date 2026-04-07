# src/http/priority.mojo
#
# RFC 9218 Priority header (M2.5b §7.1). Pure parse/serialize — no I/O, no
# integration with the H2/H3 PRIORITY_UPDATE frame (that lands in HC-4/M5).

comptime DEFAULT_URGENCY = 3


struct Priority(Copyable, Movable):
    """RFC 9218 §4 Priority header value."""

    var urgency: Int        # 0..7; default 3
    var incremental: Bool   # default False

    def __init__(out self, *, urgency: Int, incremental: Bool):
        self.urgency = urgency
        self.incremental = incremental

    def __init__(out self, *, other: Self):
        self.urgency = other.urgency
        self.incremental = other.incremental

    def __init__(out self, *, deinit take: Self):
        self.urgency = take.urgency
        self.incremental = take.incremental

    @staticmethod
    def default() -> Self:
        """RFC 9218 §4.1 / §4.2 defaults: u=3, i=false."""
        return Self(urgency=DEFAULT_URGENCY, incremental=False)
