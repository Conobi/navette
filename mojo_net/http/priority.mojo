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

    @staticmethod
    def parse_header(value: String) raises -> Self:
        """Parse an RFC 9218 §4 Priority header value. Accepts `u=N`
        (0..7), bare `i`, and explicit `i=?0` / `i=?1`. Unknown keys are
        ignored per Structured Fields forward-compatibility. Raises if the
        urgency is outside 0..7 or if `u=` is followed by a non-integer."""
        var urgency = DEFAULT_URGENCY
        var incremental = False

        var i = 0
        var bytes = value.as_bytes()
        var n = len(bytes)

        # Byte constants
        var B_SP   = UInt8(32)   # ' '
        var B_TAB  = UInt8(9)    # '\t'
        var B_COMMA = UInt8(44)  # ','
        var B_EQ   = UInt8(61)   # '='

        while i < n:
            # Skip leading whitespace / commas
            while i < n and (bytes[i] == B_SP or bytes[i] == B_COMMA or bytes[i] == B_TAB):
                i += 1
            if i >= n:
                break

            # Read the key (letters until '=' or ',' or whitespace)
            var key_start = i
            while i < n and bytes[i] != B_EQ and bytes[i] != B_COMMA and bytes[i] != B_SP and bytes[i] != B_TAB:
                i += 1
            # Build key string from byte range
            var key = String()
            var ki = key_start
            while ki < i:
                key += chr(Int(bytes[ki]))
                ki += 1

            # Read optional '=' value
            var has_value = False
            var val_str = String("")
            if i < n and bytes[i] == B_EQ:
                i += 1
                has_value = True
                var val_start = i
                while i < n and bytes[i] != B_COMMA and bytes[i] != B_SP and bytes[i] != B_TAB:
                    i += 1
                # Build val_str from byte range
                var vi = val_start
                while vi < i:
                    val_str += chr(Int(bytes[vi]))
                    vi += 1

            if key == "u":
                if not has_value:
                    raise Error("Priority.parse_header: 'u' key requires a value")
                urgency = atol(val_str)
                if urgency < 0 or urgency > 7:
                    raise Error("Priority.parse_header: urgency out of range 0..7")
            elif key == "i":
                if not has_value:
                    incremental = True
                elif val_str == "?1":
                    incremental = True
                elif val_str == "?0":
                    incremental = False
                else:
                    raise Error("Priority.parse_header: 'i' value must be '?0' or '?1'")
            # Unknown keys are silently ignored (forward compat).

        return Self(urgency=urgency, incremental=incremental)

    def serialize_header(self) -> String:
        """Render to an RFC 9218 §4 Priority header value. Defaults are
        omitted — an empty string is returned when both fields are at their
        defaults. Non-default urgency is rendered as `u=N`; incremental is
        rendered as the bare token `i` when true."""
        var parts = List[String]()
        if self.urgency != DEFAULT_URGENCY:
            parts.append(String("u=") + String(self.urgency))
        if self.incremental:
            parts.append(String("i"))

        if len(parts) == 0:
            return String("")
        var out = parts[0]
        for idx in range(1, len(parts)):
            out += String(", ")
            out += parts[idx]
        return out
