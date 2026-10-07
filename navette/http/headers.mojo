# src/http/headers.mojo
#
# HTTP header collection (RFC 9110 Section 5).
# Ordered list of name-value pairs. Lowercase-on-insert.
# Pseudo-headers (:method, :path, etc.) are NOT stored here.


def _to_lower(s: String) -> String:
    """ASCII-lowercase `s`; returns `s` itself (no allocation) when it has no A-Z byte."""
    var bytes = s.as_bytes()
    for b in bytes:
        if b >= UInt8(65) and b <= UInt8(90):
            var out = List[Byte](capacity=len(bytes))
            for c in bytes:
                out.append(c + UInt8(32) if c >= UInt8(65) and c <= UInt8(90) else c)
            return String(unsafe_from_utf8=out^)
    return s


struct Headers(Copyable, Movable, Sized):
    """Ordered HTTP header collection.

    Names are lowercased on insert. Values are preserved exactly.
    Multiple headers with the same name are allowed (e.g., Set-Cookie).

    `_auto_content_type` is a non-wire sidecar bit that body-source helpers
    flip to True when they auto-insert a Content-Type header (and leave at
    False when the caller supplied their own). Downstream code paths that
    rewrite the request (e.g. POST -> GET on a 3xx redirect) read this
    bit to decide whether dropping the body should also drop the type.
    """
    var _names: List[String]
    var _values: List[String]
    var _auto_content_type: Bool

    def __init__(out self):
        """Construct an empty Headers collection."""
        self._names = List[String]()
        self._values = List[String]()
        self._auto_content_type = False

    # --- Size ---

    def __len__(self) -> Int:
        """Return the total number of header entries."""
        return len(self._names)

    # --- Add / Set / Remove ---

    def add(mut self, name: String, value: String):
        """Append a header. Name is lowercased on insert."""
        self._names.append(_to_lower(name))
        self._values.append(value)

    def add_lowercase(mut self, var name: String, var value: String):
        """Append a header where `name` is already lowercase, taking both Strings without a copy.

        Caller MUST guarantee `name` contains no ASCII A-Z. Used by
        the HPACK and QPACK ingress paths: HTTP/2 and HTTP/3 wire
        header names are required to be lowercase (RFC 9113 Section
        8.2.1, RFC 9114 Section 4.2), so the decoder output is
        already valid input here. Skips `_to_lower` to avoid the
        duplicate scan + allocation.
        """
        self._names.append(name^)
        self._values.append(value^)

    def set(mut self, name: String, value: String):
        """Set a header, replacing all existing values for this name."""
        self.remove(name)
        self.add(name, value)

    def remove(mut self, name: String):
        """Remove all headers with the given name (case-insensitive), compacting in place."""
        var lower_name = _to_lower(name)
        var kept = 0
        for i in range(len(self._names)):
            if self._names[i] != lower_name:
                self._names[kept] = self._names[i]
                self._values[kept] = self._values[i]
                kept += 1
        self._names.shrink(kept)
        self._values.shrink(kept)

    # --- Retrieval ---

    def get(self, name: String) -> String:
        """Return the first value for a header name, or empty string if absent."""
        var lower_name = _to_lower(name)
        for i in range(len(self._names)):
            if self._names[i] == lower_name:
                return self._values[i]
        return String("")

    def get_all(self, name: String) -> List[String]:
        """Return all values for a header name in insertion order."""
        var lower_name = _to_lower(name)
        var result = List[String]()
        for i in range(len(self._names)):
            if self._names[i] == lower_name:
                result.append(self._values[i])
        return result^

    def has(self, name: String) -> Bool:
        """Return whether a header with the given name exists."""
        var lower_name = _to_lower(name)
        for ref hdr_name in self._names:
            if hdr_name == lower_name:
                return True
        return False

    # --- Indexed access ---

    def name_at(self, index: Int) -> String:
        """Return the name at the given index (insertion order)."""
        return self._names[index]

    def value_at(self, index: Int) -> String:
        """Return the value at the given index (insertion order)."""
        return self._values[index]
