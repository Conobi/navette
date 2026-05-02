# src/http/headers.mojo
#
# HTTP header collection (RFC 9110 Section 5).
# Ordered list of name-value pairs. Lowercase-on-insert.
# Pseudo-headers (:method, :path, etc.) are NOT stored here.


def _to_lower(s: String) -> String:
    """Convert ASCII uppercase to lowercase in a string.

    ASCII-only contract preserved (matches the previous chr-based
    implementation). Bulk-build into a sized List[UInt8] then convert
    once to String, avoiding per-byte += chr(Int(b)) allocator churn.
    """
    var bytes = s.as_bytes()
    var n = len(bytes)
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var b = bytes[i]
        if b >= UInt8(65) and b <= UInt8(90):
            out.append(b + UInt8(32))
        else:
            out.append(b)
    return String(unsafe_from_utf8=out)


struct Headers(Copyable, Movable, Sized):
    """Ordered HTTP header collection.

    Names are lowercased on insert. Values are preserved exactly.
    Multiple headers with the same name are allowed (e.g., Set-Cookie).
    """
    var _names: List[String]
    var _values: List[String]

    def __init__(out self):
        """Construct an empty Headers collection."""
        self._names = List[String]()
        self._values = List[String]()

    def __init__(out self, *, other: Self):
        """Copy constructor."""
        self._names = other._names.copy()
        self._values = other._values.copy()

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._names = take._names^
        self._values = take._values^

    # --- Size ---

    def __len__(self) -> Int:
        """Return the total number of header entries."""
        return len(self._names)

    # --- Add / Set / Remove ---

    def add(mut self, name: String, var value: String):
        """Append a header. Name is lowercased on insert. Value is taken
        by-transfer so owned-temporary callers (literal, returned String,
        local var passed via ^) avoid the auto-copy on append."""
        self._names.append(_to_lower(name))
        self._values.append(value^)

    def add_lowercase(mut self, var name: String, var value: String):
        """Append a header where `name` is already lowercase.

        Caller MUST guarantee `name` contains no ASCII A-Z. Used by
        the HPACK ingress path: HTTP/2 wire header names are required
        to be lowercase by RFC 7540 Section 8.1.2, so the decoder
        output is already valid input here. Skips `_to_lower` to
        avoid the duplicate scan + allocation.

        Both name and value are taken by-transfer to avoid auto-copy
        on append.
        """
        self._names.append(name^)
        self._values.append(value^)

    def set(mut self, name: String, var value: String):
        """Set a header, replacing all existing values for this name.
        Value is taken by-transfer (see `add` doc)."""
        var lower_name = _to_lower(name)
        self.remove(lower_name)
        self._names.append(lower_name^)
        self._values.append(value^)

    def remove(mut self, name: String):
        """Remove all headers with the given name (case-insensitive)."""
        var lower_name = _to_lower(name)
        var new_names = List[String]()
        var new_values = List[String]()
        for i in range(len(self._names)):
            if self._names[i] != lower_name:
                new_names.append(self._names[i])
                new_values.append(self._values[i])
        self._names = new_names^
        self._values = new_values^

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
        for i in range(len(self._names)):
            if self._names[i] == lower_name:
                return True
        return False

    # --- Indexed access ---

    def name_at(ref self, index: Int) -> ref [self._names] String:
        """Return the name at the given index (insertion order). Returned
        by reference so call sites that pass it to borrow params (e.g.,
        QpackEncoder._encode_field) avoid the per-access String copy.
        Callers that need an owned copy should use `.copy()` explicitly."""
        return self._names[index]

    def value_at(ref self, index: Int) -> ref [self._values] String:
        """Return the value at the given index (insertion order). Returned
        by reference; see `name_at` doc."""
        return self._values[index]
