# navette/http/header_table_index.mojo
#
# O(1) lookup accelerator for HPACK/QPACK static tables.


struct StaticTableIndex(Copyable, Movable):
    """O(1) lookup accelerator for HPACK/QPACK static tables.

    Two Dicts: exact match (name + NUL + value -> index) and name-only
    (name -> first index). Built once at encoder init; replaces the
    linear scan in StaticTable.find().
    """

    var _exact: Dict[String, Int]
    var _name_only: Dict[String, Int]

    def __init__(
        out self,
        entries: List[Tuple[String, String]],
        start_index: Int,
    ):
        """Build index from a list of (name, value) entries.

        Entries before start_index are skipped (e.g. the dummy slot 0 in
        HPACK's 1-based table).
        """
        self._exact = Dict[String, Int]()
        self._name_only = Dict[String, Int]()
        for i in range(start_index, len(entries)):
            var name = entries[i][0]
            var value = entries[i][1]
            var exact_key = name + "\x00" + value
            if exact_key not in self._exact:
                self._exact[exact_key] = i
            if name not in self._name_only:
                self._name_only[name] = i

    def find(self, name: String, value: String) raises -> Tuple[Int, Bool]:
        """O(1) header lookup returning (index, exact_match).

        Returns (-1, False) when neither name nor name+value is found.
        """
        var exact_key = name + "\x00" + value
        if exact_key in self._exact:
            return (self._exact[exact_key], True)
        if name in self._name_only:
            return (self._name_only[name], False)
        return (-1, False)
