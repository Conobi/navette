from navette.http.decode import ContentEncoding
from navette.h2.hpack_table import StaticTable


def test_content_encoding_movable() raises:
    var a = ContentEncoding(UInt8(0))
    var b = a^                      # forces move-ctor synthesis
    _ = b


def test_static_table_movable() raises:
    var a = StaticTable()
    var b = a^                      # forces move-ctor synthesis
    _ = b


def main() raises:
    test_content_encoding_movable()
    test_static_table_movable()
    print("test_b2_movable_leaf_types: passed")
