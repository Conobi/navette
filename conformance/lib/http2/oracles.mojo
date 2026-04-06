# conformance/lib/http2/oracles.mojo
#
# Python oracle wrappers for HTTP/2 frame and HPACK cross-validation.
from std.python import Python, PythonObject
from lib.http1.types import Header


def _wire_to_py_bytes(wire: List[UInt8]) raises -> PythonObject:
    """Convert Mojo List[UInt8] to Python bytes."""
    var builtins = Python.import_module("builtins")
    var ba = builtins.bytearray()
    for i in range(len(wire)):
        ba.append(Int(wire[i]))
    return builtins.bytes(ba)


def _get_helpers() raises -> PythonObject:
    """Import oracle_helpers module."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    return Python.import_module("oracle_helpers")


def decode_frame_with_hyperframe(wire: List[UInt8]) raises -> PythonObject:
    """Decode one HTTP/2 frame with the hyperframe oracle. Returns Python dict."""
    var helpers = _get_helpers()
    return helpers.decode_frame_with_hyperframe(_wire_to_py_bytes(wire))


def hpack_decode_with_python(wire: List[UInt8]) raises -> PythonObject:
    """Decode HPACK wire with Python hpack oracle (stateless)."""
    var helpers = _get_helpers()
    return helpers.hpack_decode_with_python(_wire_to_py_bytes(wire))


def hpack_encode_with_python(headers: List[Header]) raises -> PythonObject:
    """Encode headers with Python hpack oracle (stateless)."""
    var helpers = _get_helpers()
    var builtins = Python.import_module("builtins")
    var py_headers = builtins.list()
    for i in range(len(headers)):
        var pair = builtins.list()
        pair.append(headers[i].name)
        pair.append(headers[i].value)
        py_headers.append(pair)
    return helpers.hpack_encode_with_python(py_headers)


def hpack_story_decode_with_python(
    wire_hex_list: List[String],
) raises -> PythonObject:
    """Decode multiple HPACK blocks statefully with Python hpack."""
    var helpers = _get_helpers()
    var builtins = Python.import_module("builtins")
    var py_list = builtins.list()
    for i in range(len(wire_hex_list)):
        py_list.append(wire_hex_list[i])
    return helpers.hpack_story_decode_with_python(py_list)


def hpack_story_encode_with_python(
    headers_lists: List[List[Header]],
) raises -> PythonObject:
    """Encode multiple header blocks statefully with Python hpack."""
    var helpers = _get_helpers()
    var builtins = Python.import_module("builtins")
    var py_outer = builtins.list()
    for i in range(len(headers_lists)):
        var py_inner = builtins.list()
        for j in range(len(headers_lists[i])):
            var pair = builtins.list()
            pair.append(headers_lists[i][j].name)
            pair.append(headers_lists[i][j].value)
            py_inner.append(pair)
        py_outer.append(py_inner)
    return helpers.hpack_story_encode_with_python(py_outer)
