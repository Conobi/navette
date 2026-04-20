# conformance/lib/http2/oracles.mojo
#
# Python oracle wrappers for HTTP/2 frame and HPACK cross-validation.
from std.python import Python, PythonObject
from src.h2.header import Header


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


def h2_server_receive(wire: List[UInt8]) raises -> PythonObject:
    """Feed bytes to Python h2 server, return result dict."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var builtins = Python.import_module("builtins")
    var py_list = builtins.list()
    for i in range(len(wire)):
        py_list.append(Int(wire[i]))
    var ba = builtins.bytes(py_list)
    return helpers.h2_server_receive(ba)


def h2_client_receive(wire: List[UInt8]) raises -> PythonObject:
    """Feed bytes to Python h2 client, return result dict."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var builtins = Python.import_module("builtins")
    var py_list = builtins.list()
    for i in range(len(wire)):
        py_list.append(Int(wire[i]))
    var ba = builtins.bytes(py_list)
    return helpers.h2_client_receive(ba)


def h2_roundtrip() raises -> PythonObject:
    """Run a full GET round-trip through Python h2."""
    var helpers = _get_helpers()
    return helpers.h2_roundtrip()


def h2_stream_data_scenario(headers: List[Header], body: List[UInt8], end_stream: Bool = True) raises -> PythonObject:
    """Send HEADERS + DATA through Python h2, return server events."""
    var helpers = _get_helpers()
    var builtins = Python.import_module("builtins")
    var py_headers = builtins.list()
    for i in range(len(headers)):
        var pair = builtins.list()
        pair.append(headers[i].name)
        pair.append(headers[i].value)
        py_headers.append(builtins.tuple(pair))
    var py_body = builtins.bytearray()
    for i in range(len(body)):
        py_body.append(Int(body[i]))
    return helpers.h2_stream_data_scenario(py_headers, builtins.bytes(py_body), end_stream)


def h2_ping_scenario(client_preface: List[UInt8], ping_frame: List[UInt8]) raises -> PythonObject:
    """Run PING scenario through h2 server, return result dict."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var builtins = Python.import_module("builtins")
    var cp_list = builtins.list()
    for i in range(len(client_preface)):
        cp_list.append(Int(client_preface[i]))
    var pf_list = builtins.list()
    for i in range(len(ping_frame)):
        pf_list.append(Int(ping_frame[i]))
    return helpers.h2_ping_scenario(builtins.bytes(cp_list), builtins.bytes(pf_list))
