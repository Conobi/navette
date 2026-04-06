# conformance/lib/http2/oracles.mojo
#
# Python oracle wrappers for HTTP/2 frame cross-validation.
from python import Python, PythonObject


def _wire_to_py_bytes(wire: List[UInt8]) raises -> PythonObject:
    """Convert Mojo List[UInt8] to Python bytes."""
    var builtins = Python.import_module("builtins")
    var ba = builtins.bytearray()
    for i in range(len(wire)):
        ba.append(Int(wire[i]))
    return builtins.bytes(ba)


def decode_frame_with_hyperframe(wire: List[UInt8]) raises -> PythonObject:
    """Decode one HTTP/2 frame with the hyperframe oracle. Returns Python dict."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    return helpers.decode_frame_with_hyperframe(_wire_to_py_bytes(wire))
