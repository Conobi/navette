# conformance/lib/http1/oracles.mojo
#
# Python oracle wrappers for cross-validation.
from python import Python, PythonObject


def _wire_to_py_bytes(wire: List[UInt8]) raises -> PythonObject:
    """Convert Mojo List[UInt8] to Python bytes."""
    var builtins = Python.import_module("builtins")
    var ba = builtins.bytearray()
    for i in range(len(wire)):
        ba.append(Int(wire[i]))
    return builtins.bytes(ba)


def parse_with_h11(wire: List[UInt8]) raises -> PythonObject:
    """Parse wire bytes with h11 oracle. Returns Python dict."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")  # so we can import oracle_helpers
    var helpers = Python.import_module("oracle_helpers")
    var py_bytes = _wire_to_py_bytes(wire)
    return helpers.parse_with_h11(py_bytes)


def parse_with_httptools(wire: List[UInt8]) raises -> PythonObject:
    """Parse wire bytes with httptools oracle. Returns Python dict."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var py_bytes = _wire_to_py_bytes(wire)
    return helpers.parse_with_httptools(py_bytes)


def parse_response_with_h11(wire: List[UInt8], request_method: String = "GET") raises -> PythonObject:
    """Parse response with h11 oracle."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var py_bytes = _wire_to_py_bytes(wire)
    return helpers.parse_response_with_h11(py_bytes, request_method)


def parse_response_with_httptools(wire: List[UInt8], request_method: String = "GET") raises -> PythonObject:
    """Parse response with httptools oracle."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var py_bytes = _wire_to_py_bytes(wire)
    return helpers.parse_response_with_httptools(py_bytes, request_method)


def parse_connection_with_h11(
    wire: List[UInt8], direction: String, request_methods: List[String],
) raises -> PythonObject:
    """Parse multi-message wire with h11's connection state machine."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    var helpers = Python.import_module("oracle_helpers")
    var py_bytes = _wire_to_py_bytes(wire)
    var builtins = Python.import_module("builtins")
    var py_methods = builtins.list()
    for i in range(len(request_methods)):
        py_methods.append(request_methods[i])
    return helpers.parse_connection_with_h11(py_bytes, direction, py_methods)
