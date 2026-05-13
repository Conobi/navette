# conformance/lib/stateful_vectors.mojo
#
# Pre-materialized oracle vector loaders for the stateful cross-validation
# tests. These replace the live Python.import_module("h11"/"httptools"/"h2"/
# "hpack") calls in test_h1_{cross_parser,response_cross,connection_cross},
# test_h2_{connection,stream}_cross, and test_hpack_cross.
#
# JSON shapes are documented in conformance/scripts/oracle_h1_h2_states.py.
from python import Python, PythonObject


def load_states(path: String) raises -> PythonObject:
    """Load a JSON sidecar containing oracle states. Returns the parsed dict."""
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "r")
    var data = json.load(f)
    f.close()
    return data


def py_has_key(obj: PythonObject, key: String) -> Bool:
    """True if a Python dict contains a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def py_field_str(obj: PythonObject, key: String) -> String:
    """Read a string field. Returns empty if missing or None."""
    try:
        if not py_has_key(obj, key):
            return String("")
        var v = obj[key]
        var builtins = Python.import_module("builtins")
        if Bool(builtins.bool(v is builtins.None)):
            return String("")
        return String(v)
    except:
        return String("")


def py_field_int(obj: PythonObject, key: String) -> Int:
    """Read an int field. Returns -1 if missing or None."""
    try:
        if not py_has_key(obj, key):
            return -1
        var v = obj[key]
        var builtins = Python.import_module("builtins")
        if Bool(builtins.bool(v is builtins.None)):
            return -1
        return Int(py=v)
    except:
        return -1


def py_field_bool(obj: PythonObject, key: String) -> Bool:
    """Read a bool field. Returns False if missing or None."""
    try:
        if not py_has_key(obj, key):
            return False
        var v = obj[key]
        var builtins = Python.import_module("builtins")
        if Bool(builtins.bool(v is builtins.None)):
            return False
        return Bool(builtins.bool(v))
    except:
        return False
