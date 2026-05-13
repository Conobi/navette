# conformance/lib/http2/oracles.mojo
#
# As of §3.3 of the dependency-enhancement plan, the bulk of the live h2 /
# hpack / hyperframe oracle wrappers have been pruned. Their callers
# (test_h2_connection_cross, test_h2_stream_cross, test_hpack_cross, and
# test_h2_frame_cross — the latter already migrated in commit d6d65af) now
# read pre-materialized oracle outputs from JSON sidecars under
# conformance/vectors/rfc91{04,13}/ and conformance/vectors/rfc7541/
# (see conformance/scripts/oracle_h1_h2_states.py).
#
# Only `h2_roundtrip` remains, since `tests/test_h2_stream.mojo` is not in
# the §3.3 stateful migration scope and still calls it directly. If
# test_h2_stream.mojo is later refactored to read from h2_states.json, this
# wrapper can be removed and oracle_helpers.py becomes a pure offline
# vector-generation script.
from std.python import Python, PythonObject


def _get_helpers() raises -> PythonObject:
    """Import oracle_helpers module."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, "scripts")
    return Python.import_module("oracle_helpers")


def h2_roundtrip() raises -> PythonObject:
    """Run a full GET round-trip through Python h2.

    Retained as the sole live oracle wrapper for `tests/test_h2_stream.mojo`,
    which is outside the §3.3 stateful-migration scope.
    """
    var helpers = _get_helpers()
    return helpers.h2_roundtrip()
