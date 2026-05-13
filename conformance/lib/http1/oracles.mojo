# conformance/lib/http1/oracles.mojo
#
# As of §3.3 of the dependency-enhancement plan, all live h11 / httptools
# oracle wrappers have been pruned. Their callers (test_h1_cross_parser,
# test_h1_response_cross, test_h1_connection_cross) now read pre-materialized
# oracle outputs from JSON sidecars under conformance/vectors/rfc9112/
# (see conformance/scripts/oracle_h1_h2_states.py).
#
# This module is intentionally left empty (apart from this note) to keep
# the `from lib.http1.oracles import …` import sites in any future test
# easy to revive — but no new live oracle calls should be added here.
from python import Python, PythonObject  # noqa: F401  (kept for potential reuse)
