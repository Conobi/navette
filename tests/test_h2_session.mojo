# tests/test_h2_session.mojo
#
# Tests for H2Session (M5.5 Task 8).

from std.collections.deque import Deque

from src.http.handler import Capabilities, ALPN_H2
from src.http.session import Session, RequestHandle
from src.h2.h2_session import H2Session


# ---------------------------------------------------------------------------
# test_construction_and_preface
# ---------------------------------------------------------------------------


def test_construction_and_preface() raises:
    """Construct H2Session, drain output. Verify non-empty (client connection
    preface: magic + SETTINGS frame)."""
    var session = H2Session()
    var data = session.drain()
    # The HTTP/2 client connection preface is 24 bytes of magic followed by
    # at least one SETTINGS frame (9 byte header + payload).  Total must be
    # non-empty.
    if len(data) == 0:
        raise Error("drain after construction must produce client preface")
    # The first 24 bytes should be the HTTP/2 connection preface magic.
    # PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    if len(data) < 24:
        raise Error(
            "preface must be at least 24 bytes, got " + String(len(data))
        )
    var magic = String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    var magic_bytes = magic.as_bytes()
    for i in range(24):
        if data[i] != magic_bytes[i]:
            raise Error("preface byte mismatch at index " + String(i))
    _ = session^
    print("PASS test_construction_and_preface")


# ---------------------------------------------------------------------------
# test_capabilities
# ---------------------------------------------------------------------------


def test_capabilities() raises:
    """Verify capabilities() returns for_h2 and alpn() returns ALPN_H2."""
    var session = H2Session()
    var caps = session.capabilities()
    if not caps.multiplexed:
        raise Error("H2 must be multiplexed")
    if not caps.trailers:
        raise Error("H2 must support trailers")
    if caps.alpn != ALPN_H2:
        raise Error("capabilities.alpn must be ALPN_H2")
    if session.alpn() != ALPN_H2:
        raise Error("alpn() must return ALPN_H2")
    _ = session^
    print("PASS test_capabilities")


# ---------------------------------------------------------------------------
# test_close
# ---------------------------------------------------------------------------


def test_close() raises:
    """Verify close() does not raise on a freshly constructed session."""
    var session = H2Session()
    # Drain the preface bytes first so we have a clean outbuf
    _ = session.drain()
    session^.close()
    print("PASS test_close")


# ---------------------------------------------------------------------------
# test_drain_idempotent
# ---------------------------------------------------------------------------


def test_drain_idempotent() raises:
    """Verify drain() returns empty after draining once."""
    var session = H2Session()
    _ = session.drain()
    var second = session.drain()
    if len(second) != 0:
        raise Error(
            "second drain must be empty, got " + String(len(second)) + " bytes"
        )
    _ = session^
    print("PASS test_drain_idempotent")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    print("test_h2_session")
    test_construction_and_preface()
    test_capabilities()
    test_close()
    test_drain_idempotent()
    print("PASS")
