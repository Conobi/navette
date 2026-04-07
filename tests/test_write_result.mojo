# tests/test_write_result.mojo
#
# Unit tests for WriteResult (M2.5a §5.4).
from src.http.handler import WriteResult
from tests._test_util import assert_true, assert_false


def test_ok() raises:
    var r = WriteResult.ok()
    assert_true(r.is_ok(), "ok.is_ok")
    assert_false(r.is_would_block(), "ok.is_would_block")
    assert_false(r.is_closed(), "ok.is_closed")


def test_would_block() raises:
    var r = WriteResult.would_block()
    assert_false(r.is_ok(), "would_block.is_ok")
    assert_true(r.is_would_block(), "would_block.is_would_block")
    assert_false(r.is_closed(), "would_block.is_closed")


def test_closed() raises:
    var r = WriteResult.closed()
    assert_false(r.is_ok(), "closed.is_ok")
    assert_false(r.is_would_block(), "closed.is_would_block")
    assert_true(r.is_closed(), "closed.is_closed")


def main() raises:
    test_ok()
    test_would_block()
    test_closed()
    print("test_write_result: all tests passed")
