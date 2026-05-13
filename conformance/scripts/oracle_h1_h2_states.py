"""Pre-materialize stateful h1/h2/hpack oracle outputs (deps-enhancement §3.3).

This script runs the live h11 / httptools / h2 / hpack oracles offline and
writes their outputs as JSON sidecars under conformance/vectors/. The
cross-validation tests then read these JSONs at runtime instead of importing
the Python libs.

Sidecar shapes (one paragraph per oracle):

  h11_request_states.json
    {<vec_id>: {"oracle": "h11", "ok": bool, "error": str|null,
                 "method": str, "target": str, "version": str,
                 "headers": [[name, value], ...], "body_hex": hex}}
    Plus a per-vec_id "httptools" sub-dict in the same shape (httptools
    has no body context for empty payloads -- body_hex always empty).

  h11_response_states.json
    {<vec_id>: {"h11": {...resp...}, "httptools": {...resp...}}}
    where resp = {"ok", "error", "status_code", "reason", "version",
                  "headers", "body_hex"}.
    httptools is omitted for HEAD/CONNECT request methods.

  h11_connection_states.json
    {<vec_id>: {"ok": bool, "error": str|null,
                "messages": [{"type": "request"|"response", ...}, ...],
                "phase": "IDLE"|"MUST_CLOSE"|"UPGRADED"|"ERROR"}}
    Only h11 -- httptools has no connection state machine.

  h2_states.json
    {"client_preface_hex": str,
     "server_preface_after_empty_recv_hex": str,
     "ping_payload_hex": str, "ping_ack_hex": str,
     "ping_events": [...],
     "roundtrip": {"server_events": [...], "client_events": [...],
                   "request_wire_hex": str, "response_wire_hex": str},
     "stream_data_100_A": {"events": [...], "wire_hex": str}}

  hpack_states.json
    {"random_seeded_stories": [
       {"seed": str, "blocks": [[[name, value], ...], ...],
        "py_encoded_hex_list": [hex, ...],
        "py_decoded_blocks": [[[name, value], ...], ...]}
     ]}
    where py_encoded_hex_list is the Python-encoded wire for each block
    (stateful encoder), and py_decoded_blocks is the Python-decoded
    output when re-feeding those wires (stateful decoder).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_CONF = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_CONF / "scripts"))

import oracle_helpers as oh  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bytes_to_hex(b) -> str:
    if b is None:
        return ""
    if isinstance(b, str):
        # already hex? assume not — return raw bytes hex
        return b.encode("ascii", errors="replace").hex()
    return bytes(b).hex()


def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


def _h11_result_to_dict(d: dict) -> dict:
    """Normalize an h11/httptools request-parse dict for JSON."""
    out = {"ok": d.get("error") is None, "error": d.get("error")}
    if out["ok"]:
        out["method"] = d.get("method") or ""
        out["target"] = d.get("target") or ""
        out["version"] = d.get("version") or ""
        out["headers"] = d.get("headers") or []
        out["body_hex"] = _bytes_to_hex(d.get("body") or b"")
    return out


def _h11_response_to_dict(d: dict) -> dict:
    out = {"ok": d.get("error") is None, "error": d.get("error")}
    if out["ok"]:
        out["status_code"] = d.get("status_code")
        out["reason"] = d.get("reason") or ""
        out["version"] = d.get("version") or ""
        out["headers"] = d.get("headers") or []
        out["body_hex"] = _bytes_to_hex(d.get("body") or b"")
    return out


def _h11_conn_to_dict(d: dict) -> dict:
    out = {"ok": d.get("error") is None, "error": d.get("error"),
           "phase": d.get("phase") or "IDLE", "messages": []}
    for m in d.get("messages") or []:
        rec = {"type": m.get("type")}
        if m.get("type") == "request":
            rec["method"] = m.get("method") or ""
            rec["target"] = m.get("target") or ""
            rec["version"] = m.get("version") or ""
            rec["headers"] = m.get("headers") or []
            rec["body_hex"] = _bytes_to_hex(m.get("body") or b"")
        else:
            rec["status_code"] = m.get("status_code")
            rec["reason"] = m.get("reason") or ""
            rec["version"] = m.get("version") or ""
            rec["headers"] = m.get("headers") or []
            rec["body_hex"] = _bytes_to_hex(m.get("body") or b"")
        out["messages"].append(rec)
    return out


def _should_skip(v: dict) -> bool:
    if "mode_flag" in v or "mode_flags" in v:
        return True
    if "deferred" in v:
        return True
    if "oracle_disagreement" in v or "auto_corrected" in v:
        return True
    return False


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def gen_h11_request_states():
    files = [
        "request_line.json", "headers.json", "content_length.json",
        "chunked.json", "host.json",
    ]
    out: dict = {}
    for fname in files:
        path = REPO_CONF / "vectors" / "rfc9112" / fname
        vectors = json.loads(path.read_text())
        for v in vectors:
            if _should_skip(v):
                continue
            wire = _hex_to_bytes(v["input"]["wire_hex"])
            h11_res = oh.parse_with_h11(wire)
            ht_res = oh.parse_with_httptools(wire)
            out[v["id"]] = {
                "h11": _h11_result_to_dict(h11_res),
                "httptools": _h11_result_to_dict(ht_res),
            }
    return out


def gen_h11_response_states():
    files = [
        "response_status.json", "response_body.json", "response_head.json",
        "response_informational.json", "response_no_body.json",
        "response_framing.json",
    ]
    out: dict = {}
    for fname in files:
        path = REPO_CONF / "vectors" / "rfc9112" / fname
        vectors = json.loads(path.read_text())
        for v in vectors:
            if _should_skip(v):
                continue
            request_method = v.get("request_method", "GET")
            wire = _hex_to_bytes(v["input"]["wire_hex"])
            h11_res = oh.parse_response_with_h11(wire, request_method)
            entry = {
                "request_method": request_method,
                "h11": _h11_response_to_dict(h11_res),
            }
            if request_method.upper() not in ("HEAD", "CONNECT"):
                ht_res = oh.parse_response_with_httptools(wire, request_method)
                entry["httptools"] = _h11_response_to_dict(ht_res)
            out[v["id"]] = entry
    return out


def gen_h11_connection_states():
    files = [
        "connection_keepalive.json", "connection_close.json",
        "connection_upgrade.json", "connection_informational.json",
        "connection_pipeline.json", "connection_error.json",
    ]
    out: dict = {}
    for fname in files:
        path = REPO_CONF / "vectors" / "rfc9112" / fname
        vectors = json.loads(path.read_text())
        for v in vectors:
            if _should_skip(v):
                continue
            direction = v["direction"]
            request_methods = list(v.get("request_methods") or [])
            wire = _hex_to_bytes(v["input"]["wire_hex"])
            h11_res = oh.parse_connection_with_h11(wire, direction, request_methods)
            out[v["id"]] = {
                "direction": direction,
                "request_methods": request_methods,
                **_h11_conn_to_dict(h11_res),
            }
    return out


def gen_h2_states():
    """Bake the fixed h2 scenarios used by test_h2_{connection,stream}_cross.

    These tests use a fixed Mojo-side client preface (which is byte-identical
    across Mojo runs since H2Connection writes a deterministic SETTINGS frame).
    We can't compute that here, so we instead bake what h2 produces given an
    *empty* receive (to extract h2's own server preface) and what h2's server
    emits when fed the standard 24-byte HTTP/2 preface string + a default
    SETTINGS frame. The test side compares whichever fields are stable.

    For PING: bake the PING ACK bytes for the canonical 8-byte payload used
    in test_h2_connection_cross.test_cross_ping.

    For roundtrip and stream-data scenarios: bake the same outputs the test
    currently fetches via h2_roundtrip() / h2_stream_data_scenario().
    """
    import h2.connection as _h2c, h2.config as _h2cfg

    out: dict = {}

    # ----- Server preface after empty receive (server.initiate->data_to_send) -
    cfg = _h2cfg.H2Configuration(client_side=False)
    server = _h2c.H2Connection(config=cfg)
    server.initiate_connection()
    server_preface = server.data_to_send()
    out["server_preface_after_empty_recv_hex"] = server_preface.hex()

    # ----- Client preface (for documentation) ---------------------------------
    cfg = _h2cfg.H2Configuration(client_side=True)
    client = _h2c.H2Connection(config=cfg)
    client.initiate_connection()
    client_preface = client.data_to_send()
    out["client_preface_hex"] = client_preface.hex()

    # ----- PING scenario: feed h2's own client preface + PING frame ----------
    # Build canonical PING frame: length=8, type=0x06, flags=0, stream_id=0,
    # payload = 0x10..0x80
    ping_payload = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
    ping_frame = (
        (8).to_bytes(3, "big")  # length
        + bytes([0x06])  # type PING
        + bytes([0x00])  # flags
        + (0).to_bytes(4, "big")  # stream_id
        + ping_payload
    )
    out["ping_payload_hex"] = ping_payload.hex()
    out["ping_frame_hex"] = ping_frame.hex()
    ping_oracle = oh.h2_ping_scenario(client_preface, ping_frame)
    out["ping_oracle"] = ping_oracle

    # ----- Roundtrip --------------------------------------------------------
    out["roundtrip"] = oh.h2_roundtrip()

    # ----- Stream data scenario: 100 'A' bytes ------------------------------
    hdrs = [(":method", "POST"), (":path", "/"),
            (":scheme", "https"), (":authority", "example.com")]
    body = b"A" * 100
    out["stream_data_100_A"] = oh.h2_stream_data_scenario(hdrs, body, end_stream=True)

    # ----- Server receive of client preface (h2 server-side events) ----------
    out["h2_server_receive_client_preface"] = oh.h2_server_receive(client_preface)

    return out


def gen_hpack_raw_stories():
    """If conformance/vectors/hpack-stories/raw-data/ is present, bake
    Python-encoder output for each story so test_hpack_cross can run
    phase 1 (our encode -> py decode) and phase 2 (py encode -> our decode)
    without importing Python hpack at test time.

    Returns a dict keyed by story filename. Empty if stories are absent.
    """
    import hpack as _hpack

    raw_dir = REPO_CONF / "vectors" / "hpack-stories" / "raw-data"
    if not raw_dir.is_dir():
        return {}

    out = {}
    files = sorted(p.name for p in raw_dir.iterdir() if p.name.endswith(".json"))
    # Match the test: first 5 stories
    for fname in files[:5]:
        data = json.loads((raw_dir / fname).read_text())
        cases = data.get("cases", [])

        # Python stateful encode (mirrors hpack_story_encode_with_python)
        encoder = _hpack.Encoder()
        py_encoded = []
        all_headers = []
        for tc in cases:
            headers = []
            for h in tc["headers"]:
                # Story headers are [{name: value}] single-key dicts
                k = list(h.keys())[0]
                v = h[k]
                headers.append([k, v])
            all_headers.append(headers)
            wire = encoder.encode([(h[0], h[1]) for h in headers])
            py_encoded.append(wire.hex())

        out[fname] = {
            "case_count": len(cases),
            "all_headers": all_headers,
            "py_encoded_hex_list": py_encoded,
        }
    return out


def gen_hpack_states():
    """Bake hpack stateful encode/decode for random-fuzz replacement.

    The Mojo test currently generates random headers per story using a
    time-seeded PRNG, then cross-validates both directions against hpack
    statefully. We bake a fixed set of 5 stories with reproducible headers
    + Python's encoded wire + decoded output.
    """
    import hpack as _hpack

    # Deterministic seed
    rng_state = 0xDEADBEEF
    def xorshift():
        nonlocal rng_state
        rng_state ^= (rng_state << 13) & 0xFFFFFFFFFFFFFFFF
        rng_state ^= (rng_state >> 7) & 0xFFFFFFFFFFFFFFFF
        rng_state ^= (rng_state << 17) & 0xFFFFFFFFFFFFFFFF
        return rng_state & 0x7FFFFFFFFFFFFFFF

    pseudo_names = [":method", ":path", ":scheme", ":authority",
                    "content-type", "accept", "user-agent",
                    "x-custom-0", "x-custom-1", "x-custom-2",
                    "x-custom-3", "x-custom-4"]
    pseudo_values = ["GET", "POST", "PUT", "/", "/index.html",
                     "https", "http", "example.com", "text/html",
                     "application/json"]
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"

    stories = []
    for _ in range(5):
        n_blocks = 3 + (xorshift() % 3)
        blocks = []
        for _ in range(n_blocks):
            n_headers = 2 + (xorshift() % 3)
            headers = []
            for _ in range(n_headers):
                name = pseudo_names[xorshift() % len(pseudo_names)]
                base = pseudo_values[xorshift() % len(pseudo_values)]
                slen = 5 + (xorshift() % 6)
                suffix = "".join(alpha[xorshift() % len(alpha)] for _ in range(slen))
                headers.append([name, base + suffix])
            blocks.append(headers)

        # Python stateful encode
        encoder = _hpack.Encoder()
        py_encoded = []
        for block in blocks:
            wire = encoder.encode([(h[0], h[1]) for h in block])
            py_encoded.append(wire.hex())

        # Python stateful decode (feed back the python-encoded wire)
        decoder = _hpack.Decoder()
        py_decoded = []
        for wire_hex in py_encoded:
            wire = bytes.fromhex(wire_hex)
            hdrs = decoder.decode(wire)
            py_decoded.append([
                [h[0].decode() if isinstance(h[0], bytes) else h[0],
                 h[1].decode() if isinstance(h[1], bytes) else h[1]]
                for h in hdrs
            ])

        stories.append({
            "blocks": blocks,
            "py_encoded_hex_list": py_encoded,
            "py_decoded_blocks": py_decoded,
        })

    return {
        "random_seeded_stories": stories,
        "raw_data_stories": gen_hpack_raw_stories(),
    }


# ---------------------------------------------------------------------------
# Random request/response cross-vectors (replaces in-test PRNG fuzz)
# ---------------------------------------------------------------------------

def gen_h11_request_random_states():
    """Pre-baked random request vectors + oracle outputs (replaces test PRNG)."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    paths = ["/", "/index.html", "/api/v1/users", "/search?q=hello",
             "/data/42", "/a/b/c/d"]
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"

    # Deterministic LCG identical-shaped to the test (no time seed)
    seed = 0x1234567890ABCDEF
    def lcg():
        nonlocal seed
        seed = (seed * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        return seed

    cases = []
    for i in range(20):
        m_idx = lcg() % len(methods)
        p_idx = lcg() % len(paths)
        rv = lcg()
        rand_val = ""
        for _ in range(12):
            rand_val += alpha[rv % len(alpha)]
            rv = (rv * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        method = methods[m_idx]
        path = paths[p_idx]
        req = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: test.example.com\r\n"
            f"X-Rand: {rand_val}\r\n\r\n"
        ).encode("ascii")
        h11_res = oh.parse_with_h11(req)
        ht_res = oh.parse_with_httptools(req)
        cases.append({
            "id": f"rand-{i}",
            "method": method,
            "path": path,
            "wire_hex": req.hex(),
            "h11": _h11_result_to_dict(h11_res),
            "httptools": _h11_result_to_dict(ht_res),
        })
    return {"cases": cases}


def gen_h11_response_random_states():
    status_codes = [200, 201, 204, 301, 302, 400, 403, 404, 500, 503]
    reasons = ["OK", "Created", "No Content", "Moved Permanently", "Found",
               "Bad Request", "Forbidden", "Not Found",
               "Internal Server Error", "Service Unavailable"]
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"

    seed = 0xFEDCBA9876543210
    def lcg():
        nonlocal seed
        seed = (seed * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        return seed

    cases = []
    for i in range(20):
        idx = lcg() % len(status_codes)
        sc = status_codes[idx]
        reason = reasons[idx]
        has_body = sc != 204
        rv = lcg()
        rand_val = ""
        for _ in range(12):
            rand_val += alpha[rv % len(alpha)]
            rv = (rv * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        rand_body = ""
        if has_body:
            body_len = 5 + (lcg() % 20)
            bv = lcg()
            for _ in range(body_len):
                rand_body += alpha[bv % len(alpha)]
                bv = (bv * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        if has_body:
            resp = (
                f"HTTP/1.1 {sc} {reason}\r\n"
                f"Content-Length: {len(rand_body)}\r\n"
                f"X-Rand: {rand_val}\r\n\r\n{rand_body}"
            ).encode("ascii")
        else:
            resp = (
                f"HTTP/1.1 {sc} {reason}\r\n"
                f"X-Rand: {rand_val}\r\n\r\n"
            ).encode("ascii")
        h11_res = oh.parse_response_with_h11(resp, "GET")
        ht_res = oh.parse_response_with_httptools(resp, "GET")
        cases.append({
            "id": f"rand-resp-{i}",
            "status_code": sc,
            "reason": reason,
            "wire_hex": resp.hex(),
            "h11": _h11_response_to_dict(h11_res),
            "httptools": _h11_response_to_dict(ht_res),
        })
    return {"cases": cases}


def gen_h11_connection_random_states():
    """5 deterministic two-GET pipelines + h11 connection oracle output."""
    alpha = "abcdefghijklmnopqrstuvwxyz"
    cases = []
    seed = 0xABCD1234
    for i in range(5):
        tv1 = seed + i * 7 + 1
        tv2 = seed + i * 13 + 3
        host1 = "h"
        host2 = "h"
        for ci in range(6):
            host1 += alpha[tv1 % 26]
            tv1 = tv1 // 26 + ci + 1
            host2 += alpha[tv2 % 26]
            tv2 = tv2 // 26 + ci + 1
        host1 += ".test"
        host2 += ".test"
        wire = (
            f"GET /a HTTP/1.1\r\nHost: {host1}\r\n\r\n"
            f"GET /b HTTP/1.1\r\nHost: {host2}\r\n\r\n"
        ).encode("ascii")
        h11_res = oh.parse_connection_with_h11(wire, "request", [])
        cases.append({
            "id": f"rand-conn-{i}",
            "wire_hex": wire.hex(),
            **_h11_conn_to_dict(h11_res),
        })
    return {"seed": seed, "cases": cases}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n")
    print(f"  wrote {path.relative_to(REPO_CONF.parent)}")


def main():
    out_root = REPO_CONF / "vectors"

    # h1 request states (vector-based + random)
    h11_req = gen_h11_request_states()
    h11_req["__random__"] = gen_h11_request_random_states()
    write_json(out_root / "rfc9112" / "h11_request_states.json", h11_req)

    # h1 response states (vector-based + random)
    h11_resp = gen_h11_response_states()
    h11_resp["__random__"] = gen_h11_response_random_states()
    write_json(out_root / "rfc9112" / "h11_response_states.json", h11_resp)

    # h1 connection states (vector-based + random)
    h11_conn = gen_h11_connection_states()
    h11_conn["__random__"] = gen_h11_connection_random_states()
    write_json(out_root / "rfc9112" / "h11_connection_states.json", h11_conn)

    # h2 fixed scenarios
    h2_states = gen_h2_states()
    write_json(out_root / "rfc9113" / "h2_states.json", h2_states)

    # hpack random stories (deterministic)
    hpack_states = gen_hpack_states()
    write_json(out_root / "rfc7541" / "hpack_states.json", hpack_states)


if __name__ == "__main__":
    main()
