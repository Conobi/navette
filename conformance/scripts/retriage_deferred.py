#!/usr/bin/env python3
"""Re-triage 67 deferred HC-2 vectors with the full 21-flag set.

For each vector marked "deferred": "HC-2", tests:
  Path 1: Exactly ONE flag makes both oracles accept -> un-defer as mode_flag
  Path 2: Exactly TWO flags make both oracles accept -> un-defer as mode_flags
  Path 3: Everything else stays deferred for HC-2b (multi_message later)

Run:
    cd ~/Projets/perso/mojo-net && uv run conformance/scripts/retriage_deferred.py
"""
import itertools
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from oracle_helpers import (
    parse_response_with_h11,
    parse_response_with_httptools,
    parse_with_h11,
    parse_with_httptools,
)

# ---------------------------------------------------------------------------
# All 21 strictness flags
# ---------------------------------------------------------------------------
ALL_FLAGS = [
    "allow_bare_lf",
    "allow_bare_cr_in_value",
    "allow_http_09",
    "allow_nonstandard_version",
    "allow_multiple_spaces",
    "allow_obs_fold",
    "allow_space_before_colon",
    "allow_header_value_ctl",
    "allow_target_ctl",
    "ignore_invalid_header_names",
    "allow_non_chunked_te",
    "allow_chunk_extensions",
    "allow_cl_leading_zeros",
    "allow_duplicate_cl",
    "allow_missing_host_11",
    "allow_duplicate_host",
    "allow_multiple_spaces_in_status_line",
    "allow_space_before_first_header",
    "allow_missing_crlf_after_chunk",
    "allow_missing_reason_sp",
    "allow_response_cl_te",
]

# Vector files that may contain HC-2 deferred vectors
VECTOR_FILES = [
    "conformance/vectors/rfc9112/request_line.json",
    "conformance/vectors/rfc9112/headers.json",
    "conformance/vectors/rfc9112/content_length.json",
    "conformance/vectors/rfc9112/chunked.json",
    # Response files (check too, in case any were deferred)
    "conformance/vectors/rfc9112/response_status.json",
    "conformance/vectors/rfc9112/response_body.json",
    "conformance/vectors/rfc9112/response_head.json",
    "conformance/vectors/rfc9112/response_framing.json",
    "conformance/vectors/rfc9112/response_informational.json",
    "conformance/vectors/rfc9112/response_no_body.json",
]

# Map flag -> the reason string our Mojo parser produces on strict rejection
FLAG_TO_REASON = {
    "allow_bare_lf": "missing CRLF",
    "allow_bare_cr_in_value": "control character in header field value",
    "allow_http_09": "unsupported HTTP version",
    "allow_nonstandard_version": "unsupported HTTP version",
    "allow_multiple_spaces": "empty target",
    "allow_obs_fold": "obs-fold",
    "allow_space_before_colon": "whitespace before colon",
    "allow_header_value_ctl": "control character in header field value",
    "allow_target_ctl": "control character in request target",
    "ignore_invalid_header_names": "invalid character in header field name",
    "allow_non_chunked_te": "Transfer-Encoding",
    "allow_chunk_extensions": "chunk extensions not allowed",
    "allow_cl_leading_zeros": "Content-Length has leading zeros",
    "allow_duplicate_cl": "multiple Content-Length",
    "allow_missing_host_11": "missing Host header",
    "allow_duplicate_host": "duplicate Host header",
    "allow_multiple_spaces_in_status_line": "rejected in strict mode",
    "allow_space_before_first_header": "rejected in strict mode",
    "allow_missing_crlf_after_chunk": "rejected in strict mode",
    "allow_missing_reason_sp": "rejected in strict mode",
    "allow_response_cl_te": "rejected in strict mode",
}


# ---------------------------------------------------------------------------
# Oracle checks
# ---------------------------------------------------------------------------
def check_oracles(wire_bytes: bytes, vector_type: str, request_method: str = "GET"):
    """Check if both oracles accept this request/response."""
    if vector_type == "response":
        h11_r = parse_response_with_h11(wire_bytes, request_method)
        ht_r = parse_response_with_httptools(wire_bytes, request_method)
    else:
        h11_r = parse_with_h11(wire_bytes)
        ht_r = parse_with_httptools(wire_bytes)

    h11_ok = h11_r.get("error") is None
    ht_ok = ht_r.get("error") is None
    both_accept = h11_ok and ht_ok
    return both_accept, h11_r, ht_r


# ---------------------------------------------------------------------------
# Wire analysis — infer which flags a vector needs
# ---------------------------------------------------------------------------
def _get_version(wire: bytes) -> str:
    decoded = wire.decode("latin-1", errors="replace")
    first_line = (
        decoded.split("\r\n")[0] if "\r\n" in decoded else decoded.split("\n")[0]
    )
    parts = first_line.rsplit(" ", 1)
    if len(parts) == 2:
        if parts[1].startswith("HTTP/"):
            return parts[1][5:]
        if parts[1].startswith("RTSP/") or parts[1].startswith("ICE/"):
            return parts[1]
    return ""


def _has_host_header(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("host:"):
            return True
    return False


def _count_host_headers(wire: bytes) -> int:
    decoded = wire.decode("latin-1", errors="replace")
    count = 0
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("host:"):
            count += 1
    return count


def _has_bare_lf_anywhere(wire: bytes) -> bool:
    for i in range(len(wire)):
        if wire[i] == 0x0A and (i == 0 or wire[i - 1] != 0x0D):
            return True
    return False


def _has_obs_fold(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    lines = decoded.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if i == 0:
            continue
        if line == "":
            break
        if line.startswith(" ") or line.startswith("\t"):
            return True
    return False


def _has_space_before_colon(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    lines = decoded.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if i == 0:
            continue
        if line == "":
            break
        colon_idx = line.find(":")
        if colon_idx > 0 and line[colon_idx - 1] == " ":
            return True
    return False


def _has_ctl_in_header_values(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    lines = decoded.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if i == 0:
            continue
        if line == "":
            break
        colon_idx = line.find(":")
        if colon_idx < 0:
            continue
        value = line[colon_idx + 1 :]
        for ch in value:
            code = ord(ch)
            if code < 0x20 and code not in (0x09,):
                return True
    return False


def _has_invalid_header_names(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    lines = decoded.replace("\r\n", "\n").split("\n")
    tchar = set(b"!#$%&'*+-.^_`|~")
    for i, line in enumerate(lines):
        if i == 0:
            continue
        if line == "":
            break
        colon_idx = line.find(":")
        if colon_idx <= 0:
            continue
        name = line[:colon_idx]
        for ch in name:
            c = ord(ch)
            if (
                not (0x41 <= c <= 0x5A)
                and not (0x61 <= c <= 0x7A)
                and not (0x30 <= c <= 0x39)
                and c not in tchar
            ):
                return True
    return False


def _get_te_value(wire: bytes) -> str:
    decoded = wire.decode("latin-1", errors="replace")
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("transfer-encoding:"):
            return line.split(":", 1)[1].strip()
    return ""


def _get_cl_value(wire: bytes) -> str:
    decoded = wire.decode("latin-1", errors="replace")
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("content-length:"):
            return line.split(":", 1)[1].strip()
    return ""


def _has_chunk_extensions(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    parts = decoded.split("\r\n\r\n", 1)
    if len(parts) < 2:
        parts = decoded.split("\n\n", 1)
    if len(parts) < 2:
        return False
    body = parts[1]
    for line in body.split("\r\n"):
        line = line.strip()
        if ";" in line:
            before_semi = line.split(";")[0].strip()
            try:
                int(before_semi, 16)
                return True
            except ValueError:
                pass
    return False


def _has_multiple_requests(wire: bytes) -> bool:
    import re

    decoded = wire.decode("latin-1", errors="replace")
    matches = re.findall(
        r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE|ANNOUNCE|SOURCE)\s+\S+\s+(?:HTTP|RTSP|ICE)/\d\.\d",
        decoded,
    )
    return len(matches) >= 2


def _has_connect_method(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    return decoded.startswith("CONNECT ")


def _has_upgrade(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace").lower()
    return "upgrade:" in decoded or "connection: upgrade" in decoded


def infer_needed_flags(wire: bytes) -> set[str]:
    """Infer which ParserStrictness flags a vector needs to pass.

    Returns a set of flag names.
    """
    flags = set()
    decoded = wire.decode("latin-1", errors="replace")
    version = _get_version(wire)

    # HTTP/0.9
    if version == "0.9" or (not version and " HTTP/" not in decoded):
        flags.add("allow_http_09")

    # Non-standard version (not 1.0 / 1.1)
    if version and version not in ("0.9", "1.0", "1.1"):
        if "RTSP/" in decoded or "ICE/" in decoded:
            flags.add("allow_nonstandard_version")
        else:
            flags.add("allow_nonstandard_version")

    # Bare LF
    if _has_bare_lf_anywhere(wire):
        flags.add("allow_bare_lf")

    # Obs-fold
    if _has_obs_fold(wire):
        flags.add("allow_obs_fold")

    # Space before colon
    if _has_space_before_colon(wire):
        flags.add("allow_space_before_colon")

    # Control chars in header values
    if _has_ctl_in_header_values(wire):
        flags.add("allow_header_value_ctl")

    # Invalid header names
    if _has_invalid_header_names(wire):
        flags.add("ignore_invalid_header_names")

    # Missing Host in HTTP/1.1
    if not _has_host_header(wire):
        flags.add("allow_missing_host_11")

    # Duplicate Host
    if _count_host_headers(wire) > 1:
        flags.add("allow_duplicate_host")

    # Content-Length leading zeros
    cl_val = _get_cl_value(wire)
    if cl_val and len(cl_val) > 1 and cl_val[0] == "0":
        flags.add("allow_cl_leading_zeros")

    # TE non-chunked
    te_val = _get_te_value(wire)
    if te_val:
        # TE: identity, or multiple TE values
        parts = [p.strip().lower() for p in te_val.split(",")]
        if any(p != "chunked" for p in parts):
            flags.add("allow_non_chunked_te")

    # Chunk extensions
    if _has_chunk_extensions(wire):
        flags.add("allow_chunk_extensions")

    # Check for prefix CRLF/LF before request line
    if wire[0:2] == b"\r\n" or wire[0:1] == b"\n":
        # Prefix newline before request line — bare LF covers this
        if wire[0:1] == b"\n":
            flags.add("allow_bare_lf")

    return flags


# ---------------------------------------------------------------------------
# Build expected structures
# ---------------------------------------------------------------------------
def build_expected_flagged_request(accepting_result: dict) -> dict:
    """Build expected_flagged from a successful oracle parse (request)."""
    body = accepting_result.get("body", b"")
    if isinstance(body, bytes):
        body_hex = body.hex()
    elif isinstance(body, str):
        body_hex = body.encode("latin-1", errors="replace").hex()
    else:
        body_hex = ""

    return {
        "behavior": "accept",
        "method": accepting_result.get("method", ""),
        "target": accepting_result.get("target", ""),
        "version": accepting_result.get("version", "1.1"),
        "headers": accepting_result.get("headers", []),
        "body_hex": body_hex,
    }


def build_expected_flagged_response(accepting_result: dict) -> dict:
    """Build expected_flagged from a successful oracle parse (response)."""
    body = accepting_result.get("body", b"")
    if isinstance(body, bytes):
        body_hex = body.hex()
    elif isinstance(body, str):
        body_hex = body.encode("latin-1", errors="replace").hex()
    else:
        body_hex = ""

    return {
        "behavior": "accept",
        "status_code": accepting_result.get("status_code", 0),
        "reason": accepting_result.get("reason", ""),
        "version": accepting_result.get("version", "1.1"),
        "headers": accepting_result.get("headers", []),
        "body_hex": body_hex,
    }


def build_expected_default_reject(flags: list[str]) -> dict:
    """Build expected_default reject dict. Uses first flag's reason."""
    reason = FLAG_TO_REASON.get(flags[0], "rejected in strict mode")
    return {"behavior": "reject", "reason": reason}


# ---------------------------------------------------------------------------
# Main triage logic
# ---------------------------------------------------------------------------
def main():
    stats = {
        "path1": 0,
        "path2": 0,
        "path3": 0,
        "total": 0,
    }
    path1_details = []
    path2_details = []
    path3_details = []

    for fpath in VECTOR_FILES:
        if not os.path.exists(fpath):
            continue

        with open(fpath) as f:
            vectors = json.load(f)

        modified = False
        for v in vectors:
            if v.get("deferred") != "HC-2":
                continue

            stats["total"] += 1
            vid = v["id"]
            wire = bytes.fromhex(v["input"]["wire_hex"])
            vector_type = v.get("type", "request")
            request_method = v.get("request_method", "GET")

            # Check if both oracles accept
            both_accept, h11_r, ht_r = check_oracles(
                wire, vector_type, request_method
            )

            if not both_accept:
                # Path 3: not both accepting — stays deferred
                stats["path3"] += 1
                path3_details.append(
                    f"  {vid}: oracles disagree "
                    f"(h11={'ok' if h11_r.get('error') is None else 'ERR'}, "
                    f"ht={'ok' if ht_r.get('error') is None else 'ERR'})"
                )
                continue

            # Both oracles accept — infer which flags are needed
            needed = infer_needed_flags(wire)

            # Use httptools result for expected_flagged (preserves original casing)
            ht_ok = ht_r.get("error") is None
            accepting = ht_r if ht_ok else h11_r

            if len(needed) == 1:
                # Path 1: exactly one flag
                flag = list(needed)[0]
                v.pop("deferred", None)
                v.pop("deferred_reason", None)
                v.pop("expected", None)
                v["mode_flag"] = flag
                v["expected_default"] = build_expected_default_reject([flag])
                if vector_type == "response":
                    v["expected_flagged"] = build_expected_flagged_response(accepting)
                else:
                    v["expected_flagged"] = build_expected_flagged_request(accepting)

                stats["path1"] += 1
                path1_details.append(f"  {vid}: mode_flag={flag}")
                modified = True

            elif len(needed) == 2:
                # Path 2: exactly two flags
                flag_list = sorted(needed)
                v.pop("deferred", None)
                v.pop("deferred_reason", None)
                v.pop("expected", None)
                v["mode_flags"] = flag_list
                v["expected_default"] = build_expected_default_reject(flag_list)
                if vector_type == "response":
                    v["expected_flagged"] = build_expected_flagged_response(accepting)
                else:
                    v["expected_flagged"] = build_expected_flagged_request(accepting)

                stats["path2"] += 1
                path2_details.append(f"  {vid}: mode_flags={flag_list}")
                modified = True

            else:
                # Path 3: 0 or 3+ flags needed — stays deferred
                stats["path3"] += 1
                path3_details.append(
                    f"  {vid}: both accept but need {len(needed)} flags: {sorted(needed)}"
                )

        if modified:
            with open(fpath, "w") as f:
                json.dump(vectors, f, indent=2, ensure_ascii=False)
                f.write("\n")
            print(f"  Wrote {fpath}")

    # Print summary
    print()
    print("=== Re-triage Results ===")
    print(f"Total HC-2 deferred vectors examined: {stats['total']}")
    print()

    print(f"Path 1 (single flag, un-deferred): {stats['path1']}")
    for d in path1_details:
        print(d)
    print()

    print(f"Path 2 (two flags, un-deferred): {stats['path2']}")
    for d in path2_details:
        print(d)
    print()

    print(f"Path 3 (stays deferred): {stats['path3']}")
    for d in path3_details:
        print(d)
    print()

    un_deferred = stats["path1"] + stats["path2"]
    print(f"Summary: {un_deferred} un-deferred, {stats['path3']} remain deferred")


if __name__ == "__main__":
    main()
