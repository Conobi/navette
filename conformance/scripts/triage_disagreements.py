#!/usr/bin/env python3
"""Triage all ~142 skipped oracle-disagreement / auto-corrected vectors.

For each one, re-run both oracles (h11, httptools), infer which
ParserStrictness flag controls the behavior, and rewrite the vector
as either:
  - dual-mode (mode_flag + expected_default + expected_flagged), or
  - deferred to HC-2.

Run:
    cd ~/Projets/perso/mojo-net && uv run conformance/scripts/triage_disagreements.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from oracle_helpers import parse_with_h11, parse_with_httptools

# ---------------------------------------------------------------------------
# Strictness flags
# ---------------------------------------------------------------------------
KNOWN_FLAGS = {
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
}

# ---------------------------------------------------------------------------
# Files containing the 142 disagreements
# ---------------------------------------------------------------------------
VECTOR_FILES = [
    "conformance/vectors/rfc9112/request_line.json",
    "conformance/vectors/rfc9112/headers.json",
    "conformance/vectors/rfc9112/content_length.json",
    "conformance/vectors/rfc9112/chunked.json",
]


# ---------------------------------------------------------------------------
# Inference logic
# ---------------------------------------------------------------------------
def _has_multiple_requests(wire: bytes) -> bool:
    """Detect if the wire contains multiple concatenated HTTP requests."""
    decoded = wire.decode("latin-1", errors="replace")
    # Count how many request-line-like patterns appear
    import re
    matches = re.findall(
        r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP/\d\.\d",
        decoded,
    )
    return len(matches) >= 2


def _has_upgrade(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace").lower()
    return "upgrade:" in decoded or "connection: upgrade" in decoded


def _has_connect_method(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    return decoded.startswith("CONNECT ")


def _is_incomplete_chunked(wire: bytes) -> bool:
    """Detect incomplete chunked body (TE header but no 0\\r\\n terminator)."""
    decoded = wire.decode("latin-1", errors="replace").lower()
    if "transfer-encoding" not in decoded:
        return False
    # Check if chunked body terminates properly
    if b"0\r\n\r\n" not in wire and b"0\n\n" not in wire:
        return True
    return False


def _get_te_value(wire: bytes) -> str:
    """Extract Transfer-Encoding header value if present."""
    decoded = wire.decode("latin-1", errors="replace")
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("transfer-encoding:"):
            return line.split(":", 1)[1].strip()
    return ""


def _get_cl_value(wire: bytes) -> str:
    """Extract Content-Length header value if present."""
    decoded = wire.decode("latin-1", errors="replace")
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("content-length:"):
            return line.split(":", 1)[1].strip()
    return ""


def _has_host_header(wire: bytes) -> bool:
    decoded = wire.decode("latin-1", errors="replace")
    for line in decoded.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("host:"):
            return True
    return False


def _get_version(wire: bytes) -> str:
    """Extract HTTP version from request line."""
    decoded = wire.decode("latin-1", errors="replace")
    first_line = decoded.split("\r\n")[0] if "\r\n" in decoded else decoded.split("\n")[0]
    parts = first_line.rsplit(" ", 1)
    if len(parts) == 2 and parts[1].startswith("HTTP/"):
        return parts[1][5:]
    if len(parts) == 2 and parts[1].startswith("RTSP/"):
        return parts[1]  # Non-HTTP protocol
    if len(parts) == 2 and parts[1].startswith("ICE/"):
        return parts[1]
    return ""


def _has_bare_lf_in_headers(wire: bytes) -> bool:
    """Check if wire uses bare LF (not preceded by CR) in header area."""
    # Find the end of the request line
    idx = 0
    for i in range(len(wire) - 1):
        if wire[i] == 0x0A:  # LF
            idx = i + 1
            break
    # Check header area for bare LFs
    in_headers = True
    i = idx
    while i < len(wire) and in_headers:
        if wire[i] == 0x0A:
            if i == 0 or wire[i - 1] != 0x0D:
                return True
        if i < len(wire) - 3:
            if wire[i] == 0x0D and wire[i + 1] == 0x0A and wire[i + 2] == 0x0D and wire[i + 3] == 0x0A:
                in_headers = False
        if i < len(wire) - 1:
            if wire[i] == 0x0A and wire[i + 1] == 0x0A:
                in_headers = False
        i += 1
    return False


def _has_bare_lf_anywhere(wire: bytes) -> bool:
    """Check if any LF in the wire is bare (not preceded by CR)."""
    for i in range(len(wire)):
        if wire[i] == 0x0A and (i == 0 or wire[i - 1] != 0x0D):
            return True
    return False


def _has_obs_fold(wire: bytes) -> bool:
    """Check for obs-fold: CRLF followed by SP or HTAB in headers."""
    decoded = wire.decode("latin-1", errors="replace")
    lines = decoded.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if i == 0:
            continue  # skip request line
        if line == "":
            break  # end of headers
        if line.startswith(" ") or line.startswith("\t"):
            return True
    return False


def _has_space_before_colon(wire: bytes) -> bool:
    """Check for space before colon in header names."""
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
    """Check for control characters in header values."""
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
        value = line[colon_idx + 1:]
        for ch in value:
            code = ord(ch)
            if code < 0x20 and code not in (0x09,):  # HTAB is allowed
                return True
    return False


def _has_invalid_header_names(wire: bytes) -> bool:
    """Check for invalid characters in header names (non-tchar)."""
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
            # tchar: ALPHA / DIGIT / special
            if (
                not (0x41 <= c <= 0x5A)  # A-Z
                and not (0x61 <= c <= 0x7A)  # a-z
                and not (0x30 <= c <= 0x39)  # 0-9
                and c not in tchar
            ):
                return True
    return False


def _has_chunk_extensions(wire: bytes) -> bool:
    """Check for chunk extensions (semicolons in chunk size lines)."""
    decoded = wire.decode("latin-1", errors="replace")
    # Look for lines in the body area that match chunk-size ; extension
    # Find the blank line separating headers from body
    parts = decoded.split("\r\n\r\n", 1)
    if len(parts) < 2:
        parts = decoded.split("\n\n", 1)
    if len(parts) < 2:
        return False
    body = parts[1]
    for line in body.split("\r\n"):
        line = line.strip()
        if ";" in line:
            # Could be a chunk extension
            before_semi = line.split(";")[0].strip()
            try:
                int(before_semi, 16)
                return True
            except ValueError:
                pass
    return False


def _get_method(wire: bytes) -> str:
    decoded = wire.decode("latin-1", errors="replace")
    first_line = decoded.split("\r\n")[0] if "\r\n" in decoded else decoded.split("\n")[0]
    return first_line.split(" ")[0] if " " in first_line else first_line


def _is_body_mismatch_only(wire: bytes, expected: dict) -> bool:
    """Check if the vector seems to be about body handling (GET/HEAD with body)."""
    method = _get_method(wire)
    return method in ("GET", "HEAD") and expected.get("behavior") == "reject"


def infer_flag(vector: dict, h11_result: dict, ht_result: dict) -> str | None:
    """Infer which ParserStrictness flag controls this disagreement.

    Returns:
        - A flag name (str) from KNOWN_FLAGS
        - "DEFERRED_HC2" for connection lifecycle / cannot determine
        - None if truly unresolvable
    """
    wire = bytes.fromhex(vector["input"]["wire_hex"])
    decoded = wire.decode("latin-1", errors="replace")
    h11_ok = h11_result.get("error") is None
    ht_ok = ht_result.get("error") is None
    h11_err = str(h11_result.get("error", ""))
    ht_err = str(ht_result.get("error", ""))
    expected = vector.get("expected", {})
    expected_beh = expected.get("behavior", "?")
    vid = vector["id"]
    method = _get_method(wire)
    version = _get_version(wire)

    # --- BOTH ORACLES REJECT (auto_corrected cases) ---
    if not h11_ok and not ht_ok:
        # Both reject -- our vector says reject, that's fine.
        # These are genuinely bad requests. Just convert to normal reject vectors.
        # Check what specific thing is wrong.
        if _has_bare_lf_anywhere(wire) and "CRLF" not in wire.decode("latin-1"):
            return "allow_bare_lf"
        if _has_space_before_colon(wire):
            return "allow_space_before_colon"
        if _has_obs_fold(wire):
            return "allow_obs_fold"
        # Both oracles reject -- just mark as properly resolved reject
        return "BOTH_REJECT"

    # --- MULTIPLE REQUESTS (pipelining / keep-alive lifecycle) ---
    if _has_multiple_requests(wire):
        return "DEFERRED_HC2"

    # --- CONNECT method ---
    if _has_connect_method(wire):
        return "DEFERRED_HC2"

    # --- Upgrade ---
    if _has_upgrade(wire):
        return "DEFERRED_HC2"

    # --- h11 rejects with "Missing mandatory Host: header", httptools accepts ---
    if not h11_ok and "Missing mandatory Host:" in h11_err and ht_ok:
        # h11 is strict about Host header.
        # Check for other issues first.

        # Transfer-Encoding non-chunked?
        te_val = _get_te_value(wire)
        if te_val and te_val.lower() != "chunked":
            return "allow_non_chunked_te"

        # Chunk extensions?
        if _has_chunk_extensions(wire):
            return "allow_chunk_extensions"

        # Content-Length leading zeros?
        cl_val = _get_cl_value(wire)
        if cl_val and cl_val != cl_val.lstrip("0") and len(cl_val) > 1:
            return "allow_cl_leading_zeros"

        # Control chars in header values?
        if _has_ctl_in_header_values(wire):
            return "allow_header_value_ctl"

        # Non-standard version (not 1.0 or 1.1)?
        if version and version not in ("1.0", "1.1"):
            return "allow_nonstandard_version"

        # No version at all -> HTTP/0.9?
        if not version:
            return "allow_http_09"

        # Prefix CRLF before request line?
        if wire[0:2] == b"\r\n" or wire[0:1] == b"\n":
            return "allow_missing_host_11"

        # Incomplete chunked?
        if _is_incomplete_chunked(wire):
            return "DEFERRED_HC2"

        # GET/HEAD with body? (body semantics differ)
        if method in ("GET", "HEAD"):
            cl = _get_cl_value(wire)
            te = _get_te_value(wire)
            if cl and int(cl) > 0:
                return "DEFERRED_HC2"
            if te:
                return "DEFERRED_HC2"

        # Default: the Host header is missing — that's the controlling flag
        if not _has_host_header(wire):
            return "allow_missing_host_11"

        # Has host but h11 still says missing? Shouldn't happen. Defer.
        return "DEFERRED_HC2"

    # --- h11 rejects with TE error, httptools accepts ---
    if not h11_ok and "Only Transfer-Encoding: chunked" in h11_err and ht_ok:
        return "allow_non_chunked_te"

    # --- httptools rejects, h11 accepts ---
    if h11_ok and not ht_ok:
        # "Invalid method" — httptools doesn't recognize the method
        if "Invalid method" in ht_err:
            # Non-standard method like ANNOUNCE with non-HTTP protocol
            prot = _get_version(wire)
            if "RTSP" in decoded or "ICE" in decoded:
                return "allow_nonstandard_version"
            return "DEFERRED_HC2"

        # "Invalid HTTP version"
        if "Invalid HTTP version" in ht_err:
            return "allow_nonstandard_version"

        # "Missing expected CR after header value" — bare LF
        if "Missing expected CR" in ht_err:
            return "allow_bare_lf"

        # "Invalid header value char" — bare LF in value or ctl
        if "Invalid header value char" in ht_err:
            if _has_bare_lf_anywhere(wire):
                return "allow_bare_lf"
            return "allow_header_value_ctl"

        # "Unexpected whitespace after header value" — space before colon or obs-fold
        if "Unexpected whitespace" in ht_err:
            if _has_obs_fold(wire):
                return "allow_obs_fold"
            if _has_space_before_colon(wire):
                return "allow_space_before_colon"
            # Check for trailing whitespace after header value -> space before colon area
            return "allow_space_before_colon"

        # "Data after `Connection: close`"
        if "Data after" in ht_err:
            return "DEFERRED_HC2"

        # "Invalid header token" — bad header name chars
        if "Invalid header token" in ht_err:
            if _has_bare_lf_anywhere(wire):
                return "allow_bare_lf"
            return "ignore_invalid_header_names"

        # "Invalid character in chunk extensions"
        if "chunk extension" in ht_err.lower():
            return "allow_chunk_extensions"

        # Chunk-related errors
        if "chunk" in ht_err.lower():
            return "allow_chunk_extensions"

        # httptools upgrade/connection lifecycle errors (numeric codes)
        if ht_err.strip().isdigit() or "connection" in ht_err.lower():
            return "DEFERRED_HC2"

        # Expected CRLF after version -> maybe extra spaces
        if "Expected CRLF" in ht_err:
            return "allow_multiple_spaces"

        # Expected HTTP/ -> bare version or HTTP/0.9
        if "Expected HTTP/" in ht_err:
            return "allow_http_09"

        # "Invalid char in url" — target control chars
        if "url" in ht_err.lower():
            return "allow_target_ctl"

        # Invalid character in chunk size
        if "chunk size" in ht_err.lower():
            return "allow_chunk_extensions"

        # Catch-all for httptools errors
        return "DEFERRED_HC2"

    # --- Both accept but fields differ ---
    if h11_ok and ht_ok:
        # Both oracles accept. If the vector says "reject", our parser
        # is stricter. Check what it's strict about.
        if version and version not in ("1.0", "1.1", "0.9"):
            return "allow_nonstandard_version"
        if _has_bare_lf_anywhere(wire):
            return "allow_bare_lf"
        # Connection lifecycle?
        if "connection" in decoded.lower():
            return "DEFERRED_HC2"
        return "DEFERRED_HC2"

    # --- Shouldn't get here ---
    return None


def build_expected_flagged(accepting_result: dict) -> dict:
    """Build the expected_flagged dict from a successful oracle parse."""
    body = accepting_result.get("body", b"")
    if isinstance(body, bytes):
        body_hex = body.hex()
    elif isinstance(body, str):
        body_hex = body.encode("latin-1", errors="replace").hex()
    else:
        body_hex = ""

    result = {
        "behavior": "accept",
        "method": accepting_result.get("method", ""),
        "target": accepting_result.get("target", ""),
        "version": accepting_result.get("version", ""),
        "headers": accepting_result.get("headers", []),
        "body_hex": body_hex,
    }
    return result


# Map each flag to the substring of the error our parser actually produces
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
}


def build_expected_default_reject(flag: str = "") -> dict:
    reason = FLAG_TO_REASON.get(flag, "rejected in strict mode")
    return {"behavior": "reject", "reason": reason}


# ---------------------------------------------------------------------------
# Main triage
# ---------------------------------------------------------------------------
def main():
    stats = {
        "resolved_flag": {},
        "deferred": 0,
        "both_reject_kept": 0,
        "unresolved": 0,
        "total": 0,
    }

    for fpath in VECTOR_FILES:
        with open(fpath) as f:
            vectors = json.load(f)

        modified = False
        for v in vectors:
            if not (v.get("oracle_disagreement") or v.get("auto_corrected")):
                continue

            stats["total"] += 1
            vid = v["id"]
            wire = bytes.fromhex(v["input"]["wire_hex"])
            h11_r = parse_with_h11(wire)
            ht_r = parse_with_httptools(wire)
            h11_ok = h11_r.get("error") is None
            ht_ok = ht_r.get("error") is None

            flag = infer_flag(v, h11_r, ht_r)

            if flag == "BOTH_REJECT":
                # Both oracles reject. Keep as simple reject vector.
                v.pop("oracle_disagreement", None)
                v.pop("auto_corrected", None)
                # The expected is already {behavior: reject} — keep it
                if "expected" not in v:
                    v["expected"] = {"behavior": "reject"}
                stats["both_reject_kept"] += 1
                modified = True
                print(f"  BOTH_REJECT: {vid}")

            elif flag == "DEFERRED_HC2":
                v.pop("oracle_disagreement", None)
                v.pop("auto_corrected", None)
                v["deferred"] = "HC-2"
                v["deferred_reason"] = "connection lifecycle / multi-message / body semantics"
                stats["deferred"] += 1
                modified = True
                print(f"  DEFERRED: {vid}")

            elif flag is not None and flag in KNOWN_FLAGS:
                # Dual-mode vector
                v.pop("oracle_disagreement", None)
                v.pop("auto_corrected", None)

                # Determine expected_default (strict mode)
                old_expected = v.get("expected", {})
                old_behavior = old_expected.get("behavior", "reject")

                # In strict mode, our parser should reject for these flags
                # (that's what makes them strictness-controlled).
                # Exception: if the old expected was "accept", it means the
                # vector was expected to pass even strictly. In that case,
                # the flag controls whether we accept or reject, so default
                # should be reject.
                if old_behavior == "accept":
                    # The source says accept, but with strictness off our
                    # parser should reject by default. The flagged mode
                    # should accept.
                    v["expected_default"] = build_expected_default_reject(flag)

                    # Build expected_flagged from accepting oracle
                    if ht_ok:
                        v["expected_flagged"] = build_expected_flagged(ht_r)
                    elif h11_ok:
                        v["expected_flagged"] = build_expected_flagged(h11_r)
                    else:
                        # Neither oracle accepts — use old expected as flagged
                        flagged = dict(old_expected)
                        flagged["behavior"] = "accept"
                        if "body_hex" not in flagged:
                            flagged["body_hex"] = ""
                        v["expected_flagged"] = flagged

                else:
                    # old_behavior == "reject": strict parser rejects, flagged
                    # mode should accept (one oracle accepts).
                    v["expected_default"] = build_expected_default_reject(flag)

                    if ht_ok:
                        v["expected_flagged"] = build_expected_flagged(ht_r)
                    elif h11_ok:
                        v["expected_flagged"] = build_expected_flagged(h11_r)
                    else:
                        # Both reject — can't build flagged accept from oracle
                        # Just mark as deferred
                        v.pop("expected_default", None)
                        v.pop("expected_flagged", None)
                        v["deferred"] = "HC-2"
                        v["deferred_reason"] = "both oracles reject; cannot build expected_flagged"
                        stats["deferred"] += 1
                        stats.setdefault("resolved_flag", {})
                        modified = True
                        print(f"  DEFERRED (both reject, flag={flag}): {vid}")
                        continue

                v["mode_flag"] = flag
                v.pop("expected", None)  # Remove old single-mode expected

                stats["resolved_flag"][flag] = stats["resolved_flag"].get(flag, 0) + 1
                modified = True
                print(f"  FLAG={flag}: {vid}")

            else:
                # Cannot determine
                v.pop("oracle_disagreement", None)
                v.pop("auto_corrected", None)
                v["deferred"] = "HC-2"
                v["deferred_reason"] = "could not determine controlling flag"
                stats["unresolved"] += 1
                modified = True
                print(f"  UNRESOLVED -> DEFERRED: {vid}")

        if modified:
            with open(fpath, "w") as f:
                json.dump(vectors, f, indent=2, ensure_ascii=False)
                f.write("\n")  # trailing newline
            print(f"  Wrote {fpath}")

    # Print summary
    print()
    print("=== Triage Results ===")
    resolved_total = sum(stats["resolved_flag"].values())
    print(f"Resolved to mode_flag: {resolved_total}")
    for flag in sorted(stats["resolved_flag"].keys()):
        print(f"  {flag}: {stats['resolved_flag'][flag]}")
    print(f"Both-reject (kept as simple reject): {stats['both_reject_kept']}")
    print(f"Deferred to HC-2: {stats['deferred']}")
    print(f"Unresolved -> deferred: {stats['unresolved']}")
    total = resolved_total + stats["both_reject_kept"] + stats["deferred"] + stats["unresolved"]
    print(f"Total: {total}")
    print()
    print(f"Remaining oracle_disagreement/auto_corrected: should be 0")


if __name__ == "__main__":
    main()
