#!/usr/bin/env python3
"""Vector conversion pipeline for HC-1.

Fetches test fixtures from llhttp and AWS http-desync-guardian,
converts to our JSON format, validates against h11/httptools oracles,
and merges into existing vector files.

Usage:
    uv run conformance/scripts/convert_vectors.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Add scripts dir to path for oracle_helpers
sys.path.insert(0, str(Path(__file__).parent))
from oracle_helpers import parse_with_h11, parse_with_httptools

VECTORS_DIR = Path(__file__).parent.parent / "vectors"

# ── Counters for audit log ──────────────────────────────────────────
_stats = {
    "converted": 0,
    "skipped": 0,
    "oracle_disagree": 0,
    "errors": 0,
}


# ── 1. Fetch Sources ────────────────────────────────────────────────


def fetch_sources(tmpdir: str) -> tuple[str, str]:
    """Clone llhttp and aws repos into tmpdir. Returns (llhttp_dir, aws_dir)."""
    llhttp_dir = os.path.join(tmpdir, "llhttp")
    aws_dir = os.path.join(tmpdir, "aws")

    print("Cloning llhttp...")
    subprocess.run(
        ["git", "clone", "--depth=1", "https://github.com/nodejs/llhttp.git", llhttp_dir],
        capture_output=True,
        check=True,
    )
    print("Cloning http-desync-guardian...")
    subprocess.run(
        ["git", "clone", "--depth=1", "https://github.com/aws/http-desync-guardian.git", aws_dir],
        capture_output=True,
        check=True,
    )
    return llhttp_dir, aws_dir


# ── 2. Parse llhttp Markdown Fixtures ───────────────────────────────


def _slugify(s: str) -> str:
    """Convert a title string to a slug suitable for use in IDs."""
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s


def _http_block_to_bytes(http_block: str) -> bytes:
    """Convert the content of an ```http code block into raw wire bytes.

    The markdown stores \\r\\n as literal two-char sequences in the text,
    and uses actual newlines as line separators.  In the wire format:
      - Each line inside the block ends with CRLF.
      - A blank line at the end of the block represents the empty
        line separating headers from body (or the end of message).
      - Backslash-escaped \\t maps to the TAB character.
    """
    # The http block in llhttp tests uses real newlines for line breaks.
    # The format stores trailing blank lines to denote the empty CRLF CRLF
    # that terminates the headers section.
    lines = http_block.split("\n")

    # The markdown block typically ends with blank lines before the
    # closing ``` fence.  For a headers-only message like:
    #   "GET / HTTP/1.1\n Header: val\n\n\n"
    # split gives: ["GET / HTTP/1.1", "Header: val", "", "", ""]
    #
    # The llhttp convention is: TWO blank lines at the end represent
    # the CRLF CRLF sequence that terminates the headers.  But since
    # our loop appends \r\n to EACH line (including blank ones), we
    # need exactly ONE blank line to get the terminating \r\n\r\n:
    #   "Header: val" + \r\n  +  "" + \r\n  =  "Header: val\r\n\r\n"
    #
    # Strip all trailing empty lines, then add back exactly one.
    while lines and lines[-1] == "":
        lines = lines[:-1]
    lines.append("")

    raw = b""
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1

        # Handle escape sequences: \t -> TAB
        line = line.replace("\\t", "\t")

        # Check for line continuation: trailing \ means the next markdown
        # line is a continuation (no CRLF between them).  Handle \n\ at
        # end of line: replace \n with LF byte and consume the continuation.
        if line.endswith("\\"):
            # Strip the trailing backslash (continuation marker)
            line = line[:-1]
            # Replace \n and \r escape sequences
            line = line.replace("\\n", "\n")
            line = line.replace("\\r", "\r")
            raw += line.encode("utf-8")
            continue

        # Normal line: replace escape sequences and append CRLF
        line = line.replace("\\n", "\n")
        line = line.replace("\\r", "\r")
        raw += line.encode("utf-8") + b"\r\n"

    return raw


def _parse_log_block(log_text: str) -> dict:
    """Extract structured info from an llhttp log block.

    Returns a dict with keys: method, url, version, headers, body,
    error (None or error string), is_complete.
    """
    result = {
        "method": None,
        "url": None,
        "version": None,
        "headers": [],
        "body_parts": [],
        "error": None,
        "is_complete": False,
    }

    current_field = None

    for line in log_text.strip().split("\n"):
        line = line.strip()

        # span[method]="..."
        # Use greedy match (.*) then require closing " at end of
        # the span value.  The span is always the last thing on the
        # line, so match greedily to the final " on the line.
        m = re.search(r'span\[method\]="(.*)"$', line)
        if m:
            result["method"] = m.group(1)

        # span[url]="..."
        m = re.search(r'span\[url\]="(.*)"$', line)
        if m:
            result["url"] = m.group(1)

        # span[version]="..."
        m = re.search(r'span\[version\]="(.*)"$', line)
        if m:
            result["version"] = m.group(1)

        # span[header_field]="..."
        m = re.search(r'span\[header_field\]="(.*)"$', line)
        if m:
            current_field = m.group(1)

        # span[header_value]="..."
        m = re.search(r'span\[header_value\]="(.*)"$', line)
        if m:
            if current_field is not None:
                result["headers"].append([current_field, m.group(1)])
                current_field = None

        # span[body]="..."
        m = re.search(r'span\[body\]="(.*)"$', line)
        if m:
            result["body_parts"].append(m.group(1))

        # error code=N reason="..."
        m = re.search(r'error code=\d+\s+reason="(.*?)"', line)
        if m:
            result["error"] = m.group(1)

        # message complete
        if "message complete" in line:
            result["is_complete"] = True

    return result


def _parse_llhttp_md(filepath: str) -> list[dict]:
    """Parse a single llhttp markdown test file into vector dicts."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    basename = Path(filepath).stem
    vectors = []

    # Split into test cases by ## heading
    # Pattern: ## Title followed by optional text, then meta comment,
    # then http block, then log block.
    test_pattern = re.compile(
        r"^##[#]?\s+(.+?)$"          # Title (## or ###)
        r"(.*?)"                       # Description / commentary
        r"<!--\s*meta=(\{.*?\})\s*-->"  # Meta JSON
        r"(.*?)"                       # Gap
        r"```http\n(.*?)```"           # HTTP block
        r"\s*```log\n(.*?)```",        # Log block
        re.MULTILINE | re.DOTALL,
    )

    for m in test_pattern.finditer(content):
        title = m.group(1).strip()
        meta_str = m.group(3)
        http_block = m.group(5)
        log_block = m.group(6)

        try:
            meta = json.loads(meta_str)
        except json.JSONDecodeError:
            continue

        meta_type = meta.get("type", "")

        # Only process request types (skip response, etc.)
        if not meta_type.startswith("request"):
            continue

        # Determine if this is a "lenient" mode test
        is_lenient = "lenient" in meta_type

        # Build ID
        slug = _slugify(title)
        vector_id = f"llhttp-{basename}-{slug}"

        # Parse wire bytes and log
        wire_bytes = _http_block_to_bytes(http_block)
        log_info = _parse_log_block(log_block)

        # Build vector
        vector = {
            "id": vector_id,
            "category": _categorize_from_llhttp(basename, log_info),
            "rfc_section": _rfc_section_from_llhttp(basename),
            "description": f"llhttp: {title}",
            "input": {"wire_hex": wire_bytes.hex()},
        }

        if is_lenient:
            vector["notes"] = f"llhttp meta type: {meta_type} (lenient mode)"

        if meta.get("noScan"):
            vector.setdefault("notes", "")
            if vector["notes"]:
                vector["notes"] += "; "
            vector["notes"] += "noScan=true in llhttp"

        if log_info["error"]:
            # Don't include reason: llhttp error messages won't match
            # our Mojo parser's error strings. Store the original for
            # documentation in source_reason.
            vector["expected"] = {
                "behavior": "reject",
            }
            vector["source_reason"] = f"llhttp: {log_info['error']}"
        elif log_info["is_complete"] and log_info["method"]:
            body = "".join(log_info["body_parts"])
            # Use utf-8 for body encoding to handle any Unicode chars
            body_hex = body.encode("utf-8").hex() if body else ""
            vector["expected"] = {
                "behavior": "accept",
                "method": log_info["method"],
                "target": log_info["url"] or "/",
                "version": log_info["version"] or "1.1",
                "headers": log_info["headers"],
                "body_hex": body_hex,
            }
        else:
            # Incomplete or weird parse -- treat as reject
            vector["expected"] = {
                "behavior": "reject",
            }
            vector["source_reason"] = "llhttp: incomplete parse (no message complete)"

        vectors.append(vector)

    return vectors


def _categorize_from_llhttp(basename: str, log_info: dict) -> str:
    """Determine the category based on the llhttp file basename and content."""
    mapping = {
        "sample": "request-line",
        "method": "request-line",
        "uri": "request-line",
        "invalid": "request-line",
        "content-length": "content-length",
        "transfer-encoding": "chunked",
        "connection": "headers",
        "finish": "headers",
        "pipelining": "headers",
        "lenient-headers": "headers",
        "lenient-header-value-relaxed": "headers",
        "lenient-version": "request-line",
    }
    return mapping.get(basename, "headers")


def _rfc_section_from_llhttp(basename: str) -> str:
    """Determine the RFC section based on the llhttp file basename."""
    mapping = {
        "sample": "RFC 9112 \u00a73",
        "method": "RFC 9112 \u00a73",
        "uri": "RFC 9112 \u00a73.2",
        "invalid": "RFC 9112 \u00a73",
        "content-length": "RFC 9112 \u00a76.3",
        "transfer-encoding": "RFC 9112 \u00a76.1",
        "connection": "RFC 9112 \u00a79.6",
        "finish": "RFC 9112 \u00a73",
        "pipelining": "RFC 9112 \u00a79.3",
        "lenient-headers": "RFC 9112 \u00a75",
        "lenient-header-value-relaxed": "RFC 9112 \u00a75",
        "lenient-version": "RFC 9112 \u00a72.3",
    }
    return mapping.get(basename, "RFC 9112")


def parse_llhttp_fixtures(llhttp_dir: str) -> list[dict]:
    """Parse all llhttp/test/request/*.md files into vectors."""
    request_dir = os.path.join(llhttp_dir, "test", "request")
    vectors = []

    md_files = sorted(Path(request_dir).glob("*.md"))
    for md_file in md_files:
        file_vectors = _parse_llhttp_md(str(md_file))
        vectors.extend(file_vectors)

    return vectors


# ── 3. Parse AWS http-desync-guardian YAML ──────────────────────────


def _aws_case_to_wire_bytes(case: dict) -> bytes:
    """Reconstruct HTTP/1.1 wire bytes from an AWS test case dict.

    AWS test cases have: method, uri, version, headers (list of dicts
    with name/value).  We reconstruct the full HTTP request from these.
    """
    method = case.get("method", "GET")
    uri = case.get("uri", "/")
    version = case.get("version", "HTTP/1.1")

    # Request line
    request_line = f"{method} {uri} {version}\r\n"
    # Try latin-1 first (preserves raw bytes), fall back to utf-8 for
    # Unicode characters that appear in some AWS test URIs.
    try:
        wire = request_line.encode("latin-1")
    except UnicodeEncodeError:
        wire = request_line.encode("utf-8")

    # Headers
    headers = case.get("headers") or []
    for hdr in headers:
        name = hdr.get("name", "")
        value = str(hdr.get("value", ""))
        header_line = f"{name}: {value}\r\n"
        try:
            wire += header_line.encode("latin-1")
        except UnicodeEncodeError:
            wire += header_line.encode("utf-8")

    # End of headers
    wire += b"\r\n"
    return wire


def _aws_tier_to_severity(tier: str) -> str:
    """Map AWS tier classifications to our severity levels."""
    mapping = {
        "Severe": "severe",
        "Ambiguous": "ambiguous",
        "Acceptable": "acceptable",
        "Compliant": "compliant",
    }
    return mapping.get(tier, tier.lower())


def _aws_categorize(case: dict) -> tuple[str, str]:
    """Return (category, rfc_section) for an AWS test case."""
    headers = case.get("headers") or []
    header_names = [h.get("name", "").strip().lower() for h in headers]
    reason = case.get("expected", {}).get("reason", "")

    # Check for CL+TE smuggling
    has_cl = any("content-length" in n for n in header_names)
    has_te = any("transfer-encoding" in n for n in header_names)

    if has_cl and has_te:
        return "request-smuggling", "RFC 9112 \u00a76.1"

    if "ContentLength" in reason or "content-length" in reason.lower():
        return "content-length", "RFC 9112 \u00a76.3"

    if "TransferEncoding" in reason or "transfer-encoding" in reason.lower():
        return "chunked", "RFC 9112 \u00a76.1"

    if "Uri" in reason:
        return "request-line", "RFC 9112 \u00a73.2"

    if "Header" in reason or "header" in reason.lower():
        return "headers", "RFC 9112 \u00a75"

    if "Version" in reason:
        return "request-line", "RFC 9112 \u00a72.3"

    # Default
    return "headers", "RFC 9112 \u00a75"


def parse_aws_fixtures(aws_dir: str) -> list[dict]:
    """Parse AWS http-desync-guardian test YAML files into vectors."""
    import yaml

    tests_dir = os.path.join(aws_dir, "tests")
    vectors = []

    yaml_files = sorted(Path(tests_dir).glob("*.yaml"))
    for yaml_file in yaml_files:
        with open(yaml_file, "r", encoding="utf-8") as f:
            try:
                cases = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"  Warning: failed to parse {yaml_file.name}: {e}")
                continue

        if not isinstance(cases, list):
            continue

        for i, case in enumerate(cases):
            if not isinstance(case, dict):
                continue

            name = case.get("name", f"case-{i}")
            expected = case.get("expected", {})
            tier = expected.get("tier", "Unknown")
            reason = expected.get("reason", "")
            severity = _aws_tier_to_severity(tier)

            # Build ID
            slug = _slugify(name)
            # Truncate overly long slugs
            if len(slug) > 60:
                slug = slug[:60].rstrip("-")
            vector_id = f"aws-{yaml_file.stem}-{slug}"

            # Reconstruct wire bytes
            try:
                wire_bytes = _aws_case_to_wire_bytes(case)
            except Exception as e:
                print(f"  Warning: failed to build wire bytes for {vector_id}: {e}")
                continue

            category, rfc_section = _aws_categorize(case)

            vector = {
                "id": vector_id,
                "category": category,
                "rfc_section": rfc_section,
                "severity": severity,
                "description": f"AWS desync: {name}",
                "input": {"wire_hex": wire_bytes.hex()},
            }

            # For severe/ambiguous -> reject; otherwise validate with oracles.
            # Don't include reason: AWS reason strings won't match our
            # Mojo parser's error messages. Store original for docs.
            vector["source_reason"] = f"AWS tier={tier}: {reason}"
            # Add notes for ambiguous vectors (required by security test)
            if severity == "ambiguous":
                vector["notes"] = f"Auto-converted from AWS http-desync-guardian ({tier}/{reason}). Strict parser rejects this as defense-in-depth."
            if severity in ("severe", "ambiguous"):
                vector["expected"] = {
                    "behavior": "reject",
                }
            else:
                # For acceptable/compliant, we validate against oracles below;
                # start with an "accept" expectation based on the wire bytes
                # that we'll refine in validate_vector.
                vector["expected"] = {
                    "behavior": "accept",
                }

            vectors.append(vector)

    return vectors


# ── 4. Validate Against Oracles ─────────────────────────────────────


def _extract_headers_from_wire(wire_hex: str) -> list[list[str]]:
    """Parse header names and values directly from wire bytes.

    This preserves the original casing of header names, unlike h11
    which lowercases them.
    """
    wire = bytes.fromhex(wire_hex)
    headers = []
    # Find end of request line
    idx = wire.find(b"\r\n")
    if idx < 0:
        return headers
    pos = idx + 2
    while pos < len(wire):
        end = wire.find(b"\r\n", pos)
        if end < 0:
            break
        line = wire[pos:end]
        if not line:
            break  # Empty line = end of headers
        colon = line.find(b":")
        if colon > 0:
            name = line[:colon].decode("ascii", errors="replace")
            value = line[colon + 1:].decode("ascii", errors="replace").strip()
            headers.append([name, value])
        pos = end + 2
    return headers


def _fill_accept_from_oracle(
    vector: dict,
    h11_result: dict,
    ht_result: dict,
) -> None:
    """Fill in accept fields from oracle parse results.

    Prefers httptools for header names (preserves original casing).
    When falling back to h11 (which lowercases header names), we
    extract header names from the wire bytes to preserve casing.
    """
    expected = vector["expected"]
    if expected.get("method"):
        return  # Already filled in (llhttp vectors)

    ht_ok = ht_result.get("error") is None
    h11_ok = h11_result.get("error") is None

    if ht_ok:
        # httptools preserves original casing -- use it
        primary = ht_result
        expected["headers"] = primary.get("headers", [])
    elif h11_ok:
        # h11 lowercases header names -- extract from wire instead
        primary = h11_result
        expected["headers"] = _extract_headers_from_wire(
            vector["input"]["wire_hex"]
        )
    else:
        return  # Neither oracle succeeded

    expected["method"] = primary.get("method", "GET")
    expected["target"] = primary.get("target", "/")
    ver = primary.get("version", "1.1")
    if ver and not isinstance(ver, str):
        ver = str(ver)
    expected["version"] = ver or "1.1"
    body = primary.get("body", b"")
    if isinstance(body, bytes):
        expected["body_hex"] = body.hex()
    else:
        expected["body_hex"] = ""


def validate_vector(vector: dict) -> tuple[str, str, str]:
    """Validate a vector against h11 and httptools oracles.

    Returns (status, h11_verdict, ht_verdict) where status is
    'OK', 'REVIEW', or 'ERROR'.
    """
    wire_hex = vector["input"]["wire_hex"]
    wire_bytes = bytes.fromhex(wire_hex)

    h11_result = parse_with_h11(wire_bytes)
    ht_result = parse_with_httptools(wire_bytes)

    h11_accepts = h11_result.get("error") is None
    ht_accepts = ht_result.get("error") is None

    expected_behavior = vector.get("expected", {}).get("behavior", "accept")
    vector_accepts = expected_behavior == "accept"

    h11_str = "accept" if h11_accepts else "reject"
    ht_str = "accept" if ht_accepts else "reject"

    # For accept vectors without parsed details, fill from oracle
    if vector_accepts and not vector["expected"].get("method"):
        _fill_accept_from_oracle(vector, h11_result, ht_result)

    # Both agree with vector
    if h11_accepts == vector_accepts and ht_accepts == vector_accepts:
        return "OK", h11_str, ht_str

    # Oracles disagree with each other.  Use the original source's
    # expectation as a tiebreaker when at least one oracle agrees
    # with it.  This works because:
    #  - If source says reject and one oracle rejects: likely correct
    #  - If source says accept and one oracle accepts: fill details
    #    from the accepting oracle
    if h11_accepts != ht_accepts:
        vector["oracle_disagreement"] = True

        # Check if original expectation aligns with at least one oracle
        source_has_ally = (
            (vector_accepts and (h11_accepts or ht_accepts))
            or (not vector_accepts and (not h11_accepts or not ht_accepts))
        )

        if source_has_ally:
            # Trust the original source expectation
            if vector_accepts:
                vector["expected"] = {"behavior": "accept"}
                _fill_accept_from_oracle(vector, h11_result, ht_result)
            # else: keep reject (already set)
        else:
            # No oracle agrees with source -- shouldn't happen when
            # oracles disagree with each other and source takes a side.
            # Fall back to reject (strict)
            vector["expected"] = {"behavior": "reject"}

        return "REVIEW", h11_str, ht_str

    # Both oracles disagree with vector -- trust the oracles and
    # auto-correct the expected behavior.  The llhttp/AWS expectation
    # reflects their specific parser policies (e.g. llhttp rejects
    # unknown HTTP methods, AWS "acceptable" allows non-compliant
    # headers), whereas our conformance goal aligns with what strict
    # RFC-based parsers (h11, httptools) do.
    if h11_accepts:
        # Both oracles accept, but vector said reject -> flip to accept
        vector["expected"] = {"behavior": "accept"}
        _fill_accept_from_oracle(vector, h11_result, ht_result)
        vector["auto_corrected"] = "source said reject, both oracles accept"
    else:
        # Both oracles reject, but vector said accept -> flip to reject
        vector["expected"] = {"behavior": "reject"}
        vector["auto_corrected"] = "source said accept, both oracles reject"

    return "CORRECTED", h11_str, ht_str


# ── 5. Categorize into target files ─────────────────────────────────


def categorize_vector(vector: dict) -> str:
    """Return the relative path under VECTORS_DIR for this vector."""
    cat = vector.get("category", "")
    severity = vector.get("severity", "")

    # Build a combined text for keyword matching (description + source_reason)
    text_lower = (
        vector.get("description", "")
        + " "
        + vector.get("source_reason", "")
    ).lower()

    # Security vectors
    if cat == "request-smuggling":
        if "content-length" in text_lower and "transfer-encoding" in text_lower:
            return "security/smuggling_cl_te.json"
        if "transfer-encoding" in text_lower or "te " in text_lower:
            return "security/smuggling_te.json"
        return "security/smuggling_cl_te.json"

    if cat == "header-injection" or severity == "severe":
        if "content-length" in text_lower:
            return "security/smuggling_cl_te.json"
        if "transfer-encoding" in text_lower:
            return "security/smuggling_te.json"
        return "security/header_injection.json"

    # RFC9112 vectors
    if cat == "request-line":
        return "rfc9112/request_line.json"
    if cat == "content-length":
        return "rfc9112/content_length.json"
    if cat == "chunked":
        return "rfc9112/chunked.json"
    if cat == "host":
        return "rfc9112/host.json"

    # Default: headers
    return "rfc9112/headers.json"


# ── 6. Merge vectors ────────────────────────────────────────────────


def merge_vectors(new_vectors: list[dict], target_file: Path) -> int:
    """Merge new vectors into an existing JSON file. Returns count added."""
    existing = []
    if target_file.exists():
        with open(target_file, "r", encoding="utf-8") as f:
            existing = json.load(f)

    existing_ids = {v["id"] for v in existing}
    added = 0

    for v in new_vectors:
        if v["id"] not in existing_ids:
            existing.append(v)
            existing_ids.add(v["id"])
            added += 1

    if added > 0:
        target_file.parent.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
            f.write("\n")

    return added


# ── 7. Main pipeline ────────────────────────────────────────────────


def _collect_existing_ids() -> set[str]:
    """Walk all existing JSON vector files and collect their IDs."""
    ids = set()
    for json_file in VECTORS_DIR.rglob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                vectors = json.load(f)
            for v in vectors:
                if "id" in v:
                    ids.add(v["id"])
        except (json.JSONDecodeError, KeyError):
            pass
    return ids


def main():
    tmpdir = tempfile.mkdtemp(prefix="hc1-vectors-")
    print(f"Working in {tmpdir}\n")

    # 1. Fetch
    llhttp_dir, aws_dir = fetch_sources(tmpdir)

    # 2. Parse llhttp
    print("\n=== llhttp conversion ===")
    llhttp_vectors = parse_llhttp_fixtures(llhttp_dir)
    print(f"  Parsed {len(llhttp_vectors)} vectors from llhttp\n")

    # 3. Parse AWS
    print("=== AWS conversion ===")
    aws_vectors = parse_aws_fixtures(aws_dir)
    print(f"  Parsed {len(aws_vectors)} vectors from AWS\n")

    # Get existing IDs so we know what to skip
    existing_ids = _collect_existing_ids()

    # 4. Validate and categorize
    # Group vectors by target file
    file_groups: dict[str, list[dict]] = {}

    all_vectors = llhttp_vectors + aws_vectors
    print("=== Validation ===")

    for vector in all_vectors:
        vid = vector["id"]

        if vid in existing_ids:
            _stats["skipped"] += 1
            continue

        # Validate against oracles
        status, h11_v, ht_v = validate_vector(vector)
        target = categorize_vector(vector)

        tag = f"[{status}]"
        pad = " " * max(1, 12 - len(tag))
        print(f"{tag}{pad}{vid} -> {target} (h11: {h11_v}, httptools: {ht_v})")

        if status == "OK":
            _stats["converted"] += 1
        elif status == "REVIEW":
            _stats["oracle_disagree"] += 1
            _stats["converted"] += 1
        elif status == "CORRECTED":
            _stats["errors"] += 1
            _stats["converted"] += 1

        file_groups.setdefault(target, []).append(vector)

    # 5. Merge
    print("\n=== Merging ===")
    total_added = 0
    for target_path, vectors in sorted(file_groups.items()):
        full_path = VECTORS_DIR / target_path
        added = merge_vectors(vectors, full_path)
        total_added += added
        print(f"  {target_path}: +{added} vectors (total in file: {added + (len(vectors) - added)} skipped)")

    # 6. Summary
    print(f"\n=== Summary ===")
    print(f"Converted: {_stats['converted']} new vectors")
    print(f"Skipped (already exist): {_stats['skipped']}")
    print(f"Oracle disagreements: {_stats['oracle_disagree']}")
    print(f"Errors: {_stats['errors']}")
    print(f"Total added to files: {total_added}")


if __name__ == "__main__":
    main()
