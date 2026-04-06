#!/usr/bin/env python3
"""Convert http2-frame-test-case vectors to our format.

Clones the http2jp/http2-frame-test-case repo, converts each JSON
test vector to our conformance format, validates accept vectors
against hyperframe, and merges into conformance/vectors/rfc9113/.

Usage:
    uv run conformance/scripts/convert_h2_vectors.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────────

REPO_URL = "https://github.com/http2jp/http2-frame-test-case.git"

VECTORS_DIR = Path(__file__).parent.parent / "vectors" / "rfc9113"

# Frame type directory name -> output file
TYPE_TO_FILE = {
    "data": "frame_data.json",
    "headers": "frame_headers.json",
    "priority": "frame_priority.json",
    "rst_stream": "frame_rst_stream.json",
    "settings": "frame_settings.json",
    "push_promise": "frame_push_promise.json",
    "ping": "frame_ping.json",
    "goaway": "frame_goaway.json",
    "window_update": "frame_window_update.json",
    "continuation": "frame_continuation.json",
}

# Frame type directory name -> RFC section
RFC_SECTION = {
    "data": "RFC 9113 §6.1",
    "headers": "RFC 9113 §6.2",
    "priority": "RFC 9113 §6.3",
    "rst_stream": "RFC 9113 §6.4",
    "settings": "RFC 9113 §6.5",
    "push_promise": "RFC 9113 §6.6",
    "ping": "RFC 9113 §6.7",
    "goaway": "RFC 9113 §6.8",
    "window_update": "RFC 9113 §6.9",
    "continuation": "RFC 9113 §6.10",
}

# HTTP/2 error code number -> name (RFC 9113 §7)
ERROR_CODE_NAME = {
    0: "NO_ERROR",
    1: "PROTOCOL_ERROR",
    2: "INTERNAL_ERROR",
    3: "FLOW_CONTROL_ERROR",
    4: "SETTINGS_TIMEOUT",
    5: "STREAM_CLOSED",
    6: "FRAME_SIZE_ERROR",
    7: "REFUSED_STREAM",
    8: "CANCEL",
    9: "COMPRESSION_ERROR",
    10: "CONNECT_ERROR",
    11: "ENHANCE_YOUR_CALM",
    12: "INADEQUATE_SECURITY",
    13: "HTTP_1_1_REQUIRED",
}

# HTTP/2 frame type number -> directory name (for error scope lookup)
FRAME_TYPE_NAME = {
    0: "data",
    1: "headers",
    2: "priority",
    3: "rst_stream",
    4: "settings",
    5: "push_promise",
    6: "ping",
    7: "goaway",
    8: "window_update",
    9: "continuation",
}

# ── Counters ───────────────────────────────────────────────────────────

_stats = {
    "converted": 0,
    "skipped_existing": 0,
    "hyperframe_ok": 0,
    "hyperframe_mismatch": 0,
    "hyperframe_error": 0,
    "errors": 0,
}


# ── Helpers ────────────────────────────────────────────────────────────


def _slugify(s: str) -> str:
    """Convert a description string to a slug suitable for IDs."""
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s


def _error_scope(error_codes: list[int], wire_hex: str) -> str:
    """Determine whether the error targets the connection or stream.

    Per RFC 9113:
    - FRAME_SIZE_ERROR (6) on a PRIORITY frame (type 2) is a stream error
    - Everything else is a connection error
    """
    wire = bytes.fromhex(wire_hex)
    if len(wire) >= 4:
        frame_type = wire[3]
    else:
        frame_type = -1

    if 6 in error_codes and frame_type == 2:
        return "stream"
    return "connection"


def _error_reason(error_codes: list[int]) -> str:
    """Build a human-readable reason string from numeric error codes."""
    names = [ERROR_CODE_NAME.get(c, f"UNKNOWN({c})") for c in error_codes]
    return ", ".join(names)


def _payload_hex(wire_hex: str, length: int) -> str:
    """Extract the payload hex from wire bytes (everything after 9-byte header)."""
    # The 9-byte frame header is 18 hex chars
    return wire_hex[18:18 + length * 2].lower()


# ── Hyperframe validation ──────────────────────────────────────────────


def validate_with_hyperframe(wire_hex: str) -> dict:
    """Decode a frame with hyperframe and return parsed info.

    Returns a dict with 'length', 'type', 'stream_id', 'error' keys.
    """
    import hyperframe.frame

    wire = bytes.fromhex(wire_hex)
    try:
        f, length = hyperframe.frame.Frame.parse_frame_header(
            memoryview(wire[:9])
        )
        f.parse_body(memoryview(wire[9:9 + length]))
        return {
            "length": length,
            "type": f.type,
            "stream_id": f.stream_id,
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}


# ── Convert accept vector ─────────────────────────────────────────────


def convert_accept(
    src: dict, frame_type: str, filename: str, seen_ids: set[str]
) -> dict:
    """Convert a source accept vector to our format."""
    wire_hex = src["wire"].lower()
    frame = src["frame"]
    description = src["description"]
    slug = _slugify(description)
    vector_id = f"h2fc-{frame_type}-{slug}"

    # Disambiguate if the same slug already appeared (e.g. two files with
    # the same description in the same frame-type directory).
    if vector_id in seen_ids:
        file_slug = _slugify(Path(filename).stem)
        vector_id = f"h2fc-{frame_type}-{file_slug}"
    seen_ids.add(vector_id)

    length = frame["length"]
    ftype = frame["type"]
    flags = frame["flags"]
    stream_id = frame["stream_identifier"]
    payload = _payload_hex(wire_hex, length)

    return {
        "id": vector_id,
        "category": frame_type,
        "type": "h2_frame",
        "rfc_section": RFC_SECTION.get(frame_type, "RFC 9113"),
        "description": description,
        "source": "http2-frame-test-case",
        "input": {"wire_hex": wire_hex},
        "expected": {
            "behavior": "accept",
            "length": length,
            "frame_type": ftype,
            "flags": flags,
            "stream_id": stream_id,
            "payload_hex": payload,
        },
    }


# ── Convert reject/error vector ───────────────────────────────────────


def convert_error(src: dict, filename: str, seen_ids: set[str]) -> dict:
    """Convert a source error vector to our format."""
    wire_hex = src["wire"].lower()
    description = src["description"]

    # Determine the frame type category from the filename
    # Filenames are like: data-frame-padding.json, headers-frame-stream.json
    # Extract the frame type prefix before "-frame"
    base = Path(filename).stem
    parts = base.split("-frame")
    frame_category = parts[0].replace("-", "_") if parts else "unknown"

    slug = _slugify(description)
    vector_id = f"h2fc-error-{slug}"

    # Disambiguate if the same slug already appeared
    if vector_id in seen_ids:
        file_slug = _slugify(Path(filename).stem)
        vector_id = f"h2fc-error-{file_slug}"
    seen_ids.add(vector_id)

    # Error codes: source stores them as a list of ints
    raw_error = src["error"]
    if isinstance(raw_error, int):
        error_codes = [raw_error]
    elif isinstance(raw_error, list):
        error_codes = [int(c) for c in raw_error]
    elif isinstance(raw_error, str):
        # Shouldn't happen based on inspection, but handle defensively
        error_codes = []
    else:
        error_codes = []

    scope = _error_scope(error_codes, wire_hex)
    reason = _error_reason(error_codes)

    return {
        "id": vector_id,
        "category": "error",
        "type": "h2_frame",
        "rfc_section": RFC_SECTION.get(frame_category, "RFC 9113"),
        "description": description,
        "source": "http2-frame-test-case",
        "input": {"wire_hex": wire_hex},
        "expected": {
            "behavior": "reject",
            "error_codes": error_codes,
            "error_scope": scope,
            "reason": reason,
        },
    }


# ── Merge ──────────────────────────────────────────────────────────────


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


# ── Main pipeline ──────────────────────────────────────────────────────


def main():
    tmpdir = tempfile.mkdtemp(prefix="h2fc-vectors-")
    src_dir = os.path.join(tmpdir, "h2frames")
    print(f"Working in {tmpdir}\n")

    # 1. Clone repo
    print("Cloning http2-frame-test-case...")
    subprocess.run(
        ["git", "clone", "--depth=1", REPO_URL, src_dir],
        capture_output=True,
        check=True,
    )
    print("  Done.\n")

    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    # Collect existing IDs across all target files
    existing_ids: set[str] = set()
    for json_file in VECTORS_DIR.glob("frame_*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                vectors = json.load(f)
            for v in vectors:
                if "id" in v:
                    existing_ids.add(v["id"])
        except (json.JSONDecodeError, KeyError):
            pass

    # Group converted vectors by target file
    file_groups: dict[str, list[dict]] = {}

    # Track generated IDs to disambiguate duplicates
    seen_ids: set[str] = set()

    # 2. Process accept vectors (one directory per frame type)
    print("=== Processing accept vectors ===")
    for frame_type, target_filename in TYPE_TO_FILE.items():
        type_dir = os.path.join(src_dir, frame_type)
        if not os.path.isdir(type_dir):
            print(f"  {frame_type}: directory not found, skipping")
            continue

        json_files = sorted(Path(type_dir).glob("*.json"))
        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    src_data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"  Warning: failed to read {json_file.name}: {e}")
                _stats["errors"] += 1
                continue

            # Skip if this is actually an error vector (shouldn't be in
            # frame type dirs, but be defensive)
            if src_data.get("error") is not None:
                continue

            vector = convert_accept(src_data, frame_type, json_file.name, seen_ids)

            if vector["id"] in existing_ids:
                _stats["skipped_existing"] += 1
                continue

            # Validate with hyperframe
            hf_result = validate_with_hyperframe(vector["input"]["wire_hex"])
            if hf_result["error"] is None:
                # Cross-check parsed values
                mismatches = []
                if hf_result["length"] != vector["expected"]["length"]:
                    mismatches.append(
                        f"length: hf={hf_result['length']} vs src={vector['expected']['length']}"
                    )
                if hf_result["type"] != vector["expected"]["frame_type"]:
                    mismatches.append(
                        f"type: hf={hf_result['type']} vs src={vector['expected']['frame_type']}"
                    )
                if hf_result["stream_id"] != vector["expected"]["stream_id"]:
                    mismatches.append(
                        f"stream_id: hf={hf_result['stream_id']} vs src={vector['expected']['stream_id']}"
                    )

                if mismatches:
                    print(f"  MISMATCH {vector['id']}: {'; '.join(mismatches)}")
                    _stats["hyperframe_mismatch"] += 1
                else:
                    _stats["hyperframe_ok"] += 1
            else:
                print(f"  HYPERFRAME ERROR {vector['id']}: {hf_result['error']}")
                _stats["hyperframe_error"] += 1

            file_groups.setdefault(target_filename, []).append(vector)
            _stats["converted"] += 1
            print(f"  {vector['id']} -> {target_filename}")

    # 3. Process error vectors
    print("\n=== Processing error vectors ===")
    error_dir = os.path.join(src_dir, "error")
    if os.path.isdir(error_dir):
        json_files = sorted(Path(error_dir).glob("*.json"))
        target_filename = "frame_error.json"

        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    src_data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"  Warning: failed to read {json_file.name}: {e}")
                _stats["errors"] += 1
                continue

            vector = convert_error(src_data, json_file.name, seen_ids)

            if vector["id"] in existing_ids:
                _stats["skipped_existing"] += 1
                continue

            file_groups.setdefault(target_filename, []).append(vector)
            _stats["converted"] += 1
            print(f"  {vector['id']} -> {target_filename}")
    else:
        print("  error directory not found, skipping")

    # 4. Merge into target files
    print("\n=== Merging ===")
    total_added = 0
    for target_filename, vectors in sorted(file_groups.items()):
        target_path = VECTORS_DIR / target_filename
        added = merge_vectors(vectors, target_path)
        total_added += added
        existing_count = 0
        if target_path.exists():
            with open(target_path, "r", encoding="utf-8") as f:
                existing_count = len(json.load(f))
        print(f"  {target_filename}: +{added} vectors (total in file: {existing_count})")

    # 5. Summary
    print(f"\n=== Summary ===")
    print(f"Converted:            {_stats['converted']} vectors")
    print(f"Skipped (existing):   {_stats['skipped_existing']}")
    print(f"Hyperframe validated:  {_stats['hyperframe_ok']}")
    print(f"Hyperframe mismatch:  {_stats['hyperframe_mismatch']}")
    print(f"Hyperframe errors:    {_stats['hyperframe_error']}")
    print(f"Read errors:          {_stats['errors']}")
    print(f"Total added to files: {total_added}")
    print("\nDone!")


if __name__ == "__main__":
    main()
