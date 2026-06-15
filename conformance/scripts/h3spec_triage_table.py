#!/usr/bin/env python3
"""Generate the h3spec triage table draft.

Reads the captured fixture pair (h3spec.out, server.err), runs the
classifier, and emits a markdown row per failure plus auto-clusters
by (RFC top-section, target_module). Used to seed the local triage
document; hand-clustering still required.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests/conformance/fixtures/h3spec_triage_capture"
TRIAGE = REPO / "conformance/scripts/h3spec_triage.py"


def run_triage() -> dict:
    """Invoke h3spec_triage.py against the captured fixture and parse JSON."""
    proc = subprocess.run(
        [
            sys.executable,
            str(TRIAGE),
            "--h3spec",
            str(FIXTURE / "h3spec.out"),
            "--server-err",
            str(FIXTURE / "server.err"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


_RFC_CLAUSE_RX = re.compile(r"\[(?P<clause>[^\]]+)\]\s*$")


def extract_rfc_clause(name: str) -> str:
    """Pull the bracketed RFC clause out of an h3spec test name.

    Examples:
      "MUST ... [Transport 4.1]" -> "RFC 9000 §4.1"
      "MUST ... [HTTP/3 6.2.1]" -> "RFC 9114 §6.2.1"
      "MUST ... [TLS 8.3]" -> "RFC 9001 §8.3"
      "MUST ... [QPACK §4.4.3]" -> "RFC 9204 §4.4.3"
    """
    m = _RFC_CLAUSE_RX.search(name)
    if not m:
        return "_TBD_"
    clause = m.group("clause").strip()
    # Normalize: split on first space, the rest is section.
    if clause.lower().startswith("transport "):
        section = clause[len("Transport "):].strip()
        return f"RFC 9000 §{section}"
    if clause.lower().startswith("http/3 "):
        section = clause[len("HTTP/3 "):].strip()
        return f"RFC 9114 §{section}"
    if clause.lower().startswith("tls "):
        section = clause[len("TLS "):].strip()
        return f"RFC 9001 §{section}"
    if clause.lower().startswith("qpack"):
        section = clause[len("QPACK"):].strip().lstrip("§").strip()
        return f"RFC 9204 §{section}" if section else "RFC 9204"
    return f"_TBD_ ({clause})"


def target_module(name: str, rfc_clause: str) -> str:
    """Assign navette/<dir>/<file>.mojo by RFC section + name heuristics.

    Heuristics:
      - [Transport 7.x or 18.x] (parameters) -> trans_param.mojo
      - [Transport 19.x] (frame types) -> connection.mojo (frame dispatch) or stream_map.mojo
      - [Transport 12.4 / 17.2] (packet structure / no frames) -> packet.mojo or codec.mojo
      - [Transport 4.1] (flow control) -> flow_control.mojo
      - [HTTP/3 4.1 / 6.2.1] (request-stream / settings sequencing) -> h3/connection.mojo
      - [HTTP/3 7.2.x] (control-stream frame dispatch) -> h3/connection.mojo
      - [TLS 6 / 8.x] (key-update / alerts / quic_transport_parameters) -> tls/connection.mojo
      - [TLS 8.3] CRYPTO-in-0-RTT -> quic/crypto_stream.mojo
    """
    # Transport section
    if rfc_clause.startswith("RFC 9000"):
        # Frame-type errors: 17.x reserved-bits / no-frames -> packet+codec
        if "§17.2.4" in rfc_clause or "§17.2" in rfc_clause:
            return "navette/quic/packet.mojo"
        if "§12.4" in rfc_clause:
            # unknown frame / no frames -> connection frame loop
            return "navette/quic/connection.mojo"
        if "§4.1" in rfc_clause:
            return "navette/quic/flow_control.mojo"
        if "§7.3" in rfc_clause or "§7.4" in rfc_clause or "§18.2" in rfc_clause:
            return "navette/quic/trans_param.mojo"
        # 19.x frame-specific
        if "§19.4" in rfc_clause or "§19.5" in rfc_clause or "§19.10" in rfc_clause:
            return "navette/quic/stream_map.mojo"
        if "§19.7" in rfc_clause or "§19.20" in rfc_clause:
            return "navette/quic/connection.mojo"
        if "§19.11" in rfc_clause or "§19.14" in rfc_clause:
            return "navette/quic/stream_map.mojo"
        if "§19.15" in rfc_clause:
            return "navette/quic/cid.mojo"
        return "navette/quic/connection.mojo"
    if rfc_clause.startswith("RFC 9114"):
        if "§4.1" in rfc_clause:
            # DATA before HEADERS on request stream
            return "navette/h3/connection.mojo"
        if "§6.2.1" in rfc_clause or "§7.2" in rfc_clause:
            return "navette/h3/connection.mojo"
        return "navette/h3/connection.mojo"
    if rfc_clause.startswith("RFC 9001"):
        # CRYPTO in 0-RTT case -> crypto_stream.mojo; other TLS-alert cases -> tls/connection.mojo
        if "CRYPTO in 0-RTT" in name:
            return "navette/quic/crypto_stream.mojo"
        return "navette/tls/connection.mojo"
    if rfc_clause.startswith("RFC 9204"):
        return "navette/h3/qpack.mojo"
    return "_TBD_"


def short_name(name: str) -> str:
    """Drop the trailing [Section] tag for the table cell (kept in rfc_clause column).

    Also strip the leading 'QUIC servers ' / 'H3 servers ' prefix h3spec injects.
    """
    n = name
    n = re.sub(r"^QUIC servers\s+", "", n)
    n = re.sub(r"^H3 servers\s+", "", n)
    n = re.sub(r"\s*\[[^\]]+\]\s*$", "", n)
    return n


def main() -> int:
    """Emit the markdown table draft to stdout."""
    triaged = run_triage()
    rows = [r for r in triaged["rows"] if r["h3spec_status"] == "fail"]
    print(f"# rows={len(rows)} summary={triaged['summary']}")
    print()
    print("| failure_id | h3spec_test_name | rfc_clause | observed_navette_behavior | classified_pattern | target_module |")
    print("|---|---|---|---|---|---|")
    enriched: list[dict] = []
    for i, r in enumerate(rows, start=1):
        fid = f"F{i:02d}"
        rfc = extract_rfc_clause(r["name"])
        mod = target_module(r["name"], rfc)
        obs = "timeout — no CONNECTION_CLOSE emitted"
        pat = r["classified_pattern"] or "UNCLASSIFIED"
        sname = short_name(r["name"])
        enriched.append(
            {"id": fid, "name": sname, "rfc": rfc, "mod": mod, "obs": obs, "pat": pat}
        )
        print(f"| {fid} | {sname} | {rfc} | {obs} | {pat} | `{mod}` |")
    print()
    # Cluster by (rfc_root_section, module)
    clusters: dict[tuple[str, str], list[str]] = {}
    for e in enriched:
        # cluster key: same module + same RFC top-level section (e.g. "RFC 9000 §7" or "RFC 9000 §19")
        rfc_top = re.sub(r"§(\d+).*$", r"§\1", e["rfc"])
        key = (rfc_top, e["mod"])
        clusters.setdefault(key, []).append(e["id"])
    # Assign cluster ids
    cluster_ids: dict[tuple[str, str], str] = {}
    for idx, key in enumerate(clusters, start=1):
        cluster_ids[key] = f"C{idx}"
    print()
    print("# CLUSTERS")
    for key, ids in clusters.items():
        cid = cluster_ids[key]
        print(f"{cid} | {key[0]} | {key[1]} | {','.join(ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
