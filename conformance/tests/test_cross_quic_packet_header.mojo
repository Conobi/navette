# conformance/tests/test_cross_quic_packet_header.mojo
#
# QC-1 Category 2: QUIC packet header parse vectors — M3 stub.
# This test is SKIPPED until M3 implements quic_packet_parse_header.
#
# When M3 ships:
#   1. Remove the early return below.
#   2. Import the M3 packet header parser.
#   3. Load vectors/rfc9000/packet_header.json.
#   4. For each accept vector: parse wire_hex, assert fields match expected.
#   5. For each error vector: assert parse raises.
#   6. Cross-check accept vectors against aioquic pull_quic_header.


def main() raises:
    print("test_cross_quic_packet_header: SKIPPED — M3 not implemented")
