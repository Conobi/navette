# conformance/lib/packet.mojo


def decode_packet_number(largest_pn: Int, truncated_pn: Int, pn_nbits: Int) -> Int:
    """Decode a packet number from truncated form using RFC 9000 Appendix A.3.

    Args:
        largest_pn: The largest packet number received so far.
        truncated_pn: The truncated packet number value.
        pn_nbits: The number of bits in the truncated packet number (1-62).

    Returns:
        The full packet number.
    """
    var expected_pn = largest_pn + 1
    var pn_win = 1 << pn_nbits
    var pn_hwin = pn_win >> 1
    var pn_mask = pn_win - 1
    var candidate_pn = (expected_pn & ~pn_mask) | truncated_pn

    if candidate_pn <= expected_pn - pn_hwin and candidate_pn < (1 << 62) - pn_win:
        return candidate_pn + pn_win
    if candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
        return candidate_pn - pn_win
    return candidate_pn


def encode_packet_number_length(full_pn: Int, largest_acked: Int) -> Int:
    """Determine the minimum bytes needed to encode a packet number.

    Args:
        full_pn: The full packet number to encode.
        largest_acked: The largest packet number that has been acknowledged,
                       or -1 if no ACK has been received.

    Returns:
        The minimum number of bytes needed (1, 2, 3, or 4).
    """
    var num_unacked: Int
    if largest_acked == -1:
        num_unacked = full_pn + 1
    else:
        num_unacked = full_pn - largest_acked

    var range_needed = 2 * num_unacked

    if range_needed <= 0x100:
        return 1
    if range_needed <= 0x10000:
        return 2
    if range_needed <= 0x1000000:
        return 3
    return 4
