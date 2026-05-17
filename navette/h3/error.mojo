# H3 application error codes (RFC 9114 §8.1)
comptime H3_NO_ERROR:                UInt64 = 0x0100
comptime H3_GENERAL_PROTOCOL_ERROR:  UInt64 = 0x0101
comptime H3_INTERNAL_ERROR:          UInt64 = 0x0102
comptime H3_STREAM_CREATION_ERROR:   UInt64 = 0x0103
comptime H3_CLOSED_CRITICAL_STREAM:  UInt64 = 0x0104
comptime H3_FRAME_UNEXPECTED:        UInt64 = 0x0105
comptime H3_FRAME_ERROR:             UInt64 = 0x0106
comptime H3_EXCESSIVE_LOAD:          UInt64 = 0x0107
comptime H3_ID_ERROR:                UInt64 = 0x0108
comptime H3_SETTINGS_ERROR:          UInt64 = 0x0109
comptime H3_MISSING_SETTINGS:        UInt64 = 0x010a
comptime H3_REQUEST_REJECTED:        UInt64 = 0x010b
comptime H3_REQUEST_CANCELLED:       UInt64 = 0x010c
comptime H3_REQUEST_INCOMPLETE:      UInt64 = 0x010d
comptime H3_MESSAGE_ERROR:           UInt64 = 0x010e
comptime H3_CONNECT_ERROR:           UInt64 = 0x010f
comptime H3_VERSION_FALLBACK:        UInt64 = 0x0110

# QPACK error codes (RFC 9204 §6)
comptime QPACK_DECOMPRESSION_FAILED:  UInt64 = 0x0200
comptime QPACK_ENCODER_STREAM_ERROR:  UInt64 = 0x0201
comptime QPACK_DECODER_STREAM_ERROR:  UInt64 = 0x0202

# Unidirectional stream type identifiers (RFC 9114 §6.2)
comptime H3_STREAM_CONTROL:       UInt64 = 0x00
comptime H3_STREAM_QPACK_ENCODER: UInt64 = 0x02
comptime H3_STREAM_QPACK_DECODER: UInt64 = 0x03
