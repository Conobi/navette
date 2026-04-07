# src/http/config.mojo
#
# Default HTTP runtime constants. Match hyper exactly. NOT stable API — may
# change once we benchmark against real workloads. See:
#   https://github.com/hyperium/hyper/blob/master/src/proto/h2/server.rs

# Stream-level body queue watermarks
comptime DEFAULT_STREAM_WINDOW_HIGH      = 1024 * 1024   # 1 MiB
comptime DEFAULT_STREAM_WINDOW_LOW       = 256  * 1024   # 256 KiB (1/4 of high)

# H2 connection-level flow control window (no equivalent in H3)
comptime DEFAULT_CONN_WINDOW             = 1024 * 1024   # 1 MiB

# Per-frame size limits
comptime DEFAULT_MAX_FRAME_SIZE          = 16   * 1024   # 16 KiB
comptime DEFAULT_MAX_SEND_BUF_SIZE       = 400  * 1024   # ~400 KiB

# Header limits
comptime DEFAULT_MAX_HEADER_LIST_SIZE    = 16   * 1024   # 16 KiB

# Concurrency limits
comptime DEFAULT_MAX_CONCURRENT_STREAMS  = 200

# Timeouts and DoS limits
comptime DEFAULT_KEEP_ALIVE_TIMEOUT_SECS = 20
comptime DEFAULT_MAX_LOCAL_RESET_STREAMS = 1024
