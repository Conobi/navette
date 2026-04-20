# src/h2/config.mojo
#
# Production HTTP/2 configuration factory.

from .connection import H2Config


def h2_production_config(*, client_side: Bool) -> H2Config:
    """Create an H2Config with production defaults.

    Production defaults match hyper:
      initial_window_size: 1 MiB (vs 64K RFC default)
      max_concurrent_streams: 200
      max_frame_size: 16384
      max_header_list_size: 16384
      header_table_size: 4096
    """
    var config = H2Config(client_side=client_side)
    config.initial_window_size = UInt32(1_048_576)
    config.max_concurrent_streams = UInt32(200)
    return config^
