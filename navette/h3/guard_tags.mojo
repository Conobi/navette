"""Single source of truth for H3 conformance guard reason tags.

Grep-friendly format: exactly one `comptime GUARD_TAG_*` per line.
See `navette/quic/guard_tags.mojo` for the rationale on the lack of a
leading underscore.
"""

comptime GUARD_TAG_DATA_BEFORE_HEADERS = "[H3-DATA-BEFORE-HEADERS]"
comptime GUARD_TAG_CTRL_NO_SETTINGS    = "[H3-CTRL-NO-SETTINGS]"
comptime GUARD_TAG_DATA_ON_CTRL        = "[H3-DATA-ON-CTRL]"
comptime GUARD_TAG_HEADERS_ON_CTRL     = "[H3-HEADERS-ON-CTRL]"
comptime GUARD_TAG_SECOND_SETTINGS     = "[H3-SECOND-SETTINGS]"
comptime GUARD_TAG_CANCEL_PUSH_REQ     = "[H3-CANCEL-PUSH-REQ]"
