"""Single source of truth for TLS conformance guard reason tags.

Grep-friendly format: one ``comptime GUARD_TAG_*`` per line; no inline
comments after the closing quote. ``coverage_check.py`` Inv-5 depends on
this format. The file lives at ``navette/tls/guard_tags.mojo`` (no leading
underscore; Mojo 1.0.0b1 rejects ``_module`` names).
"""

comptime GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE = "[TLS-KEYUPDATE-IN-HANDSHAKE]"
comptime GUARD_TAG_TLS_KEYUPDATE_1RTT      = "[TLS-KEYUPDATE-IN-1RTT]"
comptime GUARD_TAG_TLS_NO_ALPN             = "[TLS-NO-ALPN]"
comptime GUARD_TAG_TLS_END_OF_EARLY_DATA   = "[TLS-END-OF-EARLY-DATA]"
