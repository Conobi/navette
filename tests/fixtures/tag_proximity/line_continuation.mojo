fn handle(mut self):
    self._quic.close_app(
        H3_FRAME_UNEXPECTED,
        String(GUARD_TAG_DATA_BEFORE_HEADERS),
        now,
    )
