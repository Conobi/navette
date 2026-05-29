fn handle(mut self):
    self._quic.close_app(0x0, String(GUARD_TAG_DATA_BEFORE_HEADERS), now)
