fn handle(mut self):
    var reason = String(GUARD_TAG_DATA_BEFORE_HEADERS)
    var code = H3_FRAME_UNEXPECTED
    var now = monotonic_us()
    self._quic.close_app(code, reason, now)
