# Minimal connection fixture; proximity heuristic is exercised by the
# dedicated tag-proximity fixtures, not this one.
fn handle(mut self):
    self._quic.close_app(0, String(GUARD_TAG_QUIC_SAMPLE_A), now)
