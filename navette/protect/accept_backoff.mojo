"""Accept back-off after `EMFILE` / `ENFILE`.

Re-arming accept on every tick while the process is out of descriptors
spins the loop and floods the log. After an exhaustion the server stops
accepting for 100 ms and logs at most once per 10 s.
"""

comptime ACCEPT_BACKOFF_US: UInt64 = 100_000
comptime ACCEPT_LOG_INTERVAL_US: UInt64 = 10_000_000


struct AcceptBackoff(Copyable, Movable):
    """`accept_fd_exhausted` counts every exhaustion, logged or not."""

    var resume_at_us: UInt64
    var last_log_us: UInt64
    var logged: Bool
    var accept_fd_exhausted: UInt64

    def __init__(out self):
        self.resume_at_us = 0
        self.last_log_us = 0
        self.logged = False
        self.accept_fd_exhausted = 0

    def on_fd_exhausted(mut self, now_us: UInt64) -> Bool:
        """Record one exhaustion and pause accept; True when the caller should log now."""
        self.accept_fd_exhausted += 1
        self.resume_at_us = now_us + ACCEPT_BACKOFF_US
        if not self.logged or now_us - self.last_log_us >= ACCEPT_LOG_INTERVAL_US:
            self.logged = True
            self.last_log_us = now_us
            return True
        return False

    def may_accept(self, now_us: UInt64) -> Bool:
        return now_us >= self.resume_at_us
