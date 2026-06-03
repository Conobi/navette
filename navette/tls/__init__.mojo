# src/tls/__init__.mojo
#
# Re-exports for the TLS layer.
from .lib import SharedLibrary, TlsBackend
from .config import TlsClientConfig, TlsServerConfig
from .connection import TlsConnection

# Public 0-RTT acceptance configuration surface.
#
# Callers configure 0-RTT via the `EarlyDataPolicy` enum (three variants:
# Off / IdempotentOnly / Tuned) passed to `QuicServerConfig` as a ctor
# kwarg. The two underlying traits (`EarlyDataFilter`, `EarlyDataStore`)
# are exposed here so future user implementations have a stable import
# path; user types via a `Custom(filter)` variant are deferred to a
# follow-up cycle.
from .early_data_policy import EarlyDataPolicy
from .early_data_filter import (
    EarlyDataFilter,
    FilterDecision,
    IdempotentOnlyFilter,
)
from .early_data_store import (
    EarlyDataStore,
    EarlyDataStoreConfig,
    InMemoryEarlyDataStore,
    ReplayDecision,
    default_early_data_store_config,
)
