# src/tls/__init__.mojo
#
# Re-exports for the TLS layer.
from .lib import SharedLibrary, TlsBackend
from .config import TlsClientConfig, TlsServerConfig
from .connection import TlsConnection

# Public 0-RTT acceptance configuration surface.
#
# Callers configure 0-RTT via the `EarlyDataPolicy` enum (four variants:
# Off / IdempotentOnly / Tuned / Predicate) passed to `QuicServerConfig`
# as a ctor kwarg. The Predicate variant carries a user-supplied
# free-function pointer (`EarlyDataPredicateFn`); two reference
# predicates ship below. The two underlying traits (`EarlyDataFilter`,
# `EarlyDataStore`) are exposed here so future user implementations
# have a stable import path; user types via a `Custom(filter, store)`
# variant for stateful filter STRUCTS are deferred to a follow-up change.
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

# 0-RTT predicate-variant support: the function-pointer alias type +
# the two reference predicates that ship in v1.
from .early_data_filter import EarlyDataPredicateFn
from .filters import (
    idempotency_key_predicate,
    unauthenticated_only_predicate,
)
