"""Baseline DoS protections: the pure bookkeeping primitives the servers will share.

Only the building blocks live here (budgets, source keys and tables,
heaps, rate windows, config and counters); apart from H2's use of
`LocallyClosedSet`, no server is wired to them yet. Every module is
sans-I/O and allocation-free after construction, so the accept, close
and pass paths can call them without touching the heap.
"""
