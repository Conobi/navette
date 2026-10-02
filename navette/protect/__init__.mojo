"""DoS protection state shared by the servers.

`config` holds the H3 server's protection knobs and its door counters;
`locally_closed` is H2's set of streams it reset or refused, so late
frames on them are ignored instead of treated as protocol errors.
"""
