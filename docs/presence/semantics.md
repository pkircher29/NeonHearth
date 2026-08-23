# Presence semantics

The presence engine is deterministic: callers supply both observation and arrival/evaluation timestamps, and evaluation time may never move backwards. Inputs, devices, evidence, history, and per-operation work are bounded.

`Blocked` has highest precedence and requires verified enforcement; it remains until verified unblock. `Unknown` follows for sensor impairment or contradiction and never fabricates departure. `Online` requires recent trusted traffic. `Quiet` requires prior real presence plus a still-valid lease, router association, or successful probe; a probe alone cannot establish presence. `Offline` requires prior real presence, expiration of all protocol support, and the configured number of confirmation failures strictly after the latest support expiry.

Join and departure thresholds prevent flapping. Every transition includes the triggering source, evidence kind, observation/validity timestamps, arrival time, and a deterministic transition ID. Late positive evidence can reverse a recent departure only inside the bounded correction window and records `correction_of`; older evidence is retained only within the configured window and cannot rewrite older history.
