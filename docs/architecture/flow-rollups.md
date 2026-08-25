# Flow rollup contract

The flow engine trusts only the bounded source registry supplied at construction. Observations
contain an opaque source ID; they cannot claim a visibility class. Verified gateways, bridges,
and mirrors map to `complete`, verified router counters to `router_reported`, the local collector
to `local_only`, and configured inference to `estimated`. Aggregation is conservative: only
identical coverage remains unchanged, so every mixed class (including router plus local) becomes
`estimated`.

Event time selects a one-second bucket and arrival time bounds future skew and replay retention.
A second closes exactly when `bucket_start + 1 second <= watermark`. The watermark and its
explicit trusted `now` clock are monotonic, and a watermark cannot exceed `now`; callers can
therefore advance safely during idle or resume without inventing future time.
An event remains correctable through `second_close + lateness`; after that it is rejected. An
accepted late event emits a keyed `correction` for its second and changed minute/hour parents.
Minutes are built only from closed seconds, and hours only from those minute rows. Repeating a
watermark without a state change emits nothing.

Replay IDs are retained for `replay_ttl`, which configuration requires to be at least `lateness`.
After the replay entry expires, replaying an old event cannot double count because the lateness
gate rejects it; reusing that ID for a genuinely new, in-window event is accepted. Finalized
correction state is retained through the effective correction horizon (the smaller of configured
retention and lateness) and then emits a deterministic cache-only `retire` before eviction. A
retire never asks durable consumers to delete data, so parent totals never shrink when correction
cache state ages out.

Within a second and dimension key, observations from the same source sum. Parallel overlapping
sources do not sum: the engine deterministically selects Complete, then RouterReported, then
LocalOnly, then Estimated visibility, with source ID as the tie-break. Nonoverlapping seconds do
sum into parents and their coverage combines conservatively.

Destination IP/domain metadata is irreversibly stripped before storage when owner privacy is
off. When enabled, domains must be bounded ASCII DNS names and are normalized to lowercase. The
observation model has no payload/body field.

All source, device, row, replay, finalized-state, output, metadata, and per-call work limits are
validated or preflighted. Byte and time arithmetic is checked. A failing operation leaves engine
state unchanged, and ordered maps provide deterministic changes and serialized snapshots.
