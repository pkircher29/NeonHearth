# Live flow and durable retention

`FlowLiveAdapter` consumes validated current one-second rollup replacements. Upserts and
corrections replace the same key before per-device aggregation, so corrections do not add bytes
twice. Cache-only retirements never become traffic. The upstream flow engine has already selected
one authoritative visibility source for overlapping observations.

`LiveCoalescer` uses caller-supplied monotonic millisecond ticks. It emits one global
`bandwidth_frame` no faster than every 250 ms, retains the latest pending device replacement
during bursts, and can flush during idle. Every sample includes upload/download delta and rate,
coverage, device ID, interval, observation time, and emission time. Device, pending, output, and
work limits are preflighted.

SQLite stores keyed flow rollups by resolution, bucket, device, protocol, destination category,
interface, and optional privacy metadata. Upsert and correction use the same key and transaction;
cache retirement never deletes durable history. `protocol_rollups` is a nonduplicating grouped
view over this normalized table.

Compaction defaults are exactly 24 hours for seconds, 90 days for minutes, and no automatic hour
deletion. Only complete parent intervals at or before the cutoff are aggregated. Minute parents
are rebuilt from seconds and hour parents from minutes in the same transaction before eligible
children are deleted. Repeating or restarting compaction is idempotent; a failure rolls back the
whole bounded batch. Hours require explicit owner deletion, which D14 deliberately does not
expose as an automatic operation.
