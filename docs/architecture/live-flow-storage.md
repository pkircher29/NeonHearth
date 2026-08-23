# Live flow and durable retention

`FlowLiveAdapter` consumes validated cumulative one-second rollup replacements. It retains every
dimension of each device's latest second and prunes that device's superseded seconds. Emitted
baselines are keyed by the full rollup key, so a replacement from 100 to 150 bytes reports only
50 new bytes. A downward correction resets the baseline without underflow or fabricated traffic;
later growth is measured from that corrected value. Cache-only retirements remove their live
cache row and pending baseline without becoming traffic. The upstream flow engine has already
selected one authoritative visibility source for overlapping observations.

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
deletion; a configured hour duration is rejected because owner deletion is a separate future
operation. Eligibility is aligned to the parent boundary: a minute is aggregated and sealed only
when that whole minute ends at or before the seconds cutoff, and an hour only when that whole hour
ends at or before the minutes cutoff. All children of an eligible parent are aggregated before
those children are deleted. Repeating or restarting compaction is idempotent; a failure rolls back
the whole bounded batch. Hours require explicit owner deletion, which D14 deliberately does not
expose as an automatic operation.
