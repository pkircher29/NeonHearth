# M2 discovery evidence

## Automated fixture gate

The service boundary is exercised by `crates/lattice-service/tests/discovery_pipeline.rs`:

```bash
cargo test -p lattice-service --test discovery_pipeline
cargo test -p lattice-store --test retention
```

The fixture submits source-stamped link-layer and ONVIF service evidence. The app-owned identity engine resolves one stable device ID with confidence at least `0.85` and two independent evidence families. Presence requires its configured confirmations, records the source/kind that caused the join and departure, and emits a late-evidence correction for a recent departure. The retention test inserts two old one-second rows through the public repository, compacts them under the default 24-hour/90-day policy, and verifies exact byte conservation in the resulting minute row with `local-only` coverage.

The service fixture also sends a normalized rollup through `FlowIngestor`; the emitted live frame carries `local-only` coverage end-to-end. Discovery inputs use registered opaque source IDs and reject unregistered sources or families before state mutation. Retention additionally verifies minute-to-hour compaction at the 90-day boundary and repeat/idempotence.

## Real hardware acceptance — PENDING

Run only on the owner-approved private home subnet and record sanitized output here. Do not claim completion until a real device appears and departs while the service records source evidence, stable identity/confidence, presence transition trigger, and honest bandwidth coverage. No real-hardware result is fabricated by this fixture gate.
