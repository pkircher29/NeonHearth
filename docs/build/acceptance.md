# Candidate verification and local soak

These tools verify a frozen Windows Home Hub package and its explicitly isolated
local runtime. They do not prove clean-machine installation, physical camera or
router compatibility, household device control, remote-phone access, sleep/resume,
signed publisher trust, or all recovery scenarios. Those remain separate release
gates. A short smoke run is never a 72-hour soak.

## Freeze and verify

Build the native launcher and collector, production UI, and portable package from
one clean source commit using the packaging guide. `BUILD-INFO.json` must record
that exact commit with `source_dirty:false`. Review the candidate's declared
signing status. The package verifier checks every listed file's size and SHA-256,
required components, source metadata, and no unlisted files, path traversal,
case-insensitive duplicates, symlinks or Windows reparse points. The package
manifest is an integrity record, not a publisher signature.

Run from the repository root (Python 3.11+):

```text
python scripts/verify-candidate.py --package "C:/QA/NeonHearth candidate" --output "C:/QA/evidence/package.json"
```

The output file must be new and outside the package. This command starts nothing.
`package_verified` means integrity/provenance passed, not runtime acceptance.
Untrusted or malformed candidates fail with exit code 1.

## Native smoke

The test runner additionally requires `psutil==7.2.2`, a test-tool dependency
(it is not added to the customer application). Start with a short run:

```text
python scripts/soak-candidate.py --package "C:/QA/NeonHearth candidate" --state "C:/QA/state-smoke-001" --output "C:/QA/evidence/smoke-001.json" --port 58131 --mqtt-port 58193 --duration-seconds 120 --interval-seconds 5
```

Use two unused unprivileged ports and a new empty private state directory. The
script refuses the normal `%LOCALAPPDATA%/NeonHearthHomeHub` tree, overlapping
package/state paths, nonempty state, and existing evidence files. It never stops
the customer's instance, installs a service, opens a browser, invokes an active
LAN scan, configures the router feed, or controls a household device.

The native launcher starts with `--no-browser`, `--state`, `--port` and
`--mqtt-port`. Its existing protected state/DPAPI and process-identity checks
apply. The sampler independently verifies executable paths, process creation
times and listener ownership before decrypting the QA owner's credential and
performing authenticated read-only API requests. Tokens, device inventory,
connection lists, executable lists and private log text are not stored in the
evidence report. The normal collector's passive OS-neighbor observations and
local-computer telemetry continue inside this disposable QA state.

Hosted CI VMs may have no eligible physical network adapter. Only for such a
short transport check, add `--allow-degraded-collector` with a duration of at most
120 seconds (release CI uses 15 seconds). This does not turn a degraded collector
into a ready discovery source: each sample retains the actual `collector_status`
and uses `transport_ready` rather than `ready` when degraded. The report records
`measurement_scope: transport_only_smoke` and `discovery_acceptance:false`.
Authentication, process/listener identity, host freshness, broker readiness,
SQLite integrity, resource limits and continuous-sampling rules all still apply.
This option is refused for longer runs, including the default 72-hour soak.
Without the flag, a degraded collector fails even a short run.

By default each sample requires a ready collector, authenticated health/state/host responses,
a fresh host observation, a running broker, and still-disabled active discovery
and router feed. SQLite `quick_check` runs in read-only/query-only mode initially,
hourly, and at completion. Reports preserve metric history and explicit failure
types without credential-bearing exceptions. The QA instance is stopped through
its launcher on completion, handled failure, or Ctrl-C. Its state is retained.

## 72-hour local soak

After a smoke pass, select a different new QA state/evidence file:

```text
python scripts/soak-candidate.py --package "C:/QA/NeonHearth candidate" --state "C:/QA/state-soak-001" --output "C:/QA/evidence/soak-001.json" --port 58132 --mqtt-port 58194
```

Default engineering budgets are assumptions to review for the selected supported
hardware, not previously measured product guarantees:

| Condition | Default bound |
|---|---|
| Requested continuous collection | 259,200 seconds (72 hours) |
| Sampling interval | 60 seconds |
| Maximum inter-sample gap | 120 seconds |
| Host measurement age | 30 seconds |
| Combined collector + broker RSS | 512 MiB |
| Combined interval CPU | 25% of one logical CPU |
| Private state size | 2,048 MiB |
| Private state growth over run | 512 MiB |

Startup CPU before the first sample is not covered by the interval CPU budget;
record startup behavior separately. CLI flags allow explicit alternate budgets,
which are written into the report. A sampling gap, stale reading, missing metric,
timeout, failed integrity check or exceeded budget fails the run. The first sample
must occur within the gap bound; merely supplying one end-of-run sample cannot
pass. The candidate is rehashed at the end and must still match the baseline.

Keep the runner alive. If the machine sleeps long enough to create a sampling
gap, that is a failure, not 72 hours of credited uptime. Forced termination can
leave the isolated processes running; the report's `qa_state_path` identifies
the exact QA state to inspect/stop with `NeonHearth.exe --status/--stop --state`.
Never use a customer's state path to clean up a QA run.

## Evidence states and review

`starting` / `running` are progress only. `smoke_passed` covers the requested short
interval; `soak_passed` requires at least 72 hours of continuous acceptable
samples. `failed`, `interrupted` and `incomplete` cannot be called acceptance.
The runner exits 0 only for a confirmed smoke/soak pass with confirmed cleanup.
The evidence explicitly keeps hardware, clean-machine, recovery-exercise and
trusted-signing acceptance false. A claimed signed package does not change that.

Check a report against its frozen candidate, writing a new review result:

```text
python scripts/verify-candidate.py --package "C:/QA/NeonHearth candidate" --soak-report "C:/QA/evidence/soak-001.json" --output "C:/QA/evidence/soak-001-review.json"
```

A stale `running` heartbeat becomes `incomplete` in the review; an interrupted
process cannot silently gain time. A mislabeled short pass or unconfirmed cleanup
fails review. The review re-evaluates the recorded collector policy, measurement
scope and maximum transport-only duration; changing the scope or labeling a
degraded run as a 72-hour pass fails. Boolean values are not accepted as numeric
resource/freshness evidence. Neither command resumes interrupted runs or
overwrites evidence.

## Remaining release acceptance

Use a clean Windows VM or physical machine and approved install media to test
first install, normal-user startup, upgrade with pairing/history preserved,
uninstall/reinstall, missing prerequisites, occupied ports, reboot, sleep/resume,
adapter changes, offline/reconnect and database recovery. Record exact candidate
hashes and Windows build. Test real physical features and away-from-home phone
behavior only with explicit target authority. Trusted signing requires the real
publisher credential/provider and signature-chain verification; a self-signed test
certificate or SHA-256 manifest does not meet that gate.

Run tooling regression tests with:

```text
python -m unittest discover -s scripts/tests -p test_candidate_acceptance.py
```
