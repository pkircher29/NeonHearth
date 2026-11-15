# deepmerge security backport

This is an explicit local fork of upstream deepmerge 4.3.1, not an upstream
release. The package metadata records the original npm archive's verified SRI.
Upstream source: https://github.com/TehShrike/deepmerge/tree/v4.3.1
Original CJS distribution and MIT license retained; no runtime dependencies added.

Fix GHSA-gcqx-w48m-w2h4: every destination assignment now defines an enumerable,
writable, configurable own data property rather than invoking an inherited
__proto__ setter. Target and null-prototype source objects are both covered.
Existing inherited-key rejection, nested clones, symbols and custom arrays remain.
Two reproduction tests fail on the unmodified distribution and pass on this fork.

Only the Svelte build plugin consumes this dev dependency; it is not shipped as
application runtime logic. The local name makes the fork transparent; absence
from npm's registry advisory matching is not proof of safety. The reproduction
tests and source review are the verification. No audit advisory is suppressed.
Replace with a compatible fixed upstream release when available.
