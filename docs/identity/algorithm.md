# NeonHearth identity correlation

NeonHearth owns device identity. Router labels, including Acer Predator W6 labels, are stored only as `RouterHint` evidence and clamped to `0.49`; they never create, merge, or confirm an identity.

## Evidence and matching

Every fact retains its family, source, observation time, optional expiry, confidence, value, and owner-confirmed flag. Inputs, device count, per-device facts, proposals, audit decisions, and returned fact lists are bounded before state changes. Expired facts do not participate in matching or identification.

Identity anchors are deliberately narrower than classification facts. Every automatic merge requires strong matches from at least two independent, taxonomy-validated families. A globally administered MAC plus DHCP client ID can maintain identity across IP changes. Private-MAC changes require two other independent anchors, such as a TLS SPKI plus ONVIF UUID. Stable serials, protocol UUIDs, TLS keys, SSH host keys, UPnP UDNs, and DHCP client identifiers are eligible only in their assigned families. IP, OUI/vendor, router label, hostname, device class, and open ports are not automatic merge anchors.

Each contributing family must independently meet the configured match threshold. Repeated facts from one family count once. A conflicting high-confidence stable identifier blocks automatic correlation. If evidence points toward multiple candidates, NeonHearth creates deterministic owner-review proposals instead of choosing one.

## Classification

Automatic vendor plus device-class identification requires both fields to meet `0.85` and support from at least two independent non-router evidence families. The boundary is inclusive. Contradictory high-confidence vendor or class values block automatic identification. Model and firmware may remain unknown. Router hints are capped at `0.49` and excluded. Owner-confirmed values are authoritative, regardless of automatic confidence, until explicitly cleared.

## Review and reversibility

Merge proposals include candidate IDs, score, independent families, and sorted reasons. Accept/reject/undo decisions append audit records. Every accepted proposal adds its own graph edge without moving or deleting facts, including a proposal whose endpoints are already connected. Canonical components are recomputed from active edges, and undo disables only that proposal's edge, so other accepted decisions continue to support the relationship. Owner set/clear actions are a separate append-only history; owner values never expire and only an explicit tombstone clears them.

## Limits

Correlation is conservative and can leave one physical device represented by multiple IDs when stable evidence is unavailable. Configuration, state, candidate work, graph edges, audits, and output are bounded; an operation fails atomically with a typed limit error rather than returning partial results. Persistence and cross-restart audit storage are integrated separately.
