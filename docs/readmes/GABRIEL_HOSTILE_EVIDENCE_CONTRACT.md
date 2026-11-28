# Gabriel Hostile Evidence Contract

Status: design contract for the post-PR-132 hardening track

Gabriel investigates data that may have been created or modified by an
attacker. Logs, browser pages, packet captures, filenames, archives and model
responses are therefore treated as **hostile input**, not as trusted
instructions. This contract turns that assumption into requirements shared by
all twelve specialists.

## 1. Contract goals

Every investigation must be able to answer, without reconstructing hidden
agent reasoning:

1. What was observed and where did it come from?
2. What stayed local and what, if anything, crossed an egress boundary?
3. Which rule, parser, model, baseline and playbook versions were used?
4. What was not checked, what failed, and what remains uncertain?
5. Which analyst approved the next step, and which actions remain prohibited?

The contract supplements the existing encrypted evidence, custody, checkpoint,
model-budget and reviewed-memory controls. It does not weaken those controls or
turn an observation into source truth.

## 2. Data-minimization and egress

### Local-first processing

- Evidence is acquired into the encrypted evidence store before analysis.
- Parsers produce bounded typed facts or indicators rather than forwarding raw
  log bodies, packet payloads or files.
- Identifiers are pseudonymized per organization and case before model use.
- Raw content, credentials, cookies, authorization headers and active content
  remain local unless an explicitly approved adapter says otherwise.
- Ephemeral analysis sessions must have a defined expiry and must not add
  memory or watchlist entries implicitly.

### Required egress metadata

Each derived packet and each finding receipt will carry:

```json
{
  "fields_hidden": ["ip", "email", "hostname", "auth_header"],
  "stayed_local": ["raw_log_body", "packet_payload"],
  "egress": {
    "attempted": false,
    "provider": null,
    "data_handling_record": null,
    "authorization": "not_admitted"
  }
}
```

`attempted: true` requires a signed, current data-handling record identifying
the provider, purpose, allowed fields, retention terms, region and expiration.
Provider selection must fail closed when that record is absent, expired,
revoked or inconsistent with the packet.

## 3. Hostile-input containment

- Untrusted evidence is never rendered as active dashboard markup.
- Executables, macros, scripts and active document content are rejected by the
  local parser path. Detonation is a separate, isolated capability requiring
  explicit analyst authorization; no detonation environment is implied by this
  document.
- Archive metadata may be inspected with bounded limits. Extraction requires a
  separate admission path with traversal, symlink, expansion and object-count
  checks.
- Evidence writes remain atomic, private and no-follow. A supplied filename
  cannot select an output path.
- Tool invocations use a fixed allowlist, bounded input/output, no credentials,
  no network actions and an opaque origin separate from the analyst session.
- Authorization failures close hard. Capability loss must be reported as a
  degraded state, never as a clean result.

## 4. Signed policy kernel

Detection rules, routing tables, suppression rules, watchlists and response
playbooks will be distributed as signed, versioned bundles. A bundle must
include:

```json
{
  "bundle_version": "2026.11.0",
  "policy_digest": "sha256:...",
  "signer_fingerprint": "sha256:...",
  "valid_from": "...",
  "valid_until": "...",
  "rollback_to": "2026.10.3"
}
```

The runtime accepts only a trusted, unrevoked signer and a valid time window.
Updates are append-only, auditable and rollback-capable. A failed signature,
expired bundle or missing rollback target leaves the previous valid bundle in
place and reports the coverage limitation.

## 5. Finding receipt

Every alert, assessment, block or proposed action must be representable by a
single evidence-linked receipt. The minimum shape is:

```json
{
  "receipt_version": "hostile-evidence-v1",
  "finding_id": "uuid",
  "case_id": "uuid",
  "evidence": [{
    "evidence_id": "uuid",
    "digest": "sha256:...",
    "quote_or_fact": "bounded exact excerpt or typed fact",
    "custody": "validated"
  }],
  "trigger": {
    "rule_id": "...",
    "rule_version": "...",
    "model": null,
    "model_version": null,
    "baseline_version": "...",
    "playbook_version": "..."
  },
  "assessment": "suspected_unknown_exploitation",
  "confidence": "unqualified",
  "coverage": "partial",
  "limitations": ["..."],
  "degraded_state": ["analysis_incomplete"],
  "egress": {"attempted": false, "stayed_local": ["raw_content"]},
  "authorization": {"external_actions": false, "analyst": null},
  "work_trace": ["bounded parser", "cross-source correlation"]
}
```

The `quote_or_fact` value is either a bounded exact excerpt or a typed fact
with a source digest. It is not invented chain-of-thought. Work traces record
observable operations and inputs, not private model reasoning.

## 6. Unknown-exploitation and zero-day handling

No CVE match is not proof of a zero-day. Gabriel uses the following progression:

1. `anomalous_behavior` — a behavior is outside the supplied baseline.
2. `suspected_unknown_exploitation` — multiple bounded observations support an
   exploit hypothesis, but attribution or exploit novelty is unverified.
3. `confirmed_exploitation` — only after the evidence and analyst review meet
   the configured confirmation criteria.

All twelve specialists must expose corroborating evidence, contradictory
evidence, missing sensors, alternative explanations, affected assets and the
next safe verification step. None may generate, deliver or validate a
weaponized exploit, credential attack or destructive payload.

## 7. Visible memory and degraded states

Watchlists, baselines, suppressions and reviewed historical references are
visible, scoped, editable and auditable. They never change a verdict silently.
Each receipt must distinguish at least:

- `partial_coverage`
- `analysis_incomplete`
- `sensor_unreachable`
- `interrupted`
- `rule_pack_stale`
- `source_unverified`

The UI and exported report must show these states beside the conclusion. A
terminated scan cannot be represented as clean merely because no alert was
returned.

## 8. Implementation sequence

This contract is intentionally separate from PR #132:

1. Add typed receipt and egress-policy schemas with negative tests.
2. Thread the fields through local parsers, specialist results, browser
   observations and model packets.
3. Add signed policy-bundle verification and rollback tests.
4. Add quarantine/detonation admission boundaries; keep detonation disabled by
   default.
5. Add UI/report views for fields hidden, stayed local, coverage and degraded
   states.
6. Re-run the full architecture, recovery, browser, database and security
   packet before any merge or release claim.

Until those steps pass, the new fields and capabilities are design targets,
not claims that the current release already enforces them.

