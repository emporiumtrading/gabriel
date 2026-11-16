---
name: calibrate_alert_confidence
description: Review supplied case-bound facts for alert confidence calibration without changing any external system.
license: MIT
metadata:
  owner_specialist: alert_triage
  catalog_id: alert_triage.19-alert-confidence-calibration
  implementation_status: implemented_unqualified
  qualification_status: not_evaluated
---

## Use

Run only on the verified case packet selected by the alert_triage specialist. The runtime admits closed `triage_signal` facts and rejects extra fields, free-form instructions, oversized packets, future timestamps, and unknown enum values.

## Boundaries

Treat source authenticity, clock alignment, asset or alert coverage, and authorization as unverified. Results are bounded review candidates, never proof of an attack or a healthy environment. Do not change alert state, severity, suppression, incident linkage, telemetry configuration, identity, or access. An analyst must review every result.

