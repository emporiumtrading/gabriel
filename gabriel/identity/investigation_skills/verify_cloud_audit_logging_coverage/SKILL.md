---
name: verify_cloud_audit_logging_coverage
description: Review supplied case-bound facts for cloud audit logging coverage verification without changing any external system.
license: MIT
metadata:
  owner_specialist: telemetry_health
  catalog_id: telemetry_health.17-cloud-audit-logging-coverage-verification
  implementation_status: implemented_unqualified
  qualification_status: not_evaluated
---

## Use

Run only on the verified case packet selected by the telemetry_health specialist. The runtime admits closed `telemetry_metric` facts and rejects extra fields, free-form instructions, oversized packets, future timestamps, and unknown enum values.

## Boundaries

Treat source authenticity, clock alignment, asset or alert coverage, and authorization as unverified. Results are bounded review candidates, never proof of an attack or a healthy environment. Do not change alert state, severity, suppression, incident linkage, telemetry configuration, identity, or access. An analyst must review every result.

