---
name: assess_emergency_change_impact
description: Review supplied availability, integrity and recovery impact assertions for an emergency change.
license: MIT
metadata:
  role: response_remediation
  status: implemented_unqualified
---

# Assess Emergency Change Impact

Review supplied availability, integrity and recovery impact assertions for an emergency change.

Use only case-bound typed facts whose evidence integrity was checked by Gabriel. Treat source authenticity, clocks, entity binding, policy baselines, and current authority as unverified unless separate evidence establishes them. The result is an analyst review aid, not an incident verdict or action authorization.

The implementation never performs external actions, changes a console, mutates an account or control, restores a system, accepts risk, or closes an incident. An engineer must separately verify the evidence and explicitly approve any proposed action.
