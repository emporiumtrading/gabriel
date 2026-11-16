---
name: verify_system_restoration
description: Review reported system-restoration validation against a current baseline.
license: MIT
metadata:
  role: recovery_learning
  status: implemented_unqualified
---

# Verify System Restoration

Review reported system-restoration validation against a current baseline.

Use only case-bound typed facts whose evidence integrity was checked by Gabriel. Treat source authenticity, clocks, entity binding, policy baselines, and current authority as unverified unless separate evidence establishes them. The result is an analyst review aid, not an incident verdict or action authorization.

The implementation never performs external actions, changes a console, mutates an account or control, restores a system, accepts risk, or closes an incident. An engineer must separately verify the evidence and explicitly approve any proposed action.
