---
name: reassess_security_control_effectiveness
description: Review reported control-effectiveness findings without certifying the control.
license: MIT
metadata:
  role: recovery_learning
  status: implemented_unqualified
---

# Reassess Security Control Effectiveness

Review reported control-effectiveness findings without certifying the control.

Use only case-bound typed facts whose evidence integrity was checked by Gabriel. Treat source authenticity, clocks, entity binding, policy baselines, and current authority as unverified unless separate evidence establishes them. The result is an analyst review aid, not an incident verdict or action authorization.

The implementation never performs external actions, changes a console, mutates an account or control, restores a system, accepts risk, or closes an incident. An engineer must separately verify the evidence and explicitly approve any proposed action.
