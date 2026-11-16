---
name: recommend_firewall_containment
description: Review supplied firewall-containment target assertions without changing a firewall.
license: MIT
metadata:
  role: response_remediation
  status: implemented_unqualified
---

# Recommend Firewall Containment

Review supplied firewall-containment target assertions without changing a firewall.

Use only case-bound typed facts whose evidence integrity was checked by Gabriel. Treat source authenticity, clocks, entity binding, policy baselines, and current authority as unverified unless separate evidence establishes them. The result is an analyst review aid, not an incident verdict or action authorization.

The implementation never performs external actions, changes a console, mutates an account or control, restores a system, accepts risk, or closes an incident. An engineer must separately verify the evidence and explicitly approve any proposed action.
