---
name: investigate_linux_command_anomalies
description: Review bounded linux command observations from case-bound typed evidence.
license: MIT
metadata:
  role: threat_hunting
  implementation_status: implemented_unqualified
  external_actions_allowed: false
---

# Investigate Linux Command Anomalies

Use this skill only for analyst-requested review of supplied `hunt_observation` facts whose behavior is `linux_command`.

It groups observations only by the supplied entity and correlation aliases, checks source integrity, validity, baseline and reported authorization, and preserves conflicts. Absence of an observation never proves absence of activity.

The result is a bounded review queue. It never queries a live system, contains an endpoint, changes a control, declares compromise, or authorizes an external action. Every conclusion remains unqualified and requires analyst review.
