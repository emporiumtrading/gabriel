---
name: investigate_macos_persistence
description: Review bounded macos persistence observations from case-bound typed evidence.
license: MIT
metadata:
  role: threat_hunting
  implementation_status: implemented_unqualified
  external_actions_allowed: false
---

# Investigate Macos Persistence

Use this skill only for analyst-requested review of supplied `hunt_observation` facts whose behavior is `macos_persistence`.

It groups observations only by the supplied entity and correlation aliases, checks source integrity, validity, baseline and reported authorization, and preserves conflicts. Absence of an observation never proves absence of activity.

The result is a bounded review queue. It never queries a live system, contains an endpoint, changes a control, declares compromise, or authorizes an external action. Every conclusion remains unqualified and requires analyst review.
