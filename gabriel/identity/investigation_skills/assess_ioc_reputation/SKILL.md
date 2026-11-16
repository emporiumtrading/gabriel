---
name: assess_ioc_reputation
description: Review bounded ioc reputation assertions from case-bound typed evidence.
license: MIT
metadata:
  role: threat_intelligence
  implementation_status: implemented_unqualified
  external_actions_allowed: false
---

# Assess Ioc Reputation

Use this skill only for analyst-requested review of supplied `intelligence_assertion` facts whose topic is `ioc_reputation`.

It validates closed fields, case-local aliases, source authorization, effective and expiry intervals, and locally verified evidence digests. It preserves conflicting assertions and reports source counts without treating feeds as independent or authentic.

The result is a bounded review queue. It never performs a live intelligence lookup, attributes an actor, changes a detection, or authorizes an external action. Every conclusion remains unqualified and requires analyst review.

