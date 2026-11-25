# Gabriel photo gallery

This gallery collects the current Gabriel product photography in one place. It uses the repository's own interface captures and brand artwork—not generic AI-generated stock images. Every photo is assigned to a workflow stage and has a description. Screens marked **generated-data capture** show the real workbench rendered with synthetic test data; they are not evidence of live-console coverage, production AI qualification, or a completed response action.

## Photo stages

| Stage | Purpose | Repository assets |
| --- | --- | --- |
| 0 — Product identity | Establish Gabriel's visual identity | `mark.svg`, `banner.svg`, `social-preview.png` |
| 1 — Preflight and assignment | Confirm scope, choose a specialist, and select an allowed tool | `preview-preflight.png`, `preview-specialists.png`, `select-investigation-tool.png` |
| 2 — Investigation | Review the queue, case workspace, and verified local findings | `investigations.png`, `case-workspace.png`, `verified-tool-findings.png` |
| 3 — Specialist analysis | Review specialist assessments and assign the next action | `specialist-assessments.png`, `analyst-next-actions.png` |
| 4 — Evidence and learning | Inspect provenance and review references before reuse | `case-provenance.png`, `review-before-learning.png` |
| 5 — Governance and response | Review spending controls and proposed response approval | `spending-controls.png`, `preview-response.png` |
| 6 — Mobile review | Continue analyst review from a smaller screen | `mobile-case.png`, `mobile-analyst-review.png` |

## Stage 0 — Product identity

### Gabriel mark

![Gabriel halo and shield mark](mark.svg)

The primary Gabriel emblem: a halo and winged shield used to identify the defensive investigation workbench.

### Gabriel banner

![Gabriel — The Defender banner](banner.svg)

The repository banner used for the project landing page and documentation.

### Social preview

![Gabriel social preview](social-preview.png)

The share-card artwork for repository links and project announcements.

## Stage 1 — Preflight and assignment

### Preflight before autonomous investigation

![Stage 1: preflight before autonomous investigation](actions/preview-preflight.png)

**Design preview.** Illustrates the consent and readiness review before a browser investigation begins. The control is not presented as an implemented response action.

### Supervisor assignments and analyst progress

![Stage 1: supervisor assignments and analyst progress](actions/preview-specialists.png)

**Design preview.** Illustrates Hermes coordinating bounded specialist assignments while keeping analyst progress visible.

### Select an investigation tool

![Stage 1: select an investigation tool](actions/select-investigation-tool.png)

**Generated-data capture.** Shows a specialist selecting an allowed local investigation tool before execution.

## Stage 2 — Investigation

### Investigation queue

![Gabriel investigation queue](screenshots/investigations.png)

**Generated-data capture.** Shows cases and investigation assignments waiting for analyst review.

### Case workspace

![Gabriel case workspace](screenshots/case-workspace.png)

**Generated-data capture.** Shows the case view that brings evidence, timeline, questions, and provenance together.

### Verified tool findings

![Stage 2: verified tool findings](actions/verified-tool-findings.png)

**Generated-data capture.** Shows the analyst reviewing an encrypted local log-analysis result.

## Stage 3 — Specialist analysis

### Specialist assessments

![Stage 3: Gabriel specialist assessments](screenshots/specialist-assessments.png)

**Generated-data capture.** Shows bounded specialist findings with confidence and review status visible to the analyst.

### Analyst next actions

![Stage 3: analyst next actions](actions/analyst-next-actions.png)

**Generated-data capture.** Shows ownership assignment, finding recording, and the next investigation question.

## Stage 4 — Evidence and learning

### Case provenance

![Stage 4: Gabriel case provenance](screenshots/case-provenance.png)

**Generated-data capture.** Shows the evidence trail behind a finding, including source, custody, and review metadata.

### Review before learning

![Stage 4: review before learning](actions/review-before-learning.png)

**Generated-data capture.** Shows a proposed organizational reference before an analyst approves reuse.

## Stage 5 — Governance and response

### Spending controls

![Stage 5: Gabriel spending controls](screenshots/spending-controls.png)

**Generated-data capture.** Shows provider budgets, model-routing controls, and cost guardrails.

### Proposed response and analyst approval

![Stage 5: proposed response and analyst approval](actions/preview-response.png)

**Design preview.** Illustrates a proposed response awaiting an explicit analyst decision; it does not execute a response action.

## Stage 6 — Mobile review

The mobile photos show review continuity, not autonomous response from a phone.

### Mobile case review

![Stage 6: Gabriel mobile case review](screenshots/mobile-case.png)

**Generated-data capture.** Shows the responsive case-review layout for a smaller screen.

### Mobile analyst review

![Stage 6: mobile analyst review](actions/mobile-analyst-review.png)

**Generated-data capture.** Shows investigation questions and review controls in the mobile layout.

## Evidence and limitations

The image checksums and capture provenance are maintained in the adjacent [screen manifest](screenshots/manifest.json) and [action manifest](actions/manifest.json). No customer telemetry, provider credentials, or paid model calls were used for these captures. Refer to the repository README and security documentation for the current qualification and operational status.
