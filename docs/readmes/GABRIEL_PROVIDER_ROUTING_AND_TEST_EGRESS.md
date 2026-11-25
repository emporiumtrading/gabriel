# Gabriel provider routing, minimization and performance-test contract

## Provider and model assignment

Gabriel treats the provider and model as one signed, versioned configuration. A
specialist job records both values, and a resumed job must use the same pair;
it cannot silently fall back to another provider. The workbench exposes the
currently implemented choices (OpenRouter and DeepInfra) for Hermes and each
specialist. A provider/model pair is still blocked until its exact configuration
digest is in the reviewed production-admission set.

OpenRouter uses the existing candidate registry and its explicit no-fallback,
data-collection-deny and zero-data-retention request parameters. DeepInfra uses
its fixed OpenAI-compatible host and only the bounded direct model IDs in the
registry. DeepInfra account-limit and model-catalog checks are performed at
dispatch, but an API key cannot prove a provider's retention or training terms;
that policy must be separately reviewed before a production configuration is
admitted. ChatGPT/OpenAI, Anthropic Claude, DeepSeek and Kimi can be added as
separate fixed-host adapters later. A ChatGPT consumer subscription is not an
API credential, and Gabriel must never accept an arbitrary endpoint or model ID.

Autonomous assignment is allowed only inside the reviewed registry: Hermes may
select an eligible role, while the provider/model policy supplies an allowlisted
pair and budget. It cannot invent a model, change provider, or retry through a
different provider after an ambiguous request. A user can override the pair in
the workbench dropdown; the selected pair is persisted in the run/job receipt.

## Token and data minimization

The local path is deliberately typed and bounded:

1. Browser and source artifacts remain encrypted and local.
2. Local adapters produce typed facts; raw page text, log bodies, cookies,
   authorization headers, credentials, URLs and the private identity map are
   excluded from model packets.
3. Facts are pseudonymized per organization/case/key, deduplicated without
   adding counts, ordered deterministically, and accompanied by opaque local
   evidence references.
4. Specialist and Hermes packets are capped at 4 KiB; the canonical provider
   request is capped at 7 KiB and the provider transport rejects larger bodies.
   A request is refused rather than silently cropped.
5. The budget service reserves bounded input/output tokens before dispatch and
   records provider usage and cost. Local rules and read-only tools run first,
   so a model is called only when the specialist needs interpretation.

These limits reduce cost and exposure; they do not make pseudonymization
anonymous or guarantee a particular tokenizer's count. The packet explicitly
labels partial coverage and unverified source semantics.

## Egress and training-data boundary

Gabriel sends only the minimized typed packet after current consent, case
authorization, provider-key checks, source verification, budget reservation and
exact configuration admission. Secrets and private manifests never enter a
provider request, log, prompt, or public artifact. A provider's retention or
training behavior is not inferred from a successful HTTP response. If the
provider policy is not independently attested, the configuration remains
qualification-pending even though local redaction still holds.

## TryHackMe performance testing

Use a separate organization and a fresh case with purpose
`performance_test`. This disables reviewed-memory proposals/retrieval and does
not fine-tune models or change model weights. Gabriel records encrypted source
evidence, browser/tool observations, custody, model/provider/configuration
digests, prompts' hashes, token/cost usage, navigation failures, stop/revocation
events, crashes, unresolved requests and analyst review. The records are the
performance evidence and remain separate from operational memory.

During a scored round the build, prompt, tools, model pair and learning state
are frozen. A discovered defect is preserved as a failure, then fixed in a new
version and rerun in a new performance-test case. Gabriel may produce a bounded
diagnosis or remediation proposal, but it does not rewrite its own code, alter
the baseline, promote simulator data to training data, or claim that a retest
erased the original failure.
