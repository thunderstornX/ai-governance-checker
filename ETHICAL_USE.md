# Ethical use

This tool is intended as a **defensive audit aid** for teams preparing to
deploy LLM-based systems. It is not a stamp of approval, an
attestation, or a substitute for an actual compliance review.

## What this tool does

* Takes a system prompt as input (a `.txt` file or stdin).
* Runs three rule-based check engines:
  * The OWASP Top 10 for LLM Applications, 2025 revision.
  * The four NIST AI Risk Management Framework 1.0 functions.
  * The EU AI Act high-risk-system checklist.
* Optionally forwards the prompt to a hosted (Anthropic Claude) or
  local (Ollama) judge model for a second-opinion structured
  assessment.
* Emits a Markdown compliance report and a machine-readable JSON
  report with each finding tagged by its source framework section
  (e.g., `LLM01:2025`, `GOVERN-1.1`, `EU-AIA-Art-14`).

## What this tool does not do

* It does **not** read your model's training data, weights, or
  evaluation logs. It only sees the system prompt you hand it.
* It does **not** audit running production systems, transcripts,
  customer data, or telemetry. Anything beyond the static system
  prompt is out of scope.
* It does **not** issue compliance certificates. The report is an
  *aid* to a real review, never a replacement for one. A "0 findings"
  result does not mean a system is compliant; it means the included
  rules did not match.
* It does **not** redistribute Anthropic, Ollama, or any other
  vendor's model weights or proprietary content.

## Authorised use only

By using this software you affirm that:

1. You have authority to audit the prompt you supply, or you wrote it
   yourself.
2. You will not use the tool to coach an adversarial actor through
   bypassing governance controls. The rule patterns are useful in
   both directions; please use them in the right one.
3. You will respect the rate limits of any upstream LLM you point
   the optional judge at. The tool already enforces sane defaults;
   do not patch them out.
4. If you redistribute the tool, you keep this file and carry the
   same restrictions through.

## Framework attributions

The following frameworks are cited and partially encoded in this
tool's rule packs. Each remains the property of its respective
publisher; the rule pack is a *checklist implementation* of the
publicly available text, not a redistribution of it:

* OWASP Top 10 for LLM Applications (2025) — © OWASP Foundation,
  Creative Commons Attribution-ShareAlike 4.0.
* NIST AI Risk Management Framework 1.0 (NIST AI 100-1) — public
  domain U.S. government work.
* EU AI Act, Regulation (EU) 2024/1689 — © European Union,
  reproduction permitted with source acknowledged.

This software is provided as-is under the MIT license. The license
does not override the ethical and legal expectations above; the two
stand together.
