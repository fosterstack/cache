# Scanner-panel audit prompts (scanner-panel rules 8 and 8(c); REQ-SCAN-008)

Versioned instructions for the two auditor seats that judge findings only one scanner reported. They change only
through reviewed pull requests. Each section is a `## <key>` heading; `{finding}`, `{bundle}`, `{own_case}`,
`{opponent_case}` and `{scoring}` are filled by the auditor. Answers are ONE JSON object.

## audit
You are auditing a container-image vulnerability finding that only one of our scanners reported. Findings like this
are presumed false positives until evidence from the image itself shows otherwise.

The finding:
{finding}

Evidence extracted from the image (its package database entries, matching file paths, and Go build information):
{bundle}

Decide whether the named package at the named version is actually present in the image. Use only the evidence above.
Answer with ONE JSON object and nothing else:
{"verdict": "real" or "false", "evidence": ["exact lines copied from the evidence above that prove your verdict"],
 "why": "if real: what in the image this scanner read that other scanners did not; otherwise null",
 "case": "two or three sentences arguing your verdict from the quoted evidence"}
Every string in "evidence" must be copied verbatim from the evidence above; a verdict without such a quote counts as
no evidence. Do not speculate about exploitability; judge presence only.

## case
A second auditor disagrees with you about this finding. Investigate the image evidence again and build your strongest
case, from quoted evidence only, aiming to convince the other auditor.

{scoring}

The finding:
{finding}

Evidence extracted from the image:
{bundle}

Your previous case:
{own_case}

The other auditor's previous case:
{opponent_case}

Answer with ONE JSON object and nothing else:
{"verdict": "real" or "false", "evidence": ["exact lines copied from the evidence above"], "why": "as before or null",
 "case": "your case in at most five sentences"}

## verdict
Read the other auditor's case, then give your final verdict for this round. Change your verdict only if the quoted
evidence convinces you.

{scoring}

The finding:
{finding}

Evidence extracted from the image:
{bundle}

Your case:
{own_case}

The other auditor's case:
{opponent_case}

Answer with ONE JSON object and nothing else:
{"verdict": "real" or "false", "evidence": ["exact lines copied from the evidence above"], "why": "as before or null",
 "case": "one sentence on what decided it"}
