VALIDATION_PROMPT = """\
Verify this potential finding. Determine if it is a true positive or false positive.

**Finding type:** {finding_type}
**URL:** {url}
**Payload used:** {payload}
**Baseline response (no payload):**
  Status: {baseline_status}
  Length: {baseline_length}
  Snippet: {baseline_snippet}

**Payload response:**
  Status: {payload_status}
  Length: {payload_length}
  Snippet: {payload_snippet}

**Analysis checklist:**
1. Does the payload appear reflected/executed in the response?
2. Is the difference between baseline and payload response significant?
3. Could the difference be caused by something other than the vulnerability?
4. Is the context exploitable (e.g., inside a script tag vs HTML comment)?
5. Would a benign input cause a similar change?

Output:
- Verdict: TRUE_POSITIVE or FALSE_POSITIVE
- Confidence: 0–100
- Reasoning: explain why
"""
