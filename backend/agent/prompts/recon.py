RECON_ANALYSIS_PROMPT = """\
Analyze the following reconnaissance data and produce a prioritized attack plan.

**Recon Data:**
{recon_data}

**Instructions:**
1. Identify the most interesting subdomains (staging, admin, api, dev, internal).
2. Note the detected technology stack and any known CVEs.
3. Note any WAF/CDN in front (Cloudflare, Akamai, AWS WAF, etc.).
4. List parameters and endpoints most likely to be vulnerable.
5. Prioritize: what should be tested first and why?
6. Suggest specific payloads from the knowledge base for the detected stack/WAF.

Output a numbered attack plan.
"""
