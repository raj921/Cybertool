ATTACK_PLAN_PROMPT = """\
You have completed reconnaissance. Here is what you know:

**Technologies:** {technologies}
**WAF/CDN:** {waf}
**Subdomains of interest:** {subdomains}
**Key endpoints:** {endpoints}
**Parameters found:** {parameters}

**Knowledge base loaded for:** {knowledge_loaded}

Now plan your attack. For each endpoint:
1. What vulnerability type to test
2. Which specific payloads to use (considering the WAF)
3. Whether this could chain with other findings
4. Priority order

Think step by step. Be creative — look for logic bugs, not just injection.
"""

CHAIN_ANALYSIS_PROMPT = """\
Analyze these findings for possible attack chains:

{findings}

Look for combinations like:
- Open redirect + OAuth = Account Takeover
- SSRF + Cloud metadata = Infrastructure compromise
- XSS + CSRF = Self-propagating worm
- IDOR + No rate limit = Mass data exfiltration
- Information disclosure + Known CVE = RCE

Output any chains found as [CHAIN] blocks.
"""
