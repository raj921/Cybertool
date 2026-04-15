"""PoC Generator -- creates reproducible exploit proofs."""
from __future__ import annotations

from urllib.parse import quote


def generate_poc(
    finding_type: str,
    url: str,
    payload: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
) -> dict:
    """Generate a PoC for a confirmed finding."""
    poc = {
        "type": finding_type,
        "url": url,
        "curl_command": "",
        "python_script": "",
        "http_request": "",
    }

    # curl command
    curl_parts = ["curl -v"]
    if method != "GET":
        curl_parts.append(f"-X {method}")
    for k, v in (headers or {}).items():
        curl_parts.append(f'-H "{k}: {v}"')
    if body:
        curl_parts.append(f"-d '{body}'")
    curl_parts.append(f'"{url}"')
    poc["curl_command"] = " \\\n  ".join(curl_parts)

    # Python script
    poc["python_script"] = f'''import requests

url = "{url}"
headers = {headers or {}}
response = requests.{method.lower()}(url, headers=headers{f', data="""{body}"""' if body else ''}, verify=False)

print(f"Status: {{response.status_code}}")
print(f"Length: {{len(response.text)}}")
print(response.text[:1000])
'''

    # Raw HTTP request
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    http_lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for k, v in (headers or {}).items():
        http_lines.append(f"{k}: {v}")
    if body:
        http_lines.append(f"Content-Length: {len(body)}")
        http_lines.append("")
        http_lines.append(body)
    poc["http_request"] = "\r\n".join(http_lines)

    return poc
