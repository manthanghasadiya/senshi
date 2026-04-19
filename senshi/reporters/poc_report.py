"""
PoC Report Generator — Creates runnable verification scripts from findings.

Generates:
  1. poc_verify.sh  — Bash script with curl commands for each finding
  2. poc_verify.py  — Python script with requests calls + response validation
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime

from senshi.reporters.models import Finding, Severity


def generate_poc_script(
    findings: list[Finding],
    target: str = "",
    cookie: str = "",
    output_dir: str = ".",
) -> tuple[str, str]:
    """Generate PoC verification scripts.
    
    Returns (bash_path, python_path) of generated files.
    """
    # Filter to only findings with PoC data
    poc_findings = [f for f in findings if f.poc_curl or f.poc_python]
    if not poc_findings:
        return "", ""
    
    bash_script = _generate_bash_poc(poc_findings, target, cookie)
    python_script = _generate_python_poc(poc_findings, target, cookie)
    
    bash_path = str(Path(output_dir) / "poc_verify.sh")
    python_path = str(Path(output_dir) / "poc_verify.py")
    
    Path(bash_path).write_text(bash_script, encoding="utf-8")
    Path(python_path).write_text(python_script, encoding="utf-8")
    
    return bash_path, python_path


def _generate_bash_poc(findings: list[Finding], target: str, cookie: str) -> str:
    """Generate bash PoC script with curl commands."""
    lines = [
        "#!/bin/bash",
        "#",
        f"# Senshi PoC Verification Script",
        f"# Target: {target}",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Findings: {len(findings)}",
        "#",
        "# Run: chmod +x poc_verify.sh && ./poc_verify.sh",
        "# Or:  bash poc_verify.sh",
        "#",
        '# Add your session cookie below if needed:',
        f'COOKIE="{cookie}"',
        "",
        'RED="\\033[0;31m"',
        'GREEN="\\033[0;32m"',
        'YELLOW="\\033[0;33m"',
        'CYAN="\\033[0;36m"',
        'NC="\\033[0m"',
        "",
        'echo ""',
        'echo "=========================================="',
        'echo " Senshi PoC Verification"',
        f'echo " {len(findings)} findings to verify"',
        'echo "=========================================="',
        'echo ""',
        "",
    ]
    
    for i, f in enumerate(findings, 1):
        if not f.poc_curl:
            continue
        
        sev = f.severity.value.upper()
        sev_color = {"CRITICAL": "$RED", "HIGH": "$RED", "MEDIUM": "$YELLOW", "LOW": "$CYAN"}.get(sev, "$NC")
        
        # Add cookie to curl if needed
        curl_cmd = f.poc_curl
        if cookie and "-b" not in curl_cmd and "--cookie" not in curl_cmd:
            curl_cmd = curl_cmd.replace("curl ", f'curl -b "$COOKIE" ', 1)
        
        lines.extend([
            f'echo -e "{sev_color}[{sev}]{NC} Finding {i}: {f.title}"',
            f'echo "  Endpoint: {f.method} {f.endpoint}"',
            f'echo "  Payload:  {f.payload[:60]}"',
            f'echo ""',
            f'echo "  Running PoC..."',
            f'echo "  $ {curl_cmd[:120]}"',
            f'echo ""',
            "",
            f'RESPONSE=$({curl_cmd} -s 2>&1)',
            "",
            '# Show first 500 chars of response',
            'echo "  Response (first 500 chars):"',
            'echo "$RESPONSE" | head -c 500',
            'echo ""',
            'echo ""',
        ])
        
        # Add evidence check
        if f.evidence:
            # Extract a key evidence string to grep for
            evidence_key = _extract_evidence_key(f)
            if evidence_key:
                lines.extend([
                    f'if echo "$RESPONSE" | grep -qi "{evidence_key}"; then',
                    f'    echo -e "  ${{GREEN}}[VERIFIED] Evidence found: {evidence_key[:50]}${{NC}}"',
                    'else',
                    f'    echo -e "  ${{YELLOW}}[NOT FOUND] Expected evidence not in response${{NC}}"',
                    'fi',
                    'echo ""',
                ])
        
        lines.extend([
            'echo "------------------------------------------"',
            'echo ""',
            "",
        ])
    
    lines.extend([
        'echo "=========================================="',
        'echo " Verification complete"',
        'echo "=========================================="',
    ])
    
    return "\n".join(lines)


def _generate_python_poc(findings: list[Finding], target: str, cookie: str) -> str:
    """Generate Python PoC script with requests and response validation."""
    lines = [
        '"""',
        f'Senshi PoC Verification Script',
        f'Target: {target}',
        f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'Findings: {len(findings)}',
        '',
        'Run: python poc_verify.py',
        'Requirements: pip install requests',
        '"""',
        '',
        'import re',
        'import sys',
        'import requests',
        'import urllib3',
        'urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)',
        '',
        f'COOKIE = "{cookie}"',
        '',
        'COLORS = {',
        '    "RED": "\\033[0;31m",',
        '    "GREEN": "\\033[0;32m",',
        '    "YELLOW": "\\033[0;33m",',
        '    "CYAN": "\\033[0;36m",',
        '    "BOLD": "\\033[1m",',
        '    "NC": "\\033[0m",',
        '}',
        '',
        'def color(text, c):',
        '    return f"{COLORS.get(c, \\"\\")}{text}{COLORS[\\"NC\\"]}"',
        '',
        'def get_session():',
        '    s = requests.Session()',
        '    s.verify = False',
        '    if COOKIE:',
        '        for part in COOKIE.split(";"):',
        '            part = part.strip()',
        '            if "=" in part:',
        '                key, val = part.split("=", 1)',
        '                s.cookies.set(key.strip(), val.strip())',
        '    return s',
        '',
        '',
        'def main():',
        '    s = get_session()',
        '    results = []',
        f'    print("\\n" + "=" * 50)',
        f'    print(" Senshi PoC Verification")',
        f'    print(f" {{len(POCS)}} findings to verify")',
        f'    print("=" * 50 + "\\n")',
        '',
        '    for i, poc in enumerate(POCS, 1):',
        '        sev = poc["severity"]',
        '        sev_color = {"CRITICAL": "RED", "HIGH": "RED", "MEDIUM": "YELLOW", "LOW": "CYAN"}.get(sev, "NC")',
        '        print(f"{color(f\\"[{sev}]\\", sev_color)} Finding {i}: {poc[\\"title\\"]}")',
        '        print(f"  Endpoint: {poc[\\"method\\"]} {poc[\\"endpoint\\"]}")',
        '        print(f"  Payload:  {poc[\\"payload\\"][:60]}")',
        '        print()',
        '',
        '        try:',
        '            if poc["method"] == "GET":',
        '                resp = s.get(poc["url"], params=poc.get("params", {}), timeout=10)',
        '            else:',
        '                if poc.get("json_body"):',
        '                    resp = s.post(poc["url"], json=poc.get("data", {}), timeout=10)',
        '                else:',
        '                    resp = s.post(poc["url"], data=poc.get("data", {}), timeout=10)',
        '',
        '            print(f"  Status: {resp.status_code}")',
        '            print(f"  Response length: {len(resp.text)} chars")',
        '',
        '            # Check for evidence',
        '            verified = False',
        '            if poc.get("evidence_pattern"):',
        '                if re.search(poc["evidence_pattern"], resp.text, re.IGNORECASE):',
        '                    print(f"  {color(\\"[VERIFIED]\\", \\"GREEN\\")} Evidence found: {poc[\\"evidence_pattern\\"][:50]}")',
        '                    verified = True',
        '                else:',
        '                    print(f"  {color(\\"[NOT FOUND]\\", \\"YELLOW\\")} Expected evidence not in response")',
        '',
        '            # Show response snippet',
        '            print(f"  Response preview: {resp.text[:200]}")',
        '            results.append({"finding": i, "title": poc["title"], "verified": verified, "status": resp.status_code})',
        '',
        '        except Exception as e:',
        '            print(f"  {color(\\"[ERROR]\\", \\"RED\\")} Request failed: {e}")',
        '            results.append({"finding": i, "title": poc["title"], "verified": False, "status": 0})',
        '',
        '        print()',
        '        print("-" * 50)',
        '        print()',
        '',
        '    # Summary',
        '    verified_count = sum(1 for r in results if r["verified"])',
        '    print(f"\\n{\\"=\\" * 50}")',
        '    print(f" Results: {verified_count}/{len(results)} verified")',
        '    print(f"{\\"=\\" * 50}")',
        '    for r in results:',
        '        status = color("[VERIFIED]", "GREEN") if r["verified"] else color("[UNVERIFIED]", "YELLOW")',
        '        print(f"  {status} Finding {r[\\"finding\\"]}: {r[\\"title\\"]}")',
        '    print()',
        '',
        '',
    ]
    
    # Generate POCS list
    lines.append("POCS = [")
    for f in findings:
        if not f.poc_curl and not f.poc_python:
            continue
        
        # Parse the PoC into structured data
        poc_entry = _finding_to_poc_entry(f)
        lines.append(f"    {poc_entry},")
    lines.append("]")
    
    lines.extend([
        '',
        '',
        'if __name__ == "__main__":',
        '    main()',
    ])
    
    return "\n".join(lines)


def _finding_to_poc_entry(f: Finding) -> str:
    """Convert a Finding to a Python dict literal for the POCS list."""
    from urllib.parse import urlparse, parse_qs
    
    url = f.endpoint.split("?")[0] if f.endpoint else ""
    evidence_pattern = _extract_evidence_key(f)
    
    # Parse params from the PoC curl or endpoint
    params = {}
    data = {}
    json_body = False
    
    if f.poc_python:
        # Try to extract params/data from poc_python
        if "params=" in f.poc_python:
            # Extract dict from params={...}
            import re as _re
            m = _re.search(r"params=(\{[^}]+\})", f.poc_python)
            if m:
                try:
                    params = eval(m.group(1))
                except:
                    pass
        if "data=" in f.poc_python:
            import re as _re
            m = _re.search(r"data=(\{[^}]+\})", f.poc_python)
            if m:
                try:
                    data = eval(m.group(1))
                except:
                    pass
        if "json=" in f.poc_python:
            import re as _re
            m = _re.search(r"json=(\{[^}]+\})", f.poc_python)
            if m:
                try:
                    data = eval(m.group(1))
                    json_body = True
                except:
                    pass
    
    return repr({
        "title": f.title,
        "severity": f.severity.value.upper(),
        "endpoint": f.endpoint,
        "method": f.method or "GET",
        "url": url,
        "payload": f.payload,
        "params": params,
        "data": data,
        "json_body": json_body,
        "evidence_pattern": evidence_pattern,
        "poc_curl": f.poc_curl,
    })


def _extract_evidence_key(f: Finding) -> str:
    """Extract a grep-able evidence string from a finding."""
    evidence = f.evidence
    
    # For CMDi: look for uid= pattern
    if "uid=" in evidence:
        return r"uid=\d+"
    # For LFI: look for root:x:0:0
    if "root:x:0:0" in evidence or "/etc/passwd" in evidence:
        return "root:x:0:0"
    # For XSS: look for the payload itself
    if "reflected" in evidence.lower() and f.payload:
        return f.payload[:30]
    # For SQLi: look for error or marker
    if "SQLITE_ERROR" in evidence:
        return "SQLITE_ERROR"
    if "senshi_union" in evidence:
        return "senshi_union"
    if "SQL error" in evidence:
        return "SQL"
    # For SSRF: metadata keywords
    if "computeMetadata" in evidence:
        return "computeMetadata"
    # For open redirect
    if "Location:" in evidence:
        return "evil.com"
    # Generic: use first 30 chars of evidence
    if evidence:
        # Clean up for grep
        clean = evidence.split(":")[0].strip()[:30]
        return clean
    return ""
