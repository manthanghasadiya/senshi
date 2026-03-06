# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅         |

## Reporting a Vulnerability

If you discover a security vulnerability in Senshi itself, please report it responsibly.

**Do NOT open a public GitHub issue.**

Instead, please email: **manthan@ghasadiya.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours and a detailed response within 7 days.

## Responsible Use

Senshi is designed for **authorized security testing only**. By using this tool, you agree to:

1. **Only scan targets you have explicit written permission to test**
2. **Comply with all applicable laws** in your jurisdiction
3. **Follow responsible disclosure** practices for any findings
4. **Not use this tool for malicious purposes**

The author is not responsible for any misuse of this tool. Unauthorized scanning of systems you do not own or have permission to test is illegal.

## API Key Security

- Never commit API keys to version control
- Use environment variables (`DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, etc.)
- The `senshi config` command stores keys in `~/.senshi/config.json` — ensure appropriate file permissions
- API keys are masked in `senshi config --show` output
