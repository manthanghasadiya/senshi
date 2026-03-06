"""
Microsoft Copilot target profile — expanded for v0.3.0 autonomous pentesting.
"""

from __future__ import annotations

PROFILE = {
    "name": "Microsoft Copilot",
    "base_url": "https://copilot.microsoft.com",

    "endpoints": [
        {"url": "/c/api/conversations", "method": "GET", "params": ["api-version"], "auth_required": True},
        {"url": "/c/api/conversations", "method": "POST", "params": [], "auth_required": True},
        {"url": "/c/api/conversations/{id}/history", "method": "GET", "params": ["api-version"], "auth_required": True},
        {"url": "/c/api/conversations/{id}", "method": "DELETE", "params": [], "auth_required": True},
        {"url": "/c/api/attachments", "method": "POST", "params": [], "auth_required": True, "content_type": "multipart"},
        {"url": "/c/api/library/recent", "method": "GET", "params": ["limit"], "auth_required": True},
        {"url": "/c/api/projects", "method": "GET", "params": [], "auth_required": True},
        {"url": "/c/api/config", "method": "GET", "params": ["api-version"], "auth_required": True},
        {"url": "/c/api/clarity/signal", "method": "POST", "params": [], "auth_required": True},
    ],

    "websocket_endpoints": [
        {"url": "wss://copilot.microsoft.com/c/api/chat", "params": ["api-version", "clientSessionId", "accessToken"]},
    ],

    "auth": {
        "type": "cookie+bearer",
        "cookie_names": ["_EDGE_S", "MUID", "_C_Auth", "__Host-copilot-anon"],
        "bearer_header": "authorization",
    },

    "scope": [
        "*.copilot.microsoft.com",
        "copilot.microsoft.com",
        "!login.microsoftonline.com",
        "!login.live.com",
        "!*.login.microsoft.com",
    ],

    "in_scope_tests": ["idor", "ssrf", "xss", "injection", "auth", "deserialization"],
    "out_of_scope_tests": ["prompt_injection", "jailbreak"],

    "rate_limit": 2.0,

    "bounty": {
        "program": "Microsoft AI Bounty Program",
        "url": "https://www.microsoft.com/en-us/msrc/bounty-ai",
        "max_bounty": "$30,000",
        "report_url": "https://msrc.microsoft.com/report/vulnerability/new",
    },
}
