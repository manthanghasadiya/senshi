"""
OpenAI ChatGPT target profile.
"""

from __future__ import annotations

PROFILE = {
    "name": "OpenAI ChatGPT",
    "base_url": "https://chatgpt.com",

    "endpoints": [
        {"url": "/backend-api/conversations", "method": "GET", "params": ["offset", "limit"], "auth_required": True},
        {"url": "/backend-api/conversation/{id}", "method": "GET", "params": [], "auth_required": True},
        {"url": "/backend-api/conversation/{id}", "method": "PATCH", "params": [], "auth_required": True},
        {"url": "/backend-api/conversation/{id}", "method": "DELETE", "params": [], "auth_required": True},
        {"url": "/backend-api/conversation", "method": "POST", "params": [], "auth_required": True},
        {"url": "/backend-api/models", "method": "GET", "params": [], "auth_required": True},
        {"url": "/backend-api/me", "method": "GET", "params": [], "auth_required": True},
        {"url": "/backend-api/settings/user", "method": "GET", "params": [], "auth_required": True},
        {"url": "/backend-api/accounts/check", "method": "GET", "params": [], "auth_required": True},
        {"url": "/backend-api/files", "method": "POST", "params": [], "auth_required": True, "content_type": "multipart"},
        {"url": "/backend-api/gizmos/discovery", "method": "GET", "params": ["offset", "limit"], "auth_required": True},
    ],

    "auth": {
        "type": "bearer",
        "bearer_header": "authorization",
    },

    "scope": [
        "chatgpt.com",
        "*.chatgpt.com",
        "!auth0.openai.com",
        "!*.auth0.com",
    ],

    "in_scope_tests": ["idor", "auth", "injection", "ssrf", "xss"],
    "out_of_scope_tests": ["prompt_injection", "jailbreak", "model_manipulation"],

    "rate_limit": 1.5,

    "bounty": {
        "program": "OpenAI Bug Bounty",
        "url": "https://bugcrowd.com/openai",
        "max_bounty": "$20,000",
        "report_url": "https://bugcrowd.com/openai/report",
    },
}
