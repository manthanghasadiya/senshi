"""
Salesforce Agentforce target profile.
"""

from __future__ import annotations

PROFILE = {
    "name": "Salesforce Agentforce",
    "base_url": "https://agentforce.salesforce.com",

    "endpoints": [
        {"url": "/api/v1/agents", "method": "GET", "params": [], "auth_required": True},
        {"url": "/api/v1/agents/{id}", "method": "GET", "params": [], "auth_required": True},
        {"url": "/api/v1/agents/{id}/invoke", "method": "POST", "params": [], "auth_required": True},
        {"url": "/api/v1/conversations", "method": "GET", "params": ["limit"], "auth_required": True},
        {"url": "/api/v1/conversations/{id}", "method": "GET", "params": [], "auth_required": True},
        {"url": "/api/v1/embeddedservice/config", "method": "GET", "params": [], "auth_required": False},
    ],

    "auth": {
        "type": "bearer",
        "bearer_header": "authorization",
    },

    "scope": [
        "*.salesforce.com",
        "*.force.com",
        "!login.salesforce.com",
    ],

    "in_scope_tests": ["idor", "auth", "injection", "ssrf", "ai_product"],
    "out_of_scope_tests": ["DoS"],

    "rate_limit": 2.0,

    "bounty": {
        "program": "Salesforce Bug Bounty",
        "url": "https://bugcrowd.com/salesforce",
        "max_bounty": "$15,000",
    },
}
