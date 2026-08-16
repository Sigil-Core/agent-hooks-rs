version: 2.3.0

## custom
response.deny_string: "ignore previous instructions"

## mcp
allowed_tools: fetch.server.fetch, api.server.request
response.web_fetch_tools: fetch.server.fetch
response.http_tools: api.server.request
response.deterministic_ruleset: sof-response-rules-v1
response.block_classes: prompt_injection
response.redact_classes: pii, secret
response.scanner.required: true
response.scanner.profile: operator-presidio-v1
response.scanner.classes: pii, prompt_injection
response.scanner.min_confidence: 0.85
response.observe_classes: prompt_injection
response.observe_until: 2026-09-05T00:00:00Z
