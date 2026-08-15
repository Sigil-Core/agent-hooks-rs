version: 2.2.0

## mcp
allowed_tools: example.fetch
response.web_fetch_tools: example.fetch
response.deterministic_ruleset: sof-response-rules-v1
response.block_classes: prompt_injection, secret

## custom
response.deny_string: "ignore previous instructions"
