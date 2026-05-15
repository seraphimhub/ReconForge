# Security Model

ReconForge is designed for authorized security work and asset inventory.

## Guardrails

- Active modules require `--authorized` by default.
- Targets can be constrained with `--scope` or `--scope-file`.
- Private, loopback, reserved, and special IP ranges are blocked by default.
- Domain targets selected for active modules are resolved before execution; if they resolve to private or special IP space, the run is blocked unless `--allow-private` is supplied.
- Network requests use a configurable rate limit and concurrency limit.
- Reverse IP and reverse WHOIS integrations are disabled by default and require explicit provider configuration.

## Non-goals

ReconForge does not include exploitation, brute forcing, authentication attacks, stealth, evasion, payload delivery, or destructive testing.

## Recommended workflow

1. Define written scope.
2. Put domains and CIDRs in `examples/scope.txt` or another scope file.
3. Start with passive/default modules.
4. Enable active modules only after confirming authorization.
5. Store JSON reports for automation and Markdown reports for review.

