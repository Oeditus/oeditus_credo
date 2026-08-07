# OeditusCredo Quick Start

## One-Command Installation

### For Development (Recommended)
```bash
mix archive.install hex oeditus_credo
```

### For CI/CD
```bash
# In your CI config
mix archive.install hex oeditus_credo --force
mix oeditus_credo --strict
```

## Usage

```bash
# Run all OeditusCredo checks
mix oeditus_credo

# Strict mode (fail on any issues)
mix oeditus_credo --strict

# Analyze specific directory
mix oeditus_credo lib/my_app

# JSON output (for tooling integration)
mix oeditus_credo --format=json

# Show all issues (including low priority)
mix oeditus_credo --all
```

## What It Checks

OeditusCredo ships 58 specialized custom checks and automatically runs 56 of them across key categories:

1. **Error Handling**: Missing error handling, silent errors, swallowed exceptions
2. **Database & Performance**: N+1 queries, inefficient filters, missing preloads
3. **LiveView & Concurrency**: Unmanaged tasks, blocking operations, missing throttling, inline JS
4. **Code Quality**: Struct updates, callback hell, blocking plugs
5. **Code Organization & Idiomatic Refactoring**: `case` over `if`/`cond`, multi-head clauses, pipelines, inplace pattern matching, destructuring, `with` chains, tagged tuples, `for` comprehensions, list prepending, capture syntax, `Map.merge`, single-stage pipes, un-awaited tasks
6. **Readability**: Non-interpolating sigils
7. **Telemetry & Observability**: Telemetry in recursive functions, auth plugs, external HTTP
8. **Security & Vulnerabilities**: CWE Top 25 security checks (SQL injection, XSS, CSRF, IDOR, SSRF, command injection, path traversal, hardcoded credentials, TOCTOU)

Two checks are opt-in and stay disabled unless you enable them explicitly:
`ChangeRiskAntiPatterns` (needs persisted coverage data) and `UnsafeMapAccess`
(needs the optional `typle` dependency and Elixir 1.20+).

## CI/CD Examples

### GitHub Actions
```yaml
- run: mix archive.install hex oeditus_credo --force
- run: mix oeditus_credo --strict
```

### GitLab CI
```yaml
script:
  - mix archive.install hex oeditus_credo --force
  - mix oeditus_credo --strict
```

## Alternative: Escript (No Mix Required)

```bash
# Download
curl -LO https://github.com/Oeditus/oeditus_credo/releases/latest/download/oeditus_credo
chmod +x oeditus_credo

# Run
./oeditus_credo
```

## Need More Details?

- Full documentation: [README.md](README.md)
- Standalone guide: [STANDALONE.md](STANDALONE.md)
- Check descriptions: Run `mix oeditus_credo explain ISSUE_ID`
