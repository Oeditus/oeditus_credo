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

OeditusCredo automatically runs 44+ specialized custom checks across key categories:

1. **Error Handling**: Missing error handling, silent errors, swallowed exceptions
2. **Database & Performance**: N+1 queries, inefficient filters, missing preloads
3. **LiveView & Concurrency**: Unmanaged tasks, blocking operations, missing throttling, inline JS
4. **Code Quality & Idiomatic Refactoring**: Struct updates, callback hell, blocking plugs, pattern matching, pipeline operator, multi-head functions, inplace matching
5. **Telemetry & Observability**: Telemetry in recursive functions, auth plugs, external HTTP
6. **Security & Vulnerabilities**: CWE Top 25 security checks (SQL injection, XSS, CSRF, IDOR, SSRF, command injection, path traversal, hardcoded credentials, TOCTOU)

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
