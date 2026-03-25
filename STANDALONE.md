# OeditusCredo Standalone Usage

This guide covers how to use OeditusCredo as a standalone tool without adding it as a project dependency.

## Installation Methods

### Method 1: Hex Archive (Recommended)

Install OeditusCredo as a Hex archive for system-wide availability:

```bash
# Install from Hex
mix archive.install hex oeditus_credo

# Or install from local build
mix archive.build
mix archive.install
```

Once installed, you can run it in any Elixir project:

```bash
mix oeditus_credo
mix oeditus_credo --strict
mix oeditus_credo lib/my_app
```

To uninstall:

```bash
mix archive.uninstall oeditus_credo
```

### Method 2: Escript Executable

Build a standalone executable that can be used without Mix:

```bash
# Build the escript
mix escript.build

# This creates an executable: ./oeditus_credo
# Run it directly
./oeditus_credo

# Or install it globally
sudo cp oeditus_credo /usr/local/bin/
oeditus_credo
```

The escript can be distributed as a single file and works on any system with Erlang installed.

## Usage

Both installation methods support the same command-line options as Credo:

```bash
# Basic usage - analyze current project
mix oeditus_credo
# or
oeditus_credo

# Strict mode - fail on any issues
mix oeditus_credo --strict

# Analyze specific directory
mix oeditus_credo lib/my_app

# Show all issues including low priority
mix oeditus_credo --all

# Different output formats
mix oeditus_credo --format=json
mix oeditus_credo --format=flycheck

# Get help
mix oeditus_credo --help
```

## What's Included

The standalone installation automatically enables all 20 OeditusCredo checks:

**Error Handling**
- MissingErrorHandling
- SilentErrorCase
- SwallowingException

**Database & Performance**
- InefficientFilter
- NPlusOneQuery
- MissingPreload

**LiveView & Concurrency**
- UnmanagedTask
- SyncOverAsync
- MissingHandleAsync
- MissingThrottle
- InlineJavascript

**Code Quality**
- DirectStructUpdate
- CallbackHell
- BlockingInPlug

**Telemetry & Observability**
- MissingTelemetryInObanWorker
- MissingTelemetryInLiveViewMount
- TelemetryInRecursiveFunction
- MissingTelemetryInAuthPlug
- MissingTelemetryForExternalHttp

## CI/CD Integration

### GitHub Actions

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  credo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: erlef/setup-beam@v1
        with:
          elixir-version: '1.15'
          otp-version: '26'
      - name: Install OeditusCredo
        run: mix archive.install hex oeditus_credo --force
      - name: Run OeditusCredo
        run: mix oeditus_credo --strict
```

### GitLab CI

```yaml
oeditus_credo:
  image: elixir:1.15
  script:
    - mix local.hex --force
    - mix archive.install hex oeditus_credo --force
    - mix oeditus_credo --strict
```

## Comparison: Archive vs Escript

| Feature | Hex Archive | Escript |
|---------|-------------|---------|
| Installation | `mix archive.install` | Copy binary |
| Usage | `mix oeditus_credo` | `./oeditus_credo` or `oeditus_credo` |
| Updates | `mix archive.install` (overwrites) | Replace binary |
| Requires Mix | Yes | No |
| Distribution | Via Hex or file | Single binary file |
| Best for | Development environments | CI/CD, containers |

## Development Workflow

For library maintainers working on OeditusCredo:

```bash
# Build and test locally
mix deps.get
mix compile
mix test

# Build escript
mix escript.build

# Test the escript
./oeditus_credo

# Build archive
mix archive.build

# Install locally for testing
mix archive.install

# Test in another project
cd /path/to/other/project
mix oeditus_credo
```

## Troubleshooting

**Issue: "The task 'oeditus_credo' could not be found"**
- Solution: Reinstall the archive: `mix archive.install hex oeditus_credo --force`

**Issue: Escript fails with "Cannot find Elixir"**
- Solution: Ensure Erlang and Elixir are in your PATH

**Issue: Checks not running**
- Solution: Make sure you're in an Elixir project directory with `mix.exs`

**Issue: Permission denied on escript**
- Solution: `chmod +x oeditus_credo`
