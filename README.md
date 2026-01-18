# <img width="48" height="48" alt="logo-oeditus-credo-48x48" src="https://github.com/user-attachments/assets/f212dd0e-cca3-4309-b63d-1a55b5d640b4" />  OeditusCredo

Custom Credo checks for detecting common Elixir/Phoenix anti-patterns and mistakes.

## Overview

OeditusCredo provides 20 comprehensive custom Credo checks that detect common mistakes in Elixir and Phoenix projects:

### Error Handling Anti-patterns
- **MissingErrorHandling** - Detects `{:ok, x} =` pattern without error handling
- **SilentErrorCase** - Detects case statements missing error branches
- **SwallowingException** - Detects try/rescue blocks without logging or re-raising

### Database & Performance Issues  
- **InefficientFilter** - Detects `Repo.all` followed by Enum filtering
- **NPlusOneQuery** - Detects potential N+1 queries (Enum.map with Repo calls)
- **MissingPreload** - Detects Ecto queries without proper preloading

### LiveView & Concurrency Issues
- **UnmanagedTask** - Detects unsupervised `Task.async` calls
- **SyncOverAsync** - Detects blocking operations in LiveView/GenServer callbacks
- **MissingHandleAsync** - Detects blocking in handle_event without async pattern
- **MissingThrottle** - Detects form inputs without phx-debounce/throttle
- **InlineJavascript** - Detects inline JS handlers instead of phx-* bindings

### Code Quality & Maintainability
- **HardcodedValue** - Detects hardcoded URLs, IPs, and secrets
- **DirectStructUpdate** - Detects direct struct updates instead of changesets
- **CallbackHell** - Detects deeply nested case statements (suggests `with`)
- **BlockingInPlug** - Detects blocking operations in Plug functions

### Telemetry & Observability
- **MissingTelemetryInObanWorker** - Detects Oban workers without telemetry instrumentation
- **MissingTelemetryInLiveViewMount** - Detects LiveView mount/3 without telemetry events
- **TelemetryInRecursiveFunction** - Detects telemetry inside recursive functions (anti-pattern)
- **MissingTelemetryInAuthPlug** - Detects auth/authz plugs without telemetry
- **MissingTelemetryForExternalHttp** - Detects HTTP client calls without telemetry wrapper

## Installation

Add `oeditus_credo` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:oeditus_credo, "~> 0.1.0", only: [:dev, :test], runtime: false}
  ]
end
```

## Usage

Add the checks to your `.credo.exs` configuration:

```elixir
%{
  configs: [
    %{
      name: "default",
      plugins: [],
      requires: [],
      checks: %{
        enabled: [
          # ... existing checks ...
          # Error Handling
          {OeditusCredo.Check.Warning.MissingErrorHandling, []},
          {OeditusCredo.Check.Warning.SilentErrorCase, []},
          {OeditusCredo.Check.Warning.SwallowingException, []},
          # Database & Performance
          {OeditusCredo.Check.Warning.InefficientFilter, []},
          {OeditusCredo.Check.Warning.NPlusOneQuery, []},
          {OeditusCredo.Check.Warning.MissingPreload, []},
          # LiveView & Concurrency
          {OeditusCredo.Check.Warning.UnmanagedTask, []},
          {OeditusCredo.Check.Warning.SyncOverAsync, []},
          {OeditusCredo.Check.Warning.MissingHandleAsync, []},
          {OeditusCredo.Check.Warning.MissingThrottle, []},
          {OeditusCredo.Check.Warning.InlineJavascript, []},
          # Code Quality
          {OeditusCredo.Check.Warning.HardcodedValue, []},
          {OeditusCredo.Check.Warning.DirectStructUpdate, []},
          {OeditusCredo.Check.Warning.CallbackHell, [max_nesting: 2]},
          {OeditusCredo.Check.Warning.BlockingInPlug, []},
          # Telemetry & Observability
          {OeditusCredo.Check.Warning.MissingTelemetryInObanWorker, []},
          {OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount, []},
          {OeditusCredo.Check.Warning.TelemetryInRecursiveFunction, []},
          {OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug, []},
          {OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp, []}
        ]
      }
    }
  ]
}
```

Then run:

```bash
mix credo
```

## Configuration Options

Some checks support configuration parameters:

- **CallbackHell**: `max_nesting` - Maximum allowed case nesting (default: 2)
- **HardcodedValue**: `exclude_test_files` - Whether to skip test files (default: true)

Example:

```elixir
{OeditusCredo.Check.Warning.CallbackHell, [max_nesting: 3]}
```

## Test Coverage

The library includes comprehensive tests for all 20 checks. Run tests with:

```bash
mix test
```

Current test coverage: 60+ tests, including comprehensive telemetry instrumentation checks.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is dual-licensed under:

- **GNU General Public License v2.0 (GPLv2)** - for open-source projects
- **Commercial License** - for proprietary applications

### Open Source (GPLv2)

You may use this software under the GPLv2 for free in open-source projects. Under this license, your application must also be licensed under GPLv2 or a compatible license, and you must make your source code available.

### Commercial License

If you wish to use this software in a proprietary application without releasing your source code under GPLv2, you must obtain a commercial license.

For commercial licensing inquiries, please contact:
- Email: licensing@oeditus.com
- Web: https://oeditus.com/licensing

See the LICENSE file for complete details.
