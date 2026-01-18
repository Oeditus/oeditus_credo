# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-18

### Added

#### Error Handling Checks (3)
- `MissingErrorHandling` - Detects `{:ok, x} =` pattern without error handling
- `SilentErrorCase` - Detects case statements missing error branches
- `SwallowingException` - Detects try/rescue blocks without logging or re-raising

#### Database & Performance Checks (3)
- `InefficientFilter` - Detects `Repo.all` followed by Enum filtering
- `NPlusOneQuery` - Detects potential N+1 queries (Enum.map with Repo calls)
- `MissingPreload` - Detects Ecto queries without proper preloading

#### LiveView & Concurrency Checks (5)
- `UnmanagedTask` - Detects unsupervised `Task.async` calls
- `SyncOverAsync` - Detects blocking operations in LiveView/GenServer callbacks
- `MissingHandleAsync` - Detects blocking in handle_event without async pattern
- `MissingThrottle` - Detects form inputs without phx-debounce/throttle
- `InlineJavascript` - Detects inline JS handlers instead of phx-* bindings

#### Code Quality Checks (4)
- `HardcodedValue` - Detects hardcoded URLs, IPs, and secrets
- `DirectStructUpdate` - Detects direct struct updates instead of changesets
- `CallbackHell` - Detects deeply nested case statements (suggests `with`)
- `BlockingInPlug` - Detects blocking operations in Plug functions

#### Telemetry & Observability Checks (5)
- `MissingTelemetryInObanWorker` - Detects Oban workers without telemetry instrumentation
- `MissingTelemetryInLiveViewMount` - Detects LiveView mount/3 without telemetry events
- `TelemetryInRecursiveFunction` - Detects telemetry inside recursive functions (anti-pattern)
- `MissingTelemetryInAuthPlug` - Detects auth/authz plugs without telemetry
- `MissingTelemetryForExternalHttp` - Detects HTTP client calls without telemetry wrapper

### Documentation
- Comprehensive README with installation and usage instructions
- Detailed documentation for all 20 checks
- Configuration examples and best practices

### Testing
- 60+ comprehensive tests covering all checks
- Positive and negative test cases for each check
- Test coverage reporting with ExCoveralls

### Licensing
- Dual-licensed under GPLv3 and CC-BY-SA-4.0
- Open-source use under GPLv3
- Commercial license available for proprietary applications

[0.1.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.1.0
