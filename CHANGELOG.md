# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- All 20 idiomatic refactoring checks now accept the common `exclude_test_files` parameter (default `false`), matching the rest of the suite.

### Fixed
- `ChangeRiskAntiPatterns` no longer crashes when configured as `{Check, false}`.

### Documentation
- README, QUICKSTART.md, STANDALONE.md, STANDALONE_SUMMARY.md, the `OeditusCredo` moduledoc, the generated `.credo.exs` (`OeditusCredo.CLI.default_config/0`) and the ExDoc module groups now cover all 58 checks.
- Documented that `ChangeRiskAntiPatterns` and `UnsafeMapAccess` are the only two opt-in checks, so `mix oeditus_credo` enables 56 of 58 checks.

## [0.10.2] - 2026-08-07

### Added
- 5 idiomatic refactoring checks:
  - `PreferStringBoundariesOverRegex` - Detects `Regex.match?` for prefix/suffix checks instead of `String.starts_with?/2` and `String.ends_with?/2`
  - `PreferFunctionCapture` - Detects `fn x -> Module.func(x) end` instead of `&Module.func/1`
  - `PreferShortFieldAccessCapture` - Detects `fn x -> x.field end` instead of `& &1.field`
  - `PreferMapMerge` - Detects chained `Map.put` calls instead of a single `Map.merge/2`
  - `AvoidUnawaitedTaskAsync` - Detects fire-and-forget `Task.async` whose handle is discarded

## [0.10.0] - 2026-08-07

### Added
- 9 idiomatic refactoring checks:
  - `PreferDestructuring` - Detects `elem/2` and `Map.get/2` with literal keys instead of pattern match destructuring
  - `PreferMultiHeadForNil` - Detects `is_nil/1` guards instead of multi-head clauses matching `nil`
  - `PreferWithClause` - Detects nested `case` statements (pyramid of doom) instead of `with`
  - `PreferTaggedTuplesForErrors` - Detects `try...rescue` used as control flow instead of tagged tuples
  - `PreferForComprehensionOverFilterMap` - Detects `Enum.filter |> Enum.map` instead of a `for` comprehension
  - `PreferListPrepend` - Detects O(N) `list ++ [item]` appends instead of `[item | list]`
  - `PreferPatternMatchingForEmptiness` - Detects `Enum.count(list) > 0` instead of matching `[_ | _]` or `[]`
  - `PreferDotAccessForStructs` - Detects `struct[:field]` bracket access instead of `struct.field`
  - `AvoidSinglePipe` - Detects single-stage pipes `x |> f()` instead of a direct call `f(x)`

## [0.9.0] - 2026-08-07

### Added
- 6 idiomatic refactoring checks:
  - `PreferCasePatternMatching` - Detects `if`/`cond` where `case` pattern matching is preferred
  - `PreferMultiHeadFunction` - Detects parameter branching inside function body instead of multi-head clauses
  - `PreferPipelineOperator` - Detects sequential assignments instead of pipe operator `|>`
  - `PreferInplaceMapMatching` - Detects `is_map/1` guard instead of inplace `%{} = map` pattern matching
  - `PreferInplaceListMatching` - Detects O(N) `length/1` calls in guards instead of `[_ | _]` or `[]`
  - `PreferInplaceBinaryMatching` - Detects `is_binary` non-empty guards instead of `<<_::utf8, _::binary>>`

## [0.8.1] - 2026-06-29

### Removed
- `MissingTelemetryInObanWorker` - superseded by Oban's native telemetry instrumentation.

## [0.8.0] - 2026-06-28

### Added
- `ChangeRiskAntiPatterns` - Flags functions with a high CRAP (Change Risk Anti-Patterns) score by combining cyclomatic complexity with test coverage. Opt-in/disabled by default; requires running `mix test --cover --export-coverage default` before `mix credo`. Ports the scoring, complexity, and coverage logic from [ExCrap](https://github.com/germsvel/ex_crap) (MIT). See NOTICE.md for attribution.

### Changed
- Licensing normalized to MIT; resolved all compiler warnings and Dialyzer findings.

## [0.6.4] - 2026-05-28

### Added
- `UnnecessaryInterpolatingSigil` - Detects `~s`/`~c`/`~w` without interpolation (suggests `~S`/`~C`/`~W`); the sigil set is configurable and backslash escapes are skipped.

### Changed
- `SuggestFSM` detection accuracy improved (module attributes, sigil-defined state lists, struct-update transitions).

### Removed
- `MissingTelemetryInLiveViewMount` - the check never shipped; documentation references were dropped.

## [0.5.0] - 2026-05-07

### Added
- `SuggestFSM` - Detects imperative status/state management and suggests `Finitomata` or `:gen_statem`.
- `UnsafeMapAccess` - Type-aware check for bracket access on maps; requires the optional `typle` dependency and Elixir 1.20+.

### Changed
- Tightened CWE-200 (`SensitiveDataExposure`) detection and completed `@moduledoc` coverage.

## [0.4.0] - 2026-04-13

### Added
- `mix oeditus_assistant_rules` - Generates `.aiassistant/rules/oeditus.md` coding rules for AI assistants from the enabled checks.

## [0.3.3] - 2026-03-25

### Added
- Support for the general Credo parameters `false` (disable) and `exit_status: N` across all checks.
- `exclude_test_files` parameter, backed by the shared `OeditusCredo.Helpers.test_file?/1`.

## [0.3.0] - 2026-03-18

### Added
- 17 CWE Top 25 security checks: `SQLInjection`, `OSCommandInjection`, `CodeInjection`, `XSSVulnerability`, `MissingAuthentication`, `MissingAuthorization`, `IncorrectAuthorization`, `InsecureDirectObjectReference`, `SensitiveDataExposure`, `HardcodedCredentials`, `UnsafeDeserialization`, `ImproperInputValidation`, `PathTraversal`, `UnrestrictedFileUpload`, `MissingCSRFProtection`, `SSRFVulnerability`, `TOCTOU`.

### Removed
- `HardcodedValue` - superseded by the more precise `HardcodedCredentials`.

## [0.2.0] - 2026-01-19

### Added
- **Standalone Escript** - Build standalone executable with `mix escript.build`
- **Hex Archive Support** - Install globally with `mix archive.install`
- **Mix Task** - `mix oeditus_credo` command with all checks pre-enabled
- **CLI Module** - Automatic configuration generation
- STANDALONE.md guide with detailed installation and usage instructions
- CI/CD integration examples for GitHub Actions and GitLab CI

### Changed
- Updated README with standalone installation options
- Added escript configuration to mix.exs

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
- `DirectStructUpdate` - Detects direct struct updates instead of changesets
- `CallbackHell` - Detects deeply nested case statements (suggests `with`)
- `BlockingInPlug` - Detects blocking operations in Plug functions

#### Telemetry & Observability Checks (5)
- `MissingTelemetryInObanWorker` - Detects Oban workers without telemetry instrumentation (removed in 0.8.1)
- `MissingTelemetryInLiveViewMount` - Detects LiveView mount/3 without telemetry events (removed in 0.6.4)
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
- Released under the MIT License

[0.10.2]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.10.2
[0.10.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.10.0
[0.9.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.9.0
[0.8.1]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.8.1
[0.8.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.8.0
[0.6.4]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.6.4
[0.5.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.5.0
[0.4.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.4.0
[0.3.3]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.3.3
[0.3.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.3.0
[0.2.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.2.0
[0.1.0]: https://github.com/oeditus/oeditus_credo/releases/tag/v0.1.0
