<img src="https://raw.githubusercontent.com/Oeditus/oeditus_credo/v0.3.2/stuff/img/logo-oeditus-credo-128x128.png" alt="OeditusCredo" width="128" align="right">

# OeditusCredo

Custom Credo checks for detecting common Elixir/Phoenix anti-patterns, mistakes, and CWE Top 25 security vulnerabilities.

## Overview

OeditusCredo provides 36 comprehensive custom Credo checks that detect common mistakes and security vulnerabilities in Elixir and Phoenix projects:

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
- **DirectStructUpdate** - Detects direct struct updates instead of changesets
- **CallbackHell** - Detects deeply nested case statements (suggests `with`)
- **BlockingInPlug** - Detects blocking operations in Plug functions

### Telemetry & Observability
- **MissingTelemetryInObanWorker** - Detects Oban workers without telemetry instrumentation
- **MissingTelemetryInLiveViewMount** - Detects LiveView mount/3 without telemetry events
- **TelemetryInRecursiveFunction** - Detects telemetry inside recursive functions (anti-pattern)
- **MissingTelemetryInAuthPlug** - Detects auth/authz plugs without telemetry
- **MissingTelemetryForExternalHttp** - Detects HTTP client calls without telemetry wrapper

### Security - Injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html))
- **SQLInjection** - Detects string interpolation/concatenation in Ecto queries
- **OSCommandInjection** - Detects user input passed to System.cmd/os:cmd
- **CodeInjection** - Detects dynamic code execution via Code.eval_string
- **XSSVulnerability** - Detects raw/1 with user input in templates

### Security - Authentication & Authorization ([CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html))
- **MissingAuthentication** - Detects controllers/routers without authentication plugs
- **MissingAuthorization** - Detects Phoenix actions without authorization checks
- **IncorrectAuthorization** - Detects role checks using negation/!= patterns
- **InsecureDirectObjectReference** - Detects direct DB lookups from user params without ownership checks

### Security - Data Protection ([CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html))
- **SensitiveDataExposure** - Detects sensitive fields in JSON responses and inspect output
- **HardcodedCredentials** - Detects hardcoded passwords, API keys, tokens, and secrets
- **UnsafeDeserialization** - Detects :erlang.binary_to_term without the :safe option

### Security - Input & File Handling ([CWE-20](https://cwe.mitre.org/data/definitions/20.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-434](https://cwe.mitre.org/data/definitions/434.html))
- **ImproperInputValidation** - Detects missing validation of external input
- **PathTraversal** - Detects user input in file paths without sanitization
- **UnrestrictedFileUpload** - Detects file uploads without content-type validation

### Security - Web ([CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-918](https://cwe.mitre.org/data/definitions/918.html))
- **MissingCSRFProtection** - Detects API pipelines without CSRF protection
- **SSRFVulnerability** - Detects HTTP requests with user-controlled URLs

### Security - Race Conditions ([CWE-367](https://cwe.mitre.org/data/definitions/367.html))
- **TOCTOU** - Detects time-of-check/time-of-use patterns (File.exists? then File.read)

## Important Note

All these checks are somewhat opinionated and might produce false positives. If a warning does not apply to your specific case, you can suppress it with [`# credo:disable-for-next-line`](https://hexdocs.pm/credo/config_comments.html) or any other Credo config comment directive.

## Installation

### As a Project Dependency

Add `oeditus_credo` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:oeditus_credo, "~> 0.1.0", only: [:dev, :test], runtime: false}
  ]
end
```

### Standalone Installation (No Dependency Required)

You can also use OeditusCredo without adding it to your project dependencies:

```bash
# Install as a Hex archive (recommended for development)
mix archive.install hex oeditus_credo

# Or download and use the escript executable (best for CI/CD)
curl -L https://github.com/Oeditus/oeditus_credo/releases/latest/download/oeditus_credo -o oeditus_credo
chmod +x oeditus_credo
```

See [STANDALONE.md](STANDALONE.md) for detailed standalone usage instructions.

## Usage

### With Standalone Installation

If you installed OeditusCredo as an archive or escript:

```bash
mix oeditus_credo              # Run with all checks enabled
mix oeditus_credo --strict     # Fail on any issues
mix oeditus_credo lib/my_app   # Analyze specific directory
```

### With Project Dependency

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
          {OeditusCredo.Check.Warning.DirectStructUpdate, []},
          {OeditusCredo.Check.Warning.CallbackHell, [max_nesting: 2]},
          {OeditusCredo.Check.Warning.BlockingInPlug, []},
          # Telemetry & Observability
          {OeditusCredo.Check.Warning.MissingTelemetryInObanWorker, []},
          {OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount, []},
          {OeditusCredo.Check.Warning.TelemetryInRecursiveFunction, []},
          {OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug, []},
          {OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp, []},
          # Security - Injection
          {OeditusCredo.Check.Security.SQLInjection, []},
          {OeditusCredo.Check.Security.OSCommandInjection, []},
          {OeditusCredo.Check.Security.CodeInjection, []},
          {OeditusCredo.Check.Security.XSSVulnerability, []},
          # Security - Auth
          {OeditusCredo.Check.Security.MissingAuthentication, []},
          {OeditusCredo.Check.Security.MissingAuthorization, []},
          {OeditusCredo.Check.Security.IncorrectAuthorization, []},
          {OeditusCredo.Check.Security.InsecureDirectObjectReference, []},
          # Security - Data Protection
          {OeditusCredo.Check.Security.SensitiveDataExposure, []},
          {OeditusCredo.Check.Security.HardcodedCredentials, []},
          {OeditusCredo.Check.Security.UnsafeDeserialization, []},
          # Security - Input & File Handling
          {OeditusCredo.Check.Security.ImproperInputValidation, []},
          {OeditusCredo.Check.Security.PathTraversal, []},
          {OeditusCredo.Check.Security.UnrestrictedFileUpload, []},
          # Security - Web
          {OeditusCredo.Check.Security.MissingCSRFProtection, []},
          {OeditusCredo.Check.Security.SSRFVulnerability, []},
          # Security - Race Conditions
          {OeditusCredo.Check.Security.TOCTOU, []}
        ]
      }
    ]
  ]
}
```

Then run:

```bash
mix credo
```

## Configuration Options

All checks support configuration parameters. Pass them in `.credo.exs`:

### Common Parameters

Every check accepts the following parameter:

- `exclude_test_files` (`boolean()`, default: `false`) -- When set to `true`, files ending in `_test.exs` or located under a `/test/` directory are skipped.

### Code Quality

- **CallbackHell**: `max_nesting` -- Maximum allowed case nesting depth (default: `2`)
- **DirectStructUpdate**: `extra_struct_patterns` -- Additional regex strings for struct-like variable names (default: `[]`)
- **BlockingInPlug**: `extra_blocking_modules` -- Additional module atoms to treat as blocking (default: `[]`)

### LiveView & Concurrency

- **SyncOverAsync**: `extra_blocking_modules` -- Additional blocking module atoms (default: `[]`); `callback_functions` -- Callback names to check (default: `[:handle_event, :handle_call, :handle_info, :handle_cast, :handle_continue]`)
- **MissingHandleAsync**: `extra_blocking_modules` -- Additional blocking module atoms (default: `[]`)

### Telemetry & Observability

- **MissingTelemetryForExternalHttp**: `extra_http_modules` -- Additional `{module_parts, [functions]}` tuples (default: `[]`)
- **MissingTelemetryInAuthPlug**: `extra_auth_plug_names` -- Additional auth plug name substrings (default: `[]`)

### Security -- Injection

- **CodeInjection**: `extra_dangerous_functions` -- Additional `Code.*` function atoms to flag (default: `[]`)

### Security -- Auth

- **MissingAuthentication**: `sensitive_actions` -- Controller actions requiring auth (default: `[:index, :show, :create, :new, :update, :edit, :delete, :destroy]`)
- **MissingAuthorization**: `extra_auth_indicators` -- Additional authorization indicator substrings (default: `[]`)
- **IncorrectAuthorization**: `extra_auth_indicators` -- Additional authorization indicator substrings (default: `[]`)
- **InsecureDirectObjectReference**: `extra_ownership_indicators` -- Additional ownership/auth indicator substrings (default: `[]`)

### Security -- Data Protection

- **SensitiveDataExposure**: `extra_sensitive_terms` -- Additional sensitive field substrings (default: `[]`)
- **HardcodedCredentials**: `extra_credential_terms` -- Additional credential name substrings (default: `[]`)

### Security -- Web

- **SSRFVulnerability**: `extra_http_modules` -- Additional HTTP module atom lists, e.g. `[[:MyHTTP]]` (default: `[]`)

### Example

```elixir
{OeditusCredo.Check.Warning.CallbackHell, [max_nesting: 3]},
{OeditusCredo.Check.Warning.SyncOverAsync, [extra_blocking_modules: [:ExternalAPI]]},
{OeditusCredo.Check.Security.CodeInjection, [extra_dangerous_functions: [:compile_string]]},
{OeditusCredo.Check.Security.HardcodedCredentials, [exclude_test_files: true, extra_credential_terms: ["conn_string"]]},
{OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp, [
  extra_http_modules: [{[:MyApp, :HTTP], [:get, :post]}]
]}
```

## Test Coverage

The library includes comprehensive tests for all 36 checks. Run tests with:

```bash
mix test
```

Current test coverage: 92 tests covering all checks, including security vulnerability detection and telemetry instrumentation.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License. See [LICENSE](LICENSE) for details.
