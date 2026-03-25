defmodule OeditusCredo do
  @moduledoc """
  OeditusCredo provides custom Credo checks for detecting common Elixir/Phoenix anti-patterns.

  ## Usage

  Add to your `.credo.exs`:

      %{
        configs: [
          %{
            name: "default",
            checks: %{
              enabled: [
                {OeditusCredo.Check.Warning.MissingErrorHandling, []},
                {OeditusCredo.Check.Warning.SilentErrorCase, []},
                {OeditusCredo.Check.Warning.InefficientFilter, []},
                # ... other checks
              ]
            }
          }
        ]
      }

  > #### False Positives {: .warning}
  >
  > All these checks are somewhat opinionated and might produce false positives.
  > If a warning does not apply to your specific case, suppress it with
  > [`# credo:disable-for-next-line`](https://hexdocs.pm/credo/config_comments.html)
  > or any other Credo config comment directive.

  ## General Parameters

  All checks support the standard Credo general parameters:

  - **`false`** -- disable the check entirely:

        {OeditusCredo.Check.Warning.NPlusOneQuery, false}

  - **`exit_status`** -- override the exit status for issues from this check
    (default is `16` for the `:warning` category). Set to `0` to make a check
    advisory-only (still reports issues but won't affect the exit code):

        {OeditusCredo.Check.Warning.NPlusOneQuery, exit_status: 0}

  - **`priority`** -- override the base priority for the check.
  - **`files`** -- restrict which files the check runs on.

  ## Available Checks

  ### Error Handling
  - `OeditusCredo.Check.Warning.MissingErrorHandling` - Detects `{:ok, x} =` without error handling
  - `OeditusCredo.Check.Warning.SilentErrorCase` - Detects case statements missing error branches
  - `OeditusCredo.Check.Warning.SwallowingException` - Detects try/rescue without re-raising or logging

  ### Query & Data Access
  - `OeditusCredo.Check.Warning.NPlusOneQuery` - Detects N+1 query patterns
  - `OeditusCredo.Check.Warning.InefficientFilter` - Detects Repo.all followed by Enum filtering
  - `OeditusCredo.Check.Warning.MissingPreload` - Detects Ecto queries without proper preloading

  ### Concurrency & Performance
  - `OeditusCredo.Check.Warning.UnmanagedTask` - Detects unsupervised Task.async calls
  - `OeditusCredo.Check.Warning.SyncOverAsync` - Detects blocking operations in LiveView/GenServer
  - `OeditusCredo.Check.Warning.MissingHandleAsync` - Detects blocking in handle_event without async pattern

  ### Code Organization
  - `OeditusCredo.Check.Warning.DirectStructUpdate` - Detects struct updates instead of changesets
  - `OeditusCredo.Check.Warning.CallbackHell` - Detects chained case statements
  - `OeditusCredo.Check.Warning.BlockingInPlug` - Detects blocking operations in Plug functions

  ### LiveView & Templates
  - `OeditusCredo.Check.Warning.MissingThrottle` - Detects form inputs without phx-debounce/throttle
  - `OeditusCredo.Check.Warning.InlineJavascript` - Detects inline JS handlers instead of phx-* bindings

  ### Telemetry & Observability
  - `OeditusCredo.Check.Warning.MissingTelemetryInObanWorker` - Detects Oban workers without telemetry
  - `OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount` - Detects LiveView mount/3 without telemetry
  - `OeditusCredo.Check.Warning.TelemetryInRecursiveFunction` - Detects telemetry in recursive functions (anti-pattern)
  - `OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug` - Detects auth plugs without telemetry
  - `OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp` - Detects HTTP calls without telemetry

  ## Security Checks (CWE Top 25)

  ### Injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html))
  - `OeditusCredo.Check.Security.SQLInjection` - Detects string interpolation in Ecto queries
  - `OeditusCredo.Check.Security.OSCommandInjection` - Detects user input in System.cmd/os:cmd calls
  - `OeditusCredo.Check.Security.CodeInjection` - Detects dynamic code execution via Code.eval_string
  - `OeditusCredo.Check.Security.XSSVulnerability` - Detects raw/1 with user input in templates

  ### Authentication & Authorization ([CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html))
  - `OeditusCredo.Check.Security.MissingAuthentication` - Detects controllers/routers without auth plugs
  - `OeditusCredo.Check.Security.MissingAuthorization` - Detects actions without authorization checks
  - `OeditusCredo.Check.Security.IncorrectAuthorization` - Detects role checks using negation patterns
  - `OeditusCredo.Check.Security.InsecureDirectObjectReference` - Detects direct DB lookups from user params

  ### Data Protection ([CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html))
  - `OeditusCredo.Check.Security.SensitiveDataExposure` - Detects sensitive fields in JSON/inspect output
  - `OeditusCredo.Check.Security.HardcodedCredentials` - Detects hardcoded passwords, API keys, tokens
  - `OeditusCredo.Check.Security.UnsafeDeserialization` - Detects :erlang.binary_to_term without :safe

  ### Input & File Handling ([CWE-20](https://cwe.mitre.org/data/definitions/20.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-434](https://cwe.mitre.org/data/definitions/434.html))
  - `OeditusCredo.Check.Security.ImproperInputValidation` - Detects missing validation of external input
  - `OeditusCredo.Check.Security.PathTraversal` - Detects user input in file paths without sanitization
  - `OeditusCredo.Check.Security.UnrestrictedFileUpload` - Detects file uploads without type validation

  ### Web Security ([CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-918](https://cwe.mitre.org/data/definitions/918.html))
  - `OeditusCredo.Check.Security.MissingCSRFProtection` - Detects API pipelines without CSRF protection
  - `OeditusCredo.Check.Security.SSRFVulnerability` - Detects HTTP requests with user-controlled URLs

  ### Race Conditions ([CWE-367](https://cwe.mitre.org/data/definitions/367.html))
  - `OeditusCredo.Check.Security.TOCTOU` - Detects File.exists? followed by file operations
  """

  @version Mix.Project.config()[:version]

  @doc "Returns the version of OeditusCredo"
  def version, do: @version
end
