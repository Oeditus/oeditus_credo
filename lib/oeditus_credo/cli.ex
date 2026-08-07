defmodule OeditusCredo.CLI do
  @moduledoc """
  CLI utilities for OeditusCredo, including configuration generation.
  """

  @doc """
  Returns the default Credo configuration with all OeditusCredo checks enabled.
  """
  def default_config do
    """
    # OeditusCredo Default Configuration
    # Generated automatically - modifications will be overwritten
    %{
      configs: [
        %{
          name: "default",
          color: true,
          files: %{
            included: [
              "lib/",
              "src/",
              "test/",
              "web/",
              "apps/*/lib/",
              "apps/*/src/",
              "apps/*/test/",
              "apps/*/web/"
            ],
            excluded: [
              ~r"/_build/",
              ~r"/deps/",
              ~r"/node_modules/"
            ]
          },
          requires: [],
          strict: false,
          parse_timeout: 5000,
          checks: %{
            enabled: [
              ## Error Handling Anti-patterns
              {OeditusCredo.Check.Warning.MissingErrorHandling, []},
              {OeditusCredo.Check.Warning.SilentErrorCase, []},
              {OeditusCredo.Check.Warning.SwallowingException, []},

              ## Database & Performance Issues
              {OeditusCredo.Check.Warning.InefficientFilter, []},
              {OeditusCredo.Check.Warning.NPlusOneQuery, []},
              {OeditusCredo.Check.Warning.MissingPreload, []},

              ## LiveView & Concurrency Issues
              {OeditusCredo.Check.Warning.UnmanagedTask, []},
              {OeditusCredo.Check.Warning.SyncOverAsync, []},
              {OeditusCredo.Check.Warning.MissingHandleAsync, []},
              {OeditusCredo.Check.Warning.MissingThrottle, []},
              {OeditusCredo.Check.Warning.InlineJavascript, []},

              ## Readability
              {OeditusCredo.Check.Readability.UnnecessaryInterpolatingSigil, []},

              ## Code Quality & Maintainability
              {OeditusCredo.Check.Warning.DirectStructUpdate, []},
              {OeditusCredo.Check.Warning.CallbackHell, [max_nesting: 2]},
              {OeditusCredo.Check.Warning.BlockingInPlug, []},

              ## Code Organization & Idiomatic Refactoring
              {OeditusCredo.Check.Refactoring.SuggestFSM, []},
              {OeditusCredo.Check.Refactoring.PreferCasePatternMatching, []},
              {OeditusCredo.Check.Refactoring.PreferMultiHeadFunction, []},
              {OeditusCredo.Check.Refactoring.PreferMultiHeadForNil, []},
              {OeditusCredo.Check.Refactoring.PreferPipelineOperator, []},
              {OeditusCredo.Check.Refactoring.PreferInplaceMapMatching, []},
              {OeditusCredo.Check.Refactoring.PreferInplaceListMatching, []},
              {OeditusCredo.Check.Refactoring.PreferInplaceBinaryMatching, []},
              {OeditusCredo.Check.Refactoring.PreferDestructuring, []},
              {OeditusCredo.Check.Refactoring.PreferDotAccessForStructs, []},
              {OeditusCredo.Check.Refactoring.PreferWithClause, []},
              {OeditusCredo.Check.Refactoring.PreferTaggedTuplesForErrors, []},
              {OeditusCredo.Check.Refactoring.PreferForComprehensionOverFilterMap, []},
              {OeditusCredo.Check.Refactoring.PreferListPrepend, []},
              {OeditusCredo.Check.Refactoring.PreferPatternMatchingForEmptiness, []},
              {OeditusCredo.Check.Refactoring.PreferStringBoundariesOverRegex, []},
              {OeditusCredo.Check.Refactoring.PreferFunctionCapture, []},
              {OeditusCredo.Check.Refactoring.PreferShortFieldAccessCapture, []},
              {OeditusCredo.Check.Refactoring.PreferMapMerge, []},
              {OeditusCredo.Check.Refactoring.AvoidSinglePipe, []},
              {OeditusCredo.Check.Refactoring.AvoidUnawaitedTaskAsync, []},

              ## Telemetry & Observability
              {OeditusCredo.Check.Warning.TelemetryInRecursiveFunction, []},
              {OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug, []},
              {OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp, []},

              ## Security - Injection
              {OeditusCredo.Check.Security.SQLInjection, []},
              {OeditusCredo.Check.Security.OSCommandInjection, []},
              {OeditusCredo.Check.Security.CodeInjection, []},
              {OeditusCredo.Check.Security.XSSVulnerability, []},

              ## Security - Authentication & Authorization
              {OeditusCredo.Check.Security.MissingAuthentication, []},
              {OeditusCredo.Check.Security.MissingAuthorization, []},
              {OeditusCredo.Check.Security.IncorrectAuthorization, []},
              {OeditusCredo.Check.Security.InsecureDirectObjectReference, []},

              ## Security - Data Protection
              {OeditusCredo.Check.Security.SensitiveDataExposure, []},
              {OeditusCredo.Check.Security.HardcodedCredentials, []},
              {OeditusCredo.Check.Security.UnsafeDeserialization, []},

              ## Security - Input & File Handling
              {OeditusCredo.Check.Security.ImproperInputValidation, []},
              {OeditusCredo.Check.Security.PathTraversal, []},
              {OeditusCredo.Check.Security.UnrestrictedFileUpload, []},

              ## Security - Web
              {OeditusCredo.Check.Security.MissingCSRFProtection, []},
              {OeditusCredo.Check.Security.SSRFVulnerability, []},

              ## Security - Race Conditions
              {OeditusCredo.Check.Security.TOCTOU, []}
            ],
            disabled: [
              ## Change Risk Anti-Patterns (CRAP) score.
              ## Opt-in: requires persisted coverage data. Run
              ## `mix test --cover --export-coverage default` before this check,
              ## then move it to `enabled` above.
              {OeditusCredo.Check.Refactoring.ChangeRiskAntiPatterns, []},

              ## Type-aware map access check.
              ## Opt-in: requires the optional `typle` dependency and
              ## Elixir 1.20 or later.
              {OeditusCredo.Check.Warning.UnsafeMapAccess, []}
            ]
          }
        }
      ]
    }
    """
  end

  @doc """
  Writes the default configuration to a file.
  """
  def write_config(path \\ ".credo.exs") do
    File.write!(path, default_config())
    path
  end
end
