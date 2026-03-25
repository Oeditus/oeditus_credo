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

              ## Code Quality & Maintainability
              {OeditusCredo.Check.Warning.DirectStructUpdate, []},
              {OeditusCredo.Check.Warning.CallbackHell, [max_nesting: 2]},
              {OeditusCredo.Check.Warning.BlockingInPlug, []},

              ## Telemetry & Observability
              {OeditusCredo.Check.Warning.MissingTelemetryInObanWorker, []},
              {OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount, []},
              {OeditusCredo.Check.Warning.TelemetryInRecursiveFunction, []},
              {OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug, []},
              {OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp, []}
            ],
            disabled: []
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
