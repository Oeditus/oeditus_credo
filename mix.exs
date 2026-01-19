defmodule OeditusCredo.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/am-kantox/oeditus_credo"
  @homepage_url "https://oeditus.com"

  def project do
    [
      app: :oeditus_credo,
      version: @version,
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      aliases: aliases(),
      escript: escript(),
      test_coverage: [tool: ExCoveralls],
      dialyzer: [
        plt_add_apps: [:mix, :credo],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ],
      name: "OeditusCredo",
      source_url: @source_url,
      homepage_url: @homepage_url
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp escript do
    [
      main_module: OeditusCredo.Escript,
      name: "oeditus_credo",
      embed_elixir: true,
      app: nil
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.json": :test
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Core dependency
      {:credo, "~> 1.7"},

      # Development and documentation
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      quality: ["format", "credo --strict", "dialyzer"],
      "quality.ci": [
        "format --check-formatted",
        "credo --strict",
        "dialyzer"
      ]
    ]
  end

  defp description do
    """
    Custom Credo checks for detecting common Elixir/Phoenix anti-patterns including
    N+1 queries, missing error handling, blocking operations, telemetry gaps, and more.
    Provides 20 comprehensive static analysis checks to improve code quality.
    """
  end

  defp package do
    [
      name: "oeditus_credo",
      files: ~w(
        lib
        .formatter.exs
        mix.exs
        README.md
        STANDALONE.md
        LICENSE
        CHANGELOG.md
      ),
      licenses: ["GPL-3.0", "CC-BY-SA-4.0"],
      maintainers: ["Oeditus Team"],
      links: %{
        "GitHub" => @source_url,
        "Homepage" => @homepage_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "Documentation" => "https://hexdocs.pm/oeditus_credo"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      logo: "stuff/img/logo-oeditus-credo-48x48.png",
      assets: %{"stuff/img" => "assets"},
      extras: extras(),
      extra_section: "GUIDES",
      source_url: @source_url,
      source_ref: "v#{@version}",
      homepage_url: @homepage_url,
      formatters: ["html", "epub"],
      groups_for_modules: groups_for_modules(),
      nest_modules_by_prefix: [OeditusCredo.Check.Warning],
      before_closing_body_tag: &before_closing_body_tag/1,
      authors: ["Oeditus Team"],
      canonical: "https://hexdocs.pm/oeditus_credo",
      skip_undefined_reference_warnings_on: ["CHANGELOG.md"]
    ]
  end

  defp extras do
    [
      "README.md",
      "QUICKSTART.md": [title: "Quick Start"],
      "STANDALONE.md": [title: "Standalone Usage"],
      "CHANGELOG.md": [title: "Changelog"],
      "stuff/docs/Automated Detection of Common Elixir Phoenix Mistakes.md": [
        filename: "automated_detection",
        title: "Automated Detection"
      ]
    ]
  end

  defp groups_for_modules do
    [
      "Error Handling": [
        OeditusCredo.Check.Warning.MissingErrorHandling,
        OeditusCredo.Check.Warning.SilentErrorCase,
        OeditusCredo.Check.Warning.SwallowingException
      ],
      "Database & Performance": [
        OeditusCredo.Check.Warning.InefficientFilter,
        OeditusCredo.Check.Warning.NPlusOneQuery,
        OeditusCredo.Check.Warning.MissingPreload
      ],
      "LiveView & Concurrency": [
        OeditusCredo.Check.Warning.UnmanagedTask,
        OeditusCredo.Check.Warning.SyncOverAsync,
        OeditusCredo.Check.Warning.MissingHandleAsync,
        OeditusCredo.Check.Warning.MissingThrottle,
        OeditusCredo.Check.Warning.InlineJavascript
      ],
      "Code Quality": [
        OeditusCredo.Check.Warning.HardcodedValue,
        OeditusCredo.Check.Warning.DirectStructUpdate,
        OeditusCredo.Check.Warning.CallbackHell,
        OeditusCredo.Check.Warning.BlockingInPlug
      ],
      "Telemetry & Observability": [
        OeditusCredo.Check.Warning.MissingTelemetryInObanWorker,
        OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount,
        OeditusCredo.Check.Warning.TelemetryInRecursiveFunction,
        OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug,
        OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp
      ]
    ]
  end

  defp before_closing_body_tag(:html) do
    """
    <script>
      // Add search keyboard shortcut
      document.addEventListener("keydown", function(e) {
        if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          document.querySelector(".search-input")?.focus();
        }
      });
    </script>
    """
  end

  defp before_closing_body_tag(_), do: ""
end
