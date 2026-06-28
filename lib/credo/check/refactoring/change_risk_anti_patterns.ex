defmodule OeditusCredo.Check.Refactoring.ChangeRiskAntiPatterns do
  @moduledoc """
  Flags functions with a high Change Risk Anti-Patterns (CRAP) score, i.e. code
  that is both complex and poorly covered by tests.

  The CRAP score combines a function's cyclomatic complexity with its test
  coverage:

      CRAP = complexity^2 * (1 - coverage/100)^3 + complexity

  A fully covered function scores its complexity; an uncovered, complex function
  scores much higher. The default maximum of `30` follows the historical CRAP
  convention.

  > #### Coverage data is required {: .warning}
  >
  > This check is a static analyzer and cannot run your tests, so it reads
  > **persisted coverage data**. You MUST generate that data first:
  >
  > ```
  > mix test --cover --export-coverage default
  > mix credo
  > ```
  >
  > Plain `mix test --cover` prints a coverage report but does NOT leave an
  > importable coverage file. Without `cover/default.coverdata` (or the path set
  > via the `:coverdata` param) the check is a no-op by default, so it never
  > breaks a `mix credo` run that was launched without coverage. Set
  > `require_coverage: true` to turn missing coverage into a reported issue
  > instead (useful in CI).

  Functions with no matching coverage entry are scored pessimistically as `0%`
  covered, matching the behaviour of the original `mix crap` task.

  This check ports the scoring, complexity, and coverage logic of
  [ExCrap](https://github.com/germsvel/ex_crap) (MIT) into a Credo check.
  """

  use Credo.Check,
    base_priority: :low,
    category: :refactoring,
    explanations: [
      check: """
      Functions that are both complex and under-tested are the riskiest to
      change. The CRAP (Change Risk Anti-Patterns) score surfaces them by
      combining cyclomatic complexity with test coverage:

          CRAP = complexity^2 * (1 - coverage/100)^3 + complexity

      IMPORTANT: this check needs persisted coverage data and must be run AFTER
      generating it:

          mix test --cover --export-coverage default
          mix credo

      Plain `mix test --cover` does not leave an importable coverage file. When
      no coverage data is available the check does nothing by default (set
      `require_coverage: true` to flag that situation instead).

      A high score is a prompt to investigate: add meaningful tests, simplify the
      function, or write characterization tests before refactoring risky legacy
      code. Cyclomatic complexity is only a proxy for path/test burden; it does
      not measure naming, cohesion, or whether tests assert anything meaningful.
      """,
      params: [
        max_score: "The maximum CRAP score a function may have before it is reported.",
        coverdata:
          "Path to the persisted coverage file, relative to the project root " <>
            "(default `cover/default.coverdata`).",
        exclude_test_files: "Set to false to also score test files (default: true).",
        require_coverage:
          "When true, report an issue if coverage data is missing instead of " <>
            "silently skipping (default: false).",
        coverage:
          "Advanced/testing: an explicit `%{{module, function, arity} => percent}` " <>
            "map that bypasses coverdata loading."
      ]
    ]

  alias OeditusCredo.Crap.Complexity
  alias OeditusCredo.Crap.Coverage
  alias OeditusCredo.Crap.Score

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @cache_key {__MODULE__, :coverage_cache}

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    if Params.get(params, :exclude_test_files, __MODULE__) and test_file?(source_file.filename) do
      []
    else
      issue_meta = IssueMeta.for(source_file, params)
      max_score = Params.get(params, :max_score, __MODULE__)

      case resolve_coverage(params) do
        {:ok, coverage_map} ->
          analyze(source_file, coverage_map, max_score, issue_meta)

        {:error, _reason} ->
          if Params.get(params, :require_coverage, __MODULE__) do
            missing_coverage_issues(source_file, issue_meta)
          else
            []
          end
      end
    end
  end

  @doc false
  @impl true
  def param_defaults do
    [
      max_score: 30,
      coverdata: "cover/default.coverdata",
      exclude_test_files: true,
      require_coverage: false,
      coverage: nil
    ]
  end

  # --- Coverage resolution (explicit map > cached coverdata load) ---

  defp resolve_coverage(params) do
    case Params.get(params, :coverage, __MODULE__) do
      coverage when is_map(coverage) -> {:ok, coverage}
      _other -> load_coverage(Params.get(params, :coverdata, __MODULE__))
    end
  end

  defp load_coverage(path) do
    abs_path = Path.expand(path)

    case File.stat(abs_path) do
      {:ok, %File.Stat{type: :regular, mtime: mtime, size: size}} ->
        cached_or_load(abs_path, {abs_path, mtime, size})

      _other ->
        {:error, {:coverdata_missing, abs_path}}
    end
  end

  # Importing/analysing coverdata is a project-wide operation, so it is computed
  # once and memoized for the lifetime of the `mix credo` run. The cache key
  # includes mtime+size so regenerated coverage is picked up automatically.
  defp cached_or_load(abs_path, cache_key) do
    case :persistent_term.get(@cache_key, nil) do
      {^cache_key, coverage} -> {:ok, coverage}
      _other -> load_and_cache(abs_path, cache_key)
    end
  end

  defp load_and_cache(abs_path, cache_key) do
    case safe_from_coverdata(abs_path) do
      {:ok, coverage} ->
        :persistent_term.put(@cache_key, {cache_key, coverage})
        {:ok, coverage}

      {:error, _reason} = error ->
        error
    end
  end

  defp safe_from_coverdata(abs_path) do
    Coverage.from_coverdata(abs_path)
  rescue
    error -> {:error, {:coverdata_error, error}}
  catch
    kind, value -> {:error, {:coverdata_error, {kind, value}}}
  end

  # --- Analysis ---

  defp analyze(source_file, coverage_map, max_score, issue_meta) do
    source = SourceFile.source(source_file)

    case Complexity.from_string(source) do
      {:ok, functions} ->
        Enum.flat_map(functions, &issue_for_function(&1, coverage_map, max_score, issue_meta))

      {:error, _reason} ->
        []
    end
  end

  defp issue_for_function(function, coverage_map, max_score, issue_meta) do
    key = {function.module, function.function, function.arity}
    coverage_percent = Map.get(coverage_map, key, 0)

    case Score.score(function.complexity, coverage_percent) do
      {:ok, score} when score > max_score ->
        [build_issue(issue_meta, function, score, coverage_percent, max_score)]

      _other ->
        []
    end
  end

  defp build_issue(issue_meta, function, score, coverage_percent, max_score) do
    label = function_label(function)

    format_issue(
      issue_meta,
      message:
        "Function #{label} has a CRAP score of #{format_number(score)} " <>
          "(max is #{format_number(max_score)}; cyclomatic complexity #{function.complexity}, " <>
          "test coverage #{format_number(coverage_percent)}%). Add tests or reduce complexity.",
      trigger: label,
      line_no: function.line
    )
  end

  defp missing_coverage_issues(source_file, issue_meta) do
    source = SourceFile.source(source_file)

    case Complexity.from_string(source) do
      {:ok, [_ | _] = functions} ->
        line =
          functions
          |> Enum.map(& &1.line)
          |> Enum.reject(&is_nil/1)
          |> Enum.min(fn -> 1 end)

        [
          format_issue(
            issue_meta,
            message:
              "Cannot compute CRAP scores: no coverage data found. Run " <>
                "`mix test --cover --export-coverage default` before `mix credo`.",
            trigger: "defmodule",
            line_no: line
          )
        ]

      _other ->
        []
    end
  end

  defp function_label(function) do
    "#{inspect(function.module)}.#{function.function}/#{function.arity}"
  end

  defp format_number(number) do
    :erlang.float_to_binary(number * 1.0, decimals: 2)
  end
end
