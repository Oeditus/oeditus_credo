defmodule OeditusCredo.Crap do
  @moduledoc false

  # Ported (subset) from ExCrap (https://github.com/germsvel/ex_crap), MIT License,
  # Copyright (c) 2026 The Software League. See NOTICE.md for the full notice.
  #
  # Glue that joins per-function complexity with explicit coverage data by MFA key.
  # Only the source-analysis subset needed by the Credo check is ported here; the
  # `mix crap` task, project scanner, and report renderer are intentionally omitted.

  alias OeditusCredo.Crap.Complexity
  alias OeditusCredo.Crap.Score

  @doc """
  Calculates the canonical CRAP score for a complexity and coverage percentage.
  """
  @spec score(number(), number()) ::
          {:ok, float()} | {:error, :invalid_complexity | :invalid_coverage}
  def score(complexity, coverage_percent) do
    Score.score(complexity, coverage_percent)
  end

  @doc """
  Analyzes Elixir source and combines each discovered function with explicit coverage.

  `coverage_by_function` must be a map keyed by `{module, function_name, arity}`:

      %{{Example, :visible?, 1} => 75.0}

  Coverage values are percentages from `0` to `100`. Functions without a matching
  coverage entry are scored as `0%` covered. Returns `{:ok, scored_functions}` or
  an error tuple from the analyzer.
  """
  @spec analyze_string(binary(), map()) :: {:ok, [map()]} | {:error, term()}
  def analyze_string(source, coverage_by_function) when is_map(coverage_by_function) do
    with {:ok, functions} <- Complexity.from_string(source) do
      {:ok, Enum.map(functions, &score_function(&1, coverage_by_function))}
    end
  end

  def analyze_string(_source, _coverage_by_function), do: {:error, :invalid_coverage_map}

  @doc """
  Analyzes one Elixir source file and combines each discovered function with explicit coverage.
  """
  @spec analyze_file(binary(), map()) :: {:ok, [map()]} | {:error, term()}
  def analyze_file(path, coverage_by_function) when is_map(coverage_by_function) do
    with {:ok, functions} <- Complexity.from_file(path) do
      {:ok, Enum.map(functions, &score_function(&1, coverage_by_function))}
    end
  end

  def analyze_file(_path, _coverage_by_function), do: {:error, :invalid_coverage_map}

  defp score_function(function, coverage_by_function) do
    key = {function.module, function.function, function.arity}
    coverage_percent = Map.get(coverage_by_function, key, 0)

    case score(function.complexity, coverage_percent) do
      {:ok, score} ->
        function
        |> Map.put(:coverage_percent, coverage_percent)
        |> Map.put(:score, score)
        |> Map.put(:status, :scored)

      {:error, reason} ->
        function
        |> Map.put(:coverage_percent, coverage_percent)
        |> Map.put(:status, {:error, reason})
    end
  end
end
