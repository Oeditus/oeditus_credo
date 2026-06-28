defmodule OeditusCredo.Crap.Score do
  @moduledoc false

  # Ported from ExCrap (https://github.com/germsvel/ex_crap), MIT License,
  # Copyright (c) 2026 The Software League. See NOTICE.md for the full notice.
  #
  # CRAP = complexity^2 * (1 - coverage_percent / 100)^3 + complexity.

  @doc """
  Calculates the canonical CRAP score for a complexity and coverage percentage.

  `complexity` must be numeric and non-negative. `coverage_percent` must be
  numeric and between `0` and `100` inclusive. Returns `{:ok, score}` or
  `{:error, reason}`.
  """
  @spec score(number(), number()) ::
          {:ok, float()} | {:error, :invalid_complexity | :invalid_coverage}
  def score(complexity, coverage_percent) do
    with :ok <- validate_complexity(complexity),
         :ok <- validate_coverage(coverage_percent) do
      uncovered = 1 - coverage_percent / 100
      {:ok, complexity * complexity * uncovered * uncovered * uncovered + complexity * 1.0}
    end
  end

  defp validate_complexity(complexity) when is_number(complexity) and complexity >= 0, do: :ok
  defp validate_complexity(_complexity), do: {:error, :invalid_complexity}

  defp validate_coverage(coverage_percent)
       when is_number(coverage_percent) and coverage_percent >= 0 and coverage_percent <= 100,
       do: :ok

  defp validate_coverage(_coverage_percent), do: {:error, :invalid_coverage}
end
