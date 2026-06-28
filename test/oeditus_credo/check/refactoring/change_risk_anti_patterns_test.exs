defmodule OeditusCredo.Check.Refactoring.ChangeRiskAntiPatternsTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Refactoring.ChangeRiskAntiPatterns

  # A function with cyclomatic complexity 8:
  # base 1 + if 1 + and 1 + case (3 branches) + cond (2 clauses).
  @complex_source """
  defmodule Example do
    def risky(a, b) do
      if a > 0 and b > 0 do
        case a do
          1 -> :one
          2 -> :two
          _ -> :many
        end
      else
        cond do
          b > 10 -> :big
          true -> :small
        end
      end
    end
  end
  """

  # A function with cyclomatic complexity 2: base 1 + if 1.
  @small_source """
  defmodule Example do
    def maybe(x) do
      if x, do: :yes, else: :no
    end
  end
  """

  describe "ChangeRiskAntiPatterns" do
    test "reports a complex, uncovered function above the default threshold" do
      @complex_source
      |> to_source_file("lib/example.ex")
      |> run_check(ChangeRiskAntiPatterns, coverage: %{})
      |> assert_issue(fn issue ->
        assert issue.message =~ "CRAP score"
        assert issue.message =~ "Example.risky/2"
      end)
    end

    test "does not report when the function is well covered" do
      @complex_source
      |> to_source_file("lib/example.ex")
      |> run_check(ChangeRiskAntiPatterns, coverage: %{{Example, :risky, 2} => 100})
      |> refute_issues()
    end

    test "honors a custom max_score" do
      # complexity 2 at 0% coverage => CRAP 6: above 5, below the default 30.
      @small_source
      |> to_source_file("lib/example.ex")
      |> run_check(ChangeRiskAntiPatterns, coverage: %{}, max_score: 5)
      |> assert_issue()
    end

    test "stays silent for a low score under the default threshold" do
      @small_source
      |> to_source_file("lib/example.ex")
      |> run_check(ChangeRiskAntiPatterns, coverage: %{})
      |> refute_issues()
    end

    test "is a no-op when coverage data is unavailable" do
      @complex_source
      |> to_source_file("lib/example.ex")
      |> run_check(ChangeRiskAntiPatterns, coverdata: "tmp/does_not_exist.coverdata")
      |> refute_issues()
    end

    test "reports missing coverage when require_coverage is true" do
      @complex_source
      |> to_source_file("lib/example.ex")
      |> run_check(ChangeRiskAntiPatterns,
        coverdata: "tmp/does_not_exist.coverdata",
        require_coverage: true
      )
      |> assert_issue(fn issue ->
        assert issue.message =~ "no coverage data"
      end)
    end

    test "skips test files by default" do
      @complex_source
      |> to_source_file("test/example_test.exs")
      |> run_check(ChangeRiskAntiPatterns, coverage: %{})
      |> refute_issues()
    end

    test "scores test files when exclude_test_files is false" do
      @complex_source
      |> to_source_file("test/example_test.exs")
      |> run_check(ChangeRiskAntiPatterns, coverage: %{}, exclude_test_files: false)
      |> assert_issue()
    end
  end
end
