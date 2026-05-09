defmodule OeditusCredo.Check.Readability.UnnecessaryInterpolatingSigilTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Readability.UnnecessaryInterpolatingSigil

  # ── ~s ──────────────────────────────────────────────────────────────

  test "reports ~s without interpolation" do
    ~S"""
    defmodule MyApp do
      def html, do: ~s"<br>"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> assert_issue(fn issue ->
      assert issue.message =~ "~s sigil contains no interpolation"
      assert issue.message =~ "~S"
    end)
  end

  test "no issue for ~s with interpolation" do
    ~S"""
    defmodule MyApp do
      def html(tag), do: ~s"<#{tag}>"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> refute_issues()
  end

  test "no issue for ~S (already uppercase)" do
    ~S"""
    defmodule MyApp do
      def html, do: ~S"<br>"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> refute_issues()
  end

  # ── ~w ──────────────────────────────────────────────────────────────

  test "reports ~w without interpolation" do
    ~S"""
    defmodule MyApp do
      @fields ~w"name email age"a
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> assert_issue(fn issue ->
      assert issue.message =~ "~w"
      assert issue.message =~ "~W"
    end)
  end

  test "no issue for ~w with interpolation" do
    ~S"""
    defmodule MyApp do
      def fields(extra), do: ~w"name #{extra}"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> refute_issues()
  end

  # ── ~c ──────────────────────────────────────────────────────────────

  test "reports ~c without interpolation" do
    ~S"""
    defmodule MyApp do
      def charlist, do: ~c"hello"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> assert_issue(fn issue ->
      assert issue.message =~ "~c"
      assert issue.message =~ "~C"
    end)
  end

  test "no issue for ~c with interpolation" do
    ~S"""
    defmodule MyApp do
      def charlist(name), do: ~c"hello #{name}"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> refute_issues()
  end

  # ── edge cases ──────────────────────────────────────────────────────

  test "no issue for plain string literals" do
    """
    defmodule MyApp do
      def html, do: "<br>"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> refute_issues()
  end

  test "reports multiple sigils in the same module" do
    ~S"""
    defmodule MyApp do
      @fields ~w"name email"a
      def html, do: ~s"<br>"
    end
    """
    |> to_source_file()
    |> run_check(UnnecessaryInterpolatingSigil)
    |> assert_issues(fn issues ->
      assert [_, _] = issues
    end)
  end
end
