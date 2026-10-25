defmodule OeditusCredo.Check.Refactoring.AnalysisPrecisionTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Refactoring.{
    AvoidSinglePipe,
    PreferDestructuring,
    PreferMultiHeadForNil,
    PreferMultiHeadFunction,
    PreferPipelineOperator,
    PreferStringBoundariesOverRegex,
    PreferTaggedTuplesForErrors,
    PreferWithClause
  }

  describe "AvoidSinglePipe" do
    for expression <- [
          "input |> String.trim() |> String.downcase()",
          "input |> String.trim() |> String.downcase() |> String.reverse()",
          """
          input
          |> Enum.map(fn item -> item |> String.trim() |> String.downcase() end)
          |> Enum.sort()
          """,
          "input |> Enum.map(&(path(&1) |> Path.basename() |> String.downcase())) |> Enum.sort()"
        ] do
      test "does not report stages of #{expression}" do
        unquote(expression)
        |> to_source_file()
        |> run_check(AvoidSinglePipe)
        |> refute_issues()
      end
    end

    for expression <- [
          "String.trim(input) |> String.downcase()",
          "input |> Enum.map(fn x -> x |> String.trim() end) |> Enum.sort()",
          "input |> process(other |> String.trim()) |> finish()",
          "wrap(input |> String.trim()) |> process() |> finish()",
          "input |> process(other |> String.trim() |> String.downcase())"
        ] do
      test "reports exactly the independent single pipe in #{expression}" do
        assert [_] =
                 unquote(expression)
                 |> to_source_file()
                 |> run_check(AvoidSinglePipe)
      end
    end

    test "preserves separate columns for identical same-line pipes" do
      issues =
        "{input |> trim(), input |> trim(), input |> trim() |> downcase()}"
        |> to_source_file()
        |> run_check(AvoidSinglePipe)

      assert [first, second] = Enum.sort_by(issues, & &1.column)
      assert first.line_no == 1
      assert second.line_no == 1
      assert first.column == 8
      assert second.column == 25
    end

    test "checks independent single pipes in both outer and inner expressions" do
      assert [_, _] =
               "input |> process(other |> trim())"
               |> to_source_file()
               |> run_check(AvoidSinglePipe)
    end

    test "honours false even with offending source" do
      "input |> trim()"
      |> to_source_file()
      |> AvoidSinglePipe.run(false)
      |> refute_issues()
    end
  end

  describe "PreferPipelineOperator" do
    test "reports only the safe prefix before control flow needs its result" do
      assert [issue] =
               """
               image_path = Map.get(registry, title)
               thumb = prepare_thumbnail(image_path)
               text_width = if thumb, do: 100, else: 200
               {thumb, text_width}
               """
               |> to_source_file()
               |> run_check(PreferPipelineOperator)

      assert issue.message =~ "image_path -> thumb"
      refute issue.message =~ "text_width"
    end

    for body <- [
          """
          docs = fetch_docs(project)
          index = Enum.find_index(docs, &(&1.slug == slug))
          Enum.at(docs, index)
          """,
          """
          targets = fetch_targets(input)
          unknown = targets -- known_targets()
          unknown
          """,
          """
          path = Path.join(dir, filename)
          present? = File.exists?(path)
          {path, present?}
          """,
          """
          date = ~D[2026-09-15]
          first = quote_of_the_day(date)
          second = quote_of_the_day(date)
          {first, second}
          """,
          """
          sample = "fixture"
          html = render(sample)
          {sample, html}
          """,
          """
          a = prepare(input)
          b = combine(a, a)
          b
          """,
          """
          a = prepare(input)
          b = consume(a, fn -> a end)
          b
          """,
          """
          a = fetch_all()
          b = Enum.find(a, & &1.active)
          b
          """,
          """
          a = build_fun(input)
          b = a.(a)
          b
          """,
          """
          a = choose_module(input)
          b = a.transform(a)
          b
          """,
          """
          a = :outer
          result = (
            a = String.trim(input)
            b = String.upcase(a)
            b
          )
          {a, result}
          """
        ] do
      test "leaves necessary bindings or non-pipe stages intact: #{body}" do
        """
        defmodule Test do
          def run(input, project, slug, title, dir, filename) do
            #{unquote(body)}
          end
        end
        """
        |> to_source_file()
        |> run_check(PreferPipelineOperator)
        |> refute_issues()
      end
    end

    for body <- [
          "a = trim(input)\nb = downcase(a)\nb",
          "a = fetch_all()\nb = Enum.sort(a)\nc = Enum.reverse(b)\nc",
          "a = trim(input)\na = downcase(a)\na",
          "a = String.trim(input)\nb = String.downcase(a)\nb",
          "a = fun.(input)\nb = other.(a)\nb"
        ] do
      test "retains a genuine transformation chain: #{body}" do
        """
        defmodule Test do
          def run(input) do
            #{unquote(body)}
          end
        end
        """
        |> to_source_file()
        |> run_check(PreferPipelineOperator)
        |> assert_issue()
      end
    end
  end

  describe "PreferDestructuring" do
    for expression <- [
          "Map.get(attrs, :title) || Map.get(attrs, \"title\") || default_title()",
          "Map.get(item, :author) || @default_author",
          "Map.get(item, :image) || Map.get(item, :logo)",
          "Map.get(item, :url)",
          "Map.get(%{text: \"quote\"}, :author)",
          "Map.get(%{author: nil}, :author, \"default\")",
          "Map.get(item, key)",
          "elem(tuple, index)"
        ] do
      test "does not recommend a required pattern for #{expression}" do
        unquote(expression)
        |> to_source_file()
        |> run_check(PreferDestructuring)
        |> refute_issues()
      end
    end

    test "still reports a literal map with a guaranteed key" do
      "Map.get(%{name: name, other: side_effect()}, :name)"
      |> to_source_file()
      |> run_check(PreferDestructuring)
      |> assert_issue()
    end

    test "preserves literal tuple projection capture suggestions" do
      "Enum.map(invalid, &elem(&1, 0))"
      |> to_source_file()
      |> run_check(PreferDestructuring)
      |> assert_issue()
    end

    test "missing keys are semantically different from required patterns" do
      assert optional_author(%{text: "quote"}) == nil
      refute author_pattern?(%{text: "quote"})
    end
  end

  describe "PreferMultiHeadForNil" do
    for expression <- [
          "with value when not is_nil(value) <- fetch(), do: value",
          "case input do {a, b, c} when not is_nil(a) -> {a, b, c} end",
          "for {a, b, c} when not is_nil(a) <- input, do: {a, b, c}",
          "fn {a, b, c} when not is_nil(a) -> {a, b, c} end"
        ] do
      test "ignores non-definition guard in #{expression}" do
        unquote(expression)
        |> to_source_file()
        |> run_check(PreferMultiHeadForNil)
        |> refute_issues()
      end
    end

    test "still reports private function heads" do
      "defp run(value) when not is_nil(value), do: value"
      |> to_source_file()
      |> run_check(PreferMultiHeadForNil)
      |> assert_issue()
    end
  end

  describe "PreferMultiHeadFunction" do
    for condition <- [
          "Keyword.get(opts, :write, false)",
          "String.ends_with?(opts, \".md\")",
          "opts",
          "is_custom(opts)",
          "opts == :fast and ready?(opts)",
          "ready?(opts == :fast)"
        ] do
      test "ignores conditions not expressible as head guards: #{condition}" do
        "def run(opts), do: if #{unquote(condition)}, do: :yes, else: :no"
        |> to_source_file()
        |> run_check(PreferMultiHeadFunction)
        |> refute_issues()
      end
    end

    for condition <- ["opts == :fast", "opts in [:fast, :slow]", "not is_nil(opts)"] do
      test "retains guard-compatible condition #{condition}" do
        "def run(opts), do: if #{unquote(condition)}, do: :yes, else: :no"
        |> to_source_file()
        |> run_check(PreferMultiHeadFunction)
        |> assert_issue()
      end
    end

    test "does not report cond when another branch requires a normal function" do
      """
      def run(mode) do
        cond do
          mode == :fast -> :fast
          ready?(mode) -> :ready
          true -> :other
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferMultiHeadFunction)
      |> refute_issues()
    end
  end

  describe "PreferStringBoundariesOverRegex" do
    for regex <- [
          "~r/^[0-9a-fA-F]{6}$/",
          "~r/^prefix/i",
          "~r/^prefix/m",
          "~r/^prefix/x",
          "~r/suffix$/",
          "~r/^a|b/",
          "~r/^a.b/",
          "~r/^a+/",
          "~r/^/",
          ~S"~r/^prefix#{suffix}/"
        ] do
      test "preserves non-literal or option-sensitive regex #{regex}" do
        "Regex.match?(#{unquote(regex)}, value)"
        |> to_source_file()
        |> run_check(PreferStringBoundariesOverRegex)
        |> refute_issues()
      end
    end

    test "documents why regex options and dollar anchors are not string boundaries" do
      assert Regex.match?(~r/^prefix/i, "PREFIX")
      refute String.starts_with?("PREFIX", "prefix")
      assert Regex.match?(~r/^prefix/m, "other\nprefix")
      refute String.starts_with?("other\nprefix", "prefix")
      assert Regex.match?(~r/suffix$/, "suffix\n")
      refute String.ends_with?("suffix\n", "suffix")
    end
  end

  describe "PreferTaggedTuplesForErrors" do
    for expression <- [
          "try do work() after cleanup() end",
          "try do work() catch :exit, _ -> :stopped end",
          "try do work() rescue _ -> :error after cleanup() end"
        ] do
      test "does not confuse cleanup or catch with rescue control flow: #{expression}" do
        unquote(expression)
        |> to_source_file()
        |> run_check(PreferTaggedTuplesForErrors)
        |> refute_issues()
      end
    end
  end

  describe "PreferWithClause" do
    test "requires explicit exception preservation for non-exhaustive cases" do
      assert [issue] =
               """
               case first() do
                 {:ok, value} ->
                   case second(value) do
                     {:ok, result} -> result
                   end
               end
               """
               |> to_source_file()
               |> run_check(PreferWithClause)

      assert issue.message =~ "explicit `else`"
      assert issue.message =~ "CaseClauseError"

      original = fn input ->
        case input do
          {:ok, first} ->
            case first do
              {:ok, value} -> value
            end
        end
      end

      converted = fn input ->
        with {:ok, first} <- input,
             {:ok, value} <- first do
          value
        else
          unmatched -> raise CaseClauseError, term: unmatched
        end
      end

      assert original.({:ok, {:ok, :value}}) == converted.({:ok, {:ok, :value}})

      for input <- [{:error, :first}, {:ok, {:error, :second}}] do
        old_error = assert_raise CaseClauseError, fn -> original.(input) end
        new_error = assert_raise CaseClauseError, fn -> converted.(input) end
        assert old_error.term == new_error.term
      end
    end

    test "does not combine a raising outer case with a value-returning inner fallback" do
      """
      case first() do
        {:ok, value} ->
          case second(value) do
            {:ok, result} -> result
            _ -> nil
          end
      end
      """
      |> to_source_file()
      |> run_check(PreferWithClause)
      |> refute_issues()
    end

    test "does not treat pinned values as newly bound step results" do
      """
      case first() do
        {:ok, ^existing} ->
          case second(existing) do
            {:ok, value} -> value
          end
      end
      """
      |> to_source_file()
      |> run_check(PreferWithClause)
      |> refute_issues()
    end

    test "retains sequential operations sharing the same catch-all fallback" do
      """
      case Image.open(path) do
        {:ok, image} ->
          case Image.thumbnail(image, "260x220") do
            {:ok, thumb} -> thumb
            _ -> nil
          end
        _ -> nil
      end
      """
      |> to_source_file()
      |> run_check(PreferWithClause)
      |> assert_issue()
    end

    test "does not flatten a fallback search cascade" do
      """
      case Regex.run(first, body) do
        [_, src] -> src
        nil ->
          case Regex.run(second, body) do
            [_, src] -> src
            nil -> nil
          end
      end
      """
      |> to_source_file()
      |> run_check(PreferWithClause)
      |> refute_issues()
    end

    test "does not flatten parsing branches with distinct fallback behavior" do
      """
      case split(contents) do
        [code, body] ->
          case eval(code) do
            {%{} = attrs, _} -> {attrs, body}
            {other, _} -> raise inspect(other)
          end
        [_] -> {infer_attrs(contents), contents}
      end
      """
      |> to_source_file()
      |> run_check(PreferWithClause)
      |> refute_issues()
    end
  end

  defp optional_author(map), do: Map.get(map, :author)

  defp author_pattern?(map), do: match?(%{author: _}, map)
end
