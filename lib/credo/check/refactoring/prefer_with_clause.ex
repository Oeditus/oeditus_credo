defmodule OeditusCredo.Check.Refactoring.PreferWithClause do
  @moduledoc """
  Flags nested `case` statements (pyramid of doom) that should be refactored into a `with` clause.
  """

  use Credo.Check,
    base_priority: :high,
    category: :refactoring,
    explanations: [
      check: """
      Deeply nested `case` statements create unreadable code. Use `with` to chain sequential fallible operations cleanly.

      Bad:

          case step1() do
            {:ok, res1} ->
              case step2(res1) do
                {:ok, res2} -> {:ok, res2}
                {:error, err} -> {:error, err}
              end
            {:error, err} -> {:error, err}
          end

      Good:

          with {:ok, res1} <- step1(),
               {:ok, res2} <- step2(res1) do
            {:ok, res2}
          end
      """
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params \\ []) do
    issue_meta = IssueMeta.for(source_file, params)
    Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
  end

  defp traverse({:case, meta, [_expr, [do: clauses]]} = ast, issues, issue_meta) when is_list(clauses) do
    issues =
      if has_nested_case_clause?(clauses) do
        [
          format_issue(
            issue_meta,
            message: "Found nested `case` statement. Refactor sequential fallible operations into a `with` statement.",
            trigger: "case",
            line_no: meta[:line]
          )
          | issues
        ]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp has_nested_case_clause?(clauses) do
    Enum.any?(clauses, fn
      {:->, _, [_patterns, body]} -> contains_case?(body)
      _ -> false
    end)
  end

  defp contains_case?({:case, _, _}), do: true
  defp contains_case?({:__block__, _, block}) when is_list(block), do: Enum.any?(block, &contains_case?/1)
  defp contains_case?(_), do: false
end
