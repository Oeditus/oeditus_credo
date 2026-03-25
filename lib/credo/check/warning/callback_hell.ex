defmodule OeditusCredo.Check.Warning.CallbackHell do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Deeply nested case statements create callback hell and reduce readability.

      Use `with` statements or pipe operators for better flow control.

      Bad:

          case get_user(id) do
            {:ok, user} ->
              case get_account(user) do
                {:ok, account} ->
                  case process(account) do
                    {:ok, result} -> result
                  end
              end
          end

      Good:

          with {:ok, user} <- get_user(id),
               {:ok, account} <- get_account(user),
               {:ok, result} <- process(account) do
            result
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        max_nesting: "Maximum allowed case statement nesting (default: 2)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{}, false), do: []

  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      max_nesting = Params.get(params, :max_nesting, __MODULE__)

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, max_nesting}))
    end
  end

  @doc false
  @impl true
  def param_defaults do
    [exclude_test_files: false, max_nesting: 2]
  end

  defp traverse({:case, meta, _} = ast, issues, {issue_meta, max_nesting}) do
    nesting_level = count_case_nesting(ast)

    issues =
      if nesting_level > max_nesting do
        [issue_for(issue_meta, meta[:line], nesting_level) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _state) do
    {ast, issues}
  end

  defp count_case_nesting({:case, _, [_expr, [do: clauses]]}) when is_list(clauses) do
    max_nested = clauses |> Enum.map(&clause_case_nesting/1) |> Enum.max(fn -> 0 end)
    1 + max_nested
  end

  defp count_case_nesting(_), do: 0

  defp clause_case_nesting({:->, _, [_pattern, body]}) do
    count_nested_cases(body)
  end

  defp clause_case_nesting(_), do: 0

  defp count_nested_cases({:__block__, _, statements}) when is_list(statements) do
    statements |> Enum.map(&count_case_nesting/1) |> Enum.max(fn -> 0 end)
  end

  defp count_nested_cases({:case, _, _} = ast), do: count_case_nesting(ast)
  defp count_nested_cases(_), do: 0

  defp issue_for(issue_meta, line_no, level) do
    format_issue(
      issue_meta,
      message: "#{level} levels of nested case statements - consider using `with`",
      trigger: "case",
      line_no: line_no
    )
  end
end
