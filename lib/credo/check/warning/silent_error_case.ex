defmodule OeditusCredo.Check.Warning.SilentErrorCase do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Case statements that only handle the success case can lead to unhandled errors.

      When a case statement only matches on `{:ok, _}` without handling `{:error, _}` 
      or providing a catch-all clause, errors will not be properly handled.

      Bad:

          case Accounts.get_user(id) do
            {:ok, user} -> user
          end

      Good:

          case Accounts.get_user(id) do
            {:ok, user} -> user
            {:error, reason} -> handle_error(reason)
          end

      Or with catch-all:

          case Accounts.get_user(id) do
            {:ok, user} -> user
            _ -> nil
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp traverse({:case, meta, [_expr, [do: clauses]]} = ast, issues, issue_meta) do
    issues =
      if only_ok_clause?(clauses) do
        [issue_for(issue_meta, meta[:line]) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  defp only_ok_clause?(clauses) when is_list(clauses) do
    length(clauses) == 1 and ok_only_clause?(hd(clauses))
  end

  defp only_ok_clause?(_), do: false

  # Check if a clause is an :ok pattern without error handling
  # Case clause pattern is {:->, meta, [pattern_list, body]}
  # where pattern_list is a list of patterns (usually one element)
  defp ok_only_clause?({:->, _, [pattern_list, _body]}) when is_list(pattern_list) do
    Enum.any?(pattern_list, &ok_pattern?/1)
  end

  defp ok_only_clause?(_), do: false

  # Match 2-element tuple: {:ok, value}
  defp ok_pattern?({:ok, _}), do: true
  # Match 2-element tuple with metadata: {:ok, meta, context}
  defp ok_pattern?({:ok, _, _}), do: true
  # Match 3+ element tuples: {:{}, meta, [:ok | rest]}
  defp ok_pattern?({:{}, _, [:ok | _]}), do: true
  defp ok_pattern?(_), do: false

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Case statement only handles :ok tuple without error or catch-all clause",
      trigger: "case",
      line_no: line_no
    )
  end
end
