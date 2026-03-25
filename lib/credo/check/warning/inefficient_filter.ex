defmodule OeditusCredo.Check.Warning.InefficientFilter do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Using `Repo.all()` followed by `Enum.filter` is inefficient and should be done in SQL.

      Filtering data after fetching it from the database wastes memory and processing power.
      Use Ecto query's `where/3` to filter in the database.

      Bad:

          users = Repo.all(User)
          active_users = Enum.filter(users, & &1.active)

      Good:

          import Ecto.Query
          active_users = User |> where([u], u.active == true) |> Repo.all()
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
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
      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp traverse(ast, issues, issue_meta) do
    {ast, issues} = find_repo_all_with_filter(ast, issues, issue_meta)
    {ast, issues}
  end

  # Look for patterns like: var = Repo.all(...); Enum.filter(var, ...)
  defp find_repo_all_with_filter({:defp, _, _} = ast, issues, issue_meta) do
    issues = check_function_body(ast, issues, issue_meta)
    {ast, issues}
  end

  defp find_repo_all_with_filter({:def, _, _} = ast, issues, issue_meta) do
    issues = check_function_body(ast, issues, issue_meta)
    {ast, issues}
  end

  defp find_repo_all_with_filter(ast, issues, _issue_meta) do
    {ast, issues}
  end

  defp check_function_body({_, meta, [_head, [do: body]]}, issues, issue_meta) do
    check_body_for_pattern(body, meta[:line], issues, issue_meta)
  end

  defp check_function_body(_, issues, _), do: issues

  defp check_body_for_pattern({:__block__, _, statements}, line, issues, issue_meta)
       when is_list(statements) do
    find_repo_filter_pattern(statements, line, issues, issue_meta)
  end

  defp check_body_for_pattern(_, _, issues, _), do: issues

  defp find_repo_filter_pattern(statements, line, issues, issue_meta) do
    statements
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.reduce(issues, fn
      [{:=, _, [var, repo_call]}, filter_call], acc ->
        if repo_all?(repo_call) and enum_filter_on_var?(filter_call, var) do
          [issue_for(issue_meta, line || 1) | acc]
        else
          acc
        end

      _, acc ->
        acc
    end)
  end

  defp repo_all?({{:., _, [{:__aliases__, _, [_, :Repo]}, :all]}, _, _}), do: true
  defp repo_all?({{:., _, [{:__aliases__, _, [:Repo]}, :all]}, _, _}), do: true
  defp repo_all?(_), do: false

  defp enum_filter_on_var?(
         {{:., _, [{:__aliases__, _, [:Enum]}, func]}, _, [var | _]},
         target_var
       )
       when func in [:filter, :reject, :find, :find_value] do
    vars_match?(var, target_var)
  end

  defp enum_filter_on_var?(_, _), do: false

  defp vars_match?({name, _, _}, {name, _, _}), do: true
  defp vars_match?(_, _), do: false

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Use Ecto query's where() instead of Repo.all() followed by Enum.filter()",
      trigger: "Repo.all",
      line_no: line_no
    )
  end
end
