defmodule OeditusCredo.Check.Warning.NPlusOneQuery do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      N+1 query antipattern occurs when iterating over collections and querying the database for each item.

      This leads to poor performance. Use Ecto's `preload/2` to fetch associations in a single query.

      Bad:

          users = Repo.all(User)
          Enum.map(users, fn user ->
            posts = Repo.get_by(Post, user_id: user.id)
            {user, posts}
          end)

      Good:

          import Ecto.Query
          users = User |> preload(:posts) |> Repo.all()
          Enum.map(users, fn user -> {user, user.posts} end)
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

  # Check for Enum.map/each containing Repo calls
  defp traverse(
         {{:., _, [{:__aliases__, _, [:Enum]}, func]}, meta, [_collection, fun]} = ast,
         issues,
         issue_meta
       )
       when func in [:map, :each, :flat_map, :reduce] do
    issues =
      if has_repo_call_in_function?(fun) do
        [issue_for(issue_meta, meta[:line], func) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  # Check if function contains Repo calls
  defp has_repo_call_in_function?({:fn, _, clauses}) when is_list(clauses) do
    Enum.any?(clauses, &clause_has_repo_call?/1)
  end

  defp has_repo_call_in_function?(_), do: false

  defp clause_has_repo_call?({:->, _, [_params, body]}) do
    contains_repo_call?(body)
  end

  defp contains_repo_call?({:__block__, _, statements}) when is_list(statements) do
    Enum.any?(statements, &contains_repo_call?/1)
  end

  # Match Repo.get, Repo.get!, Repo.get_by, Repo.one, etc.
  defp contains_repo_call?({{:., _, [{:__aliases__, _, aliases}, func]}, _, _}) do
    List.last(aliases) == :Repo and is_atom(func)
  end

  # Recursively check nested structures
  defp contains_repo_call?({left, right}) do
    contains_repo_call?(left) or contains_repo_call?(right)
  end

  defp contains_repo_call?({_form, _, args}) when is_list(args) do
    Enum.any?(args, &contains_repo_call?/1)
  end

  defp contains_repo_call?(_), do: false

  defp issue_for(issue_meta, line_no, func) do
    format_issue(
      issue_meta,
      message: "Potential N+1 query in Enum.#{func} - consider using preload",
      trigger: "Enum.#{func}",
      line_no: line_no
    )
  end
end
