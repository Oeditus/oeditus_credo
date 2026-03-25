defmodule OeditusCredo.Check.Warning.MissingPreload do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Missing preload in Ecto queries can lead to N+1 query problems.

      When fetching associations, use preload to fetch them efficiently in a single query.

      Bad:

          users = Repo.all(User)
          # Later accessing user.posts will trigger N+1 queries

      Good:

          import Ecto.Query
          users = User |> preload(:posts) |> Repo.all()
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

  # Check for Repo.all without preload in a pipe chain
  defp traverse(
         {:|>, meta, [left, {{:., _, [{:__aliases__, _, [:Repo]}, :all]}, _, _}]} = ast,
         issues,
         issue_meta
       ) do
    issues =
      if no_preload_in_chain?(left) do
        [issue_for(issue_meta, meta[:line]) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  # Check if the pipe chain contains preload
  defp no_preload_in_chain?({:|>, _, [left, right]}) do
    not preload?(right) and no_preload_in_chain?(left)
  end

  defp no_preload_in_chain?(_), do: true

  # Match preload as a direct function call: preload(:posts)
  defp preload?({:preload, _, _}), do: true
  # Match preload as a module function: Query.preload(:posts)
  defp preload?({{:., _, [_, :preload]}, _, _}), do: true
  defp preload?(_), do: false

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Consider using preload/2 to avoid N+1 queries when fetching associations",
      trigger: "Repo.all",
      line_no: line_no
    )
  end
end
