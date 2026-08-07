defmodule OeditusCredo.Check.Refactoring.PreferListPrepend do
  @moduledoc """
  Flags appending elements to lists (`list ++ [item]`) which forces O(N) list traversal instead of O(1) prepending `[item | list]`.
  """

  use Credo.Check,
    base_priority: :high,
    category: :refactoring,
    explanations: [
      check: """
      Appending to a list (`list ++ [item]`) traverses the entire list (O(N)), leading to quadratic runtime in loops. Prepend `[item | list]` in O(1) and reverse at the end.

      Bad:

          acc = acc ++ [new_item]

      Good:

          acc = [new_item | acc]
          # Enum.reverse(acc)
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
    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      issue_meta = IssueMeta.for(source_file, params)
      Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp traverse({:++, meta, [_lhs, [{_, _, _} | _]]} = ast, issues, issue_meta) do
    issue =
      format_issue(
        issue_meta,
        message:
          "Appending to list (`list ++ [item]`) is O(N). Prepend `[item | list]` in O(1) and reverse at the end.",
        trigger: "++",
        line_no: meta[:line]
      )

    {ast, [issue | issues]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}
end
