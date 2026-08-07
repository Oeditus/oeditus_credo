defmodule OeditusCredo.Check.Refactoring.PreferPatternMatchingForEmptiness do
  @moduledoc """
  Flags calls to `Enum.count(list) > 0` or `Enum.count(list) == 0` when pattern matching `[_ | _]` or `[]` can be used.
  """

  use Credo.Check,
    base_priority: :high,
    category: :refactoring,
    explanations: [
      check: """
      `Enum.count/1` traverses the full list to calculate count just to check if it's empty or non-empty. Use pattern matching `[_ | _]` or `[]` instead.

      Bad:

          if Enum.count(list) > 0 do ... end

      Good:

          case list do
            [_ | _] -> ...
            [] -> ...
          end
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

  defp traverse(
         {_op, meta, [{{:., _, [{:__aliases__, _, [:Enum]}, :count]}, _, [_list]}, _count]} = ast,
         issues,
         issue_meta
       ) do
    issue =
      format_issue(
        issue_meta,
        message:
          "`Enum.count/1` traverses entire list to check emptiness. Prefer pattern matching `[_ | _]` or `[]`.",
        trigger: "Enum.count",
        line_no: meta[:line]
      )

    {ast, [issue | issues]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}
end
