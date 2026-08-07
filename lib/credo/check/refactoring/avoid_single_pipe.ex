defmodule OeditusCredo.Check.Refactoring.AvoidSinglePipe do
  @moduledoc """
  Flags single-stage pipeline calls `x |> f()` which should be written as direct function calls `f(x)`.
  """

  use Credo.Check,
    base_priority: :low,
    category: :refactoring,
    explanations: [
      check: """
      Single-stage pipes (`data |> String.trim()`) add unnecessary syntax. Pipes should only be used to chain 2 or more function calls.

      Bad:

          data |> String.trim()

      Good:

          String.trim(data)
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

  defp traverse({:|>, meta, [lhs, _rhs]} = ast, issues, issue_meta) do
    if nested_pipe?(lhs) do
      {ast, issues}
    else
      issue =
        format_issue(
          issue_meta,
          message:
            "Single-stage pipe operator `\|>` detected. Write as direct function call `f(x)` unless chaining 2+ operations.",
          trigger: "|>",
          line_no: meta[:line]
        )

      {ast, [issue | issues]}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp nested_pipe?({:|>, _, _}), do: true
  defp nested_pipe?(_), do: false
end
