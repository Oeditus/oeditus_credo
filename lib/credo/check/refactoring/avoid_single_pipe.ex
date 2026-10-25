defmodule OeditusCredo.Check.Refactoring.AvoidSinglePipe do
  @moduledoc """
  Flags single-stage pipeline calls `x |> f()` which should be written as direct function calls `f(x)`.

  Stages belonging to a longer pipe chain are excluded. Independent pipelines
  inside call arguments or anonymous functions are still checked.
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

      walk(SourceFile.ast(source_file), [], issue_meta, false)
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp walk({:|>, meta, [lhs, rhs]}, issues, issue_meta, in_chain?) do
    issues =
      if in_chain? or nested_pipe?(lhs) do
        issues
      else
        [
          format_issue(
            issue_meta,
            message:
              "Single-stage pipe operator `|>` detected. Write as direct function call `f(x)` unless chaining 2+ operations.",
            trigger: "|>",
            line_no: meta[:line],
            column: meta[:column]
          )
          | issues
        ]
      end

    issues = walk(lhs, issues, issue_meta, true)
    walk(rhs, issues, issue_meta, false)
  end

  defp walk({name, _meta, args}, issues, issue_meta, _in_chain?) do
    issues = walk(name, issues, issue_meta, false)
    walk(args, issues, issue_meta, false)
  end

  defp walk({left, right}, issues, issue_meta, _in_chain?) do
    issues = walk(left, issues, issue_meta, false)
    walk(right, issues, issue_meta, false)
  end

  defp walk(list, issues, issue_meta, _in_chain?) when is_list(list) do
    Enum.reduce(list, issues, &walk(&1, &2, issue_meta, false))
  end

  defp walk(_node, issues, _issue_meta, _in_chain?), do: issues

  defp nested_pipe?({:|>, _, _}), do: true
  defp nested_pipe?(_), do: false
end
