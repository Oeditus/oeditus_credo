defmodule OeditusCredo.Check.Refactoring.PreferTaggedTuplesForErrors do
  @moduledoc """
  Flags `try...rescue` blocks used for ordinary control flow instead of returning tagged tuples `{:ok, val}` / `{:error, reason}`.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Using `try...rescue` for ordinary control flow is inefficient on BEAM. Prefer safe functions returning tagged tuples `{:ok, val}` / `{:error, reason}`.

      Bad:

          try do
            String.to_integer(str)
          rescue
            ArgumentError -> :invalid
          end

      Good:

          case Integer.parse(str) do
            {num, ""} -> {:ok, num}
            _ -> :invalid
          end
      """
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params \\ []) do
    issue_meta = IssueMeta.for(source_file, params)
    Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
  end

  defp traverse({:try, meta, [_args]} = ast, issues, issue_meta) do
    issue =
      format_issue(
        issue_meta,
        message:
          "Found `try...rescue` block used for control flow. Prefer safe functions returning `{:ok, val}` or `{:error, reason}`.",
        trigger: "try",
        line_no: meta[:line]
      )

    {ast, [issue | issues]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}
end
