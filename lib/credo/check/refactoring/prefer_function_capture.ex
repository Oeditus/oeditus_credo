defmodule OeditusCredo.Check.Refactoring.PreferFunctionCapture do
  @moduledoc """
  Flags verbose anonymous functions `fn x -> Module.func(x) end` that can be written as function capture `&Module.func/1`.
  """

  use Credo.Check,
    base_priority: :low,
    category: :refactoring,
    explanations: [
      check: """
      Wrapping single function calls in anonymous functions `fn x -> String.trim(x) end` adds unnecessary syntax. Use function capture `&String.trim/1`.

      Bad:

          Enum.map(inputs, fn str -> String.trim(str) end)

      Good:

          Enum.map(inputs, &String.trim/1)
      """
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params \\ []) do
    issue_meta = IssueMeta.for(source_file, params)
    Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
  end

  # fn x -> Module.func(x) end
  defp traverse({:fn, meta, [{:->, _, [[{var, _, nil}], {{:., _, [_mod, _func]}, _, [{var, _, nil}]}]}]} = ast, issues, issue_meta) when is_atom(var) do
    issue =
      format_issue(
        issue_meta,
        message: "Verbose anonymous function `fn x -> Module.func(x) end`. Prefer function capture syntax `&Module.func/1`.",
        trigger: "fn",
        line_no: meta[:line]
      )
    {ast, [issue | issues]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}
end
