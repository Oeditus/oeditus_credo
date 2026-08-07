defmodule OeditusCredo.Check.Refactoring.PreferShortFieldAccessCapture do
  @moduledoc """
  Flags verbose struct field extraction `fn x -> x.field end` that can be written with short capture `& &1.field`.
  """

  use Credo.Check,
    base_priority: :low,
    category: :refactoring,
    explanations: [
      check: """
      Verbose anonymous function `fn x -> x.field end` for extracting a field can be shortened to `& &1.field`.

      Bad:

          Enum.map(users, fn u -> u.id end)

      Good:

          Enum.map(users, & &1.id)
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

  # fn x -> x.field end
  defp traverse(
         {:fn, meta, [{:->, _, [[{var, _, nil}], {{:., _, [{var, _, nil}, field]}, _, []}]}]} =
           ast,
         issues,
         issue_meta
       )
       when is_atom(var) and is_atom(field) do
    issue =
      format_issue(
        issue_meta,
        message:
          "Verbose field extraction `fn x -> x.#{field} end`. Prefer short capture syntax `& &1.#{field}`.",
        trigger: "fn",
        line_no: meta[:line]
      )

    {ast, [issue | issues]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}
end
