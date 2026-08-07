defmodule OeditusCredo.Check.Refactoring.PreferDotAccessForStructs do
  @moduledoc """
  Flags bracket access `struct[:key]` on struct variables, which should use dot notation `struct.key` or destructuring.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Bracket access syntax `struct[:field]` on structs is unidiomatic and fails at runtime unless `Access` is implemented. Use dot notation `struct.field` or pattern matching destructuring instead.

      Bad:

          user[:name]

      Good:

          user.name
          # Or: %User{name: name} = user
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

  # Bracket access user[:name]: {{:., meta, [Access, :get]}, meta2, [{var, _, nil}, key]}
  defp traverse(
         {{:., meta, [Access, :get]}, _meta2, [{var, _, nil}, key]} = ast,
         issues,
         issue_meta
       )
       when is_atom(var) do
    if atom_literal?(key) and Keyword.get(meta, :from_brackets, false) do
      issue =
        format_issue(
          issue_meta,
          message:
            "Bracket access `#{var}[#{inspect(key)}]` detected. Prefer direct dot notation `#{var}.#{key}` or destructuring.",
          trigger: "[",
          line_no: meta[:line]
        )

      {ast, [issue | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp atom_literal?(val) when is_atom(val), do: true
  defp atom_literal?(_), do: false
end
