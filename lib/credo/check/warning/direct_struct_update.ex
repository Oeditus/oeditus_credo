defmodule OeditusCredo.Check.Warning.DirectStructUpdate do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Use changesets instead of direct struct updates for data validation.

      Direct struct updates bypass validation and can lead to invalid data in the database.

      Bad:

          user = %User{user | email: new_email}
          Map.put(user, :email, new_email)

      Good:

          user
          |> User.changeset(%{email: new_email})
          |> Repo.update()
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_struct_patterns:
          "Additional regex pattern strings for struct-like variable names (default: [])"
      ]
    ]

  @default_struct_pattern ~r/(user|post|comment|account|record|entity|model)$/

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      extra = Params.get(params, :extra_struct_patterns, __MODULE__)

      patterns =
        [@default_struct_pattern | Enum.map(extra, &Regex.compile!/1)]

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, patterns}))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false, extra_struct_patterns: []]

  # Match struct update syntax: %User{user | field: value}
  defp traverse(
         {:%, meta, [_module, {:%{}, _, [{:|, _, [_struct, _updates]}]}]} = ast,
         issues,
         {issue_meta, _patterns}
       ) do
    {ast, [issue_for(issue_meta, meta[:line], "struct update") | issues]}
  end

  # Match Map.put on what looks like a struct
  defp traverse(
         {{:., meta, [{:__aliases__, _, [:Map]}, :put]}, _, [struct_var | _]} = ast,
         issues,
         {issue_meta, patterns}
       ) do
    if looks_like_struct?(struct_var, patterns) do
      {ast, [issue_for(issue_meta, meta[:line], "Map.put") | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _ctx) do
    {ast, issues}
  end

  # Check if variable name suggests it's a struct
  defp looks_like_struct?({name, _, _}, patterns) when is_atom(name) do
    name_str = Atom.to_string(name)
    Enum.any?(patterns, &Regex.match?(&1, name_str))
  end

  defp looks_like_struct?(_, _patterns), do: false

  defp issue_for(issue_meta, line_no, type) do
    format_issue(
      issue_meta,
      message: "Use Ecto changesets instead of direct #{type} for data validation",
      trigger: type,
      line_no: line_no
    )
  end
end
