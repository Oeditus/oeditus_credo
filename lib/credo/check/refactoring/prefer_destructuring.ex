defmodule OeditusCredo.Check.Refactoring.PreferDestructuring do
  @moduledoc """
  Flags calls to `elem/2` or `Map.get/2` when pattern match destructuring can be used instead.

  Map lookups are only reported for map literals that explicitly contain the
  requested key. `Map.get/2` returns `nil` for an absent key, whereas a required-key
  pattern fails; unknown maps and optional keys therefore cannot safely be
  rewritten. `Map.get/3` is never reported because patterns have no default.
  Tuple extraction is only reported for non-negative literal indexes.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Calling `elem/2` or `Map.get/2` to extract data from tuples or maps obscures pattern matching.

      Bad:

          status = elem(result, 0)
          name = Map.get(user, :name)

      Good:

          {:ok, payload} = result
          %{name: name} = user

      Map suggestions require a literal map containing the key; arbitrary maps
      may omit it. `Map.get/3` and dynamic tuple indexes are not reported.
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

  defp traverse({:elem, meta, [_tuple, index]} = ast, issues, issue_meta)
       when is_integer(index) and index >= 0 do
    issue =
      format_issue(
        issue_meta,
        message:
          "Calling `elem/2` forces imperative tuple extraction. Prefer pattern match destructuring.",
        trigger: "elem",
        line_no: meta[:line]
      )

    {ast, [issue | issues]}
  end

  # `Map.get/3` (with a default) is intentionally not matched: a pattern
  # match cannot express a default, so the two forms are not equivalent.
  defp traverse(
         {{:., meta, [{:__aliases__, _, [:Map]}, :get]}, _, [map, key]} = ast,
         issues,
         issue_meta
       ) do
    if is_atom(key) and literal_key?(map, key) do
      issue =
        format_issue(
          issue_meta,
          message:
            "Calling `Map.get/2` with atom key #{inspect(key)}. Prefer pattern match destructuring `%{#{key}: val}`.",
          trigger: "Map.get",
          line_no: meta[:line]
        )

      {ast, [issue | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp literal_key?({:%{}, _, entries}, key) do
    Enum.any?(entries, fn
      {^key, _value} -> true
      _ -> false
    end)
  end

  defp literal_key?(_, _), do: false
end
