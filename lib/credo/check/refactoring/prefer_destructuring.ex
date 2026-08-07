defmodule OeditusCredo.Check.Refactoring.PreferDestructuring do
  @moduledoc """
  Flags calls to `elem/2` or `Map.get/2` when pattern match destructuring can be used instead.
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
      """
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params \\ []) do
    issue_meta = IssueMeta.for(source_file, params)
    Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
  end

  defp traverse({:elem, meta, [_tuple, _index]} = ast, issues, issue_meta) do
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

  defp traverse(
         {{:., meta, [{:__aliases__, _, [:Map]}, :get]}, _, [_map, key]} = ast,
         issues,
         issue_meta
       ) do
    if atom_literal?(key) do
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

  defp atom_literal?(val) when is_atom(val), do: true
  defp atom_literal?(_), do: false
end
