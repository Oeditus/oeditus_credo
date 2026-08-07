defmodule OeditusCredo.Check.Refactoring.PreferMapMerge do
  @moduledoc """
  Flags chained `Map.put` calls (`map |> Map.put(:a, 1) |> Map.put(:b, 2)`) which should use `Map.merge/2`.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Chaining multiple `Map.put` calls for literal keys is inefficient and verbose. Use `Map.merge(map, %{key: val})`.

      Bad:

          map |> Map.put(:a, 1) |> Map.put(:b, 2)

      Good:

          Map.merge(map, %{a: 1, b: 2})
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

  # map |> Map.put(:a, 1) |> Map.put(:b, 2)
  defp traverse({:|>, meta, [{:|>, _, [_lhs, put1]}, put2]} = ast, issues, issue_meta) do
    issues =
      if map_put_call?(put1) and map_put_call?(put2) do
        [
          format_issue(
            issue_meta,
            message:
              "Sequential `Map.put` calls piped together. Prefer `Map.merge(map, %{...})`.",
            trigger: "Map.put",
            line_no: meta[:line]
          )
          | issues
        ]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp map_put_call?({{:., _, [{:__aliases__, _, [:Map]}, :put]}, _, _}), do: true
  defp map_put_call?(_), do: false
end
