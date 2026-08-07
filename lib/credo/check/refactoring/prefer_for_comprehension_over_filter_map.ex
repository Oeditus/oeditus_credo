defmodule OeditusCredo.Check.Refactoring.PreferForComprehensionOverFilterMap do
  @moduledoc """
  Flags sequential `Enum.filter |> Enum.map` or `Enum.map |> Enum.filter` pipelines that should use `for` comprehension or `Enum.flat_map`.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Piping `Enum.filter` into `Enum.map` (or vice-versa) iterates over the list twice and allocates intermediate lists.

      Bad:

          list |> Enum.filter(&valid?/1) |> Enum.map(&transform/1)

      Good:

          for item <- list, valid?(item), do: transform(item)
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

  # list |> Enum.filter(...) |> Enum.map(...)
  defp traverse({:|>, meta, [{:|>, _, [_lhs, filter_call]}, map_call]} = ast, issues, issue_meta) do
    issues =
      if filter_map_pipeline?(filter_call, map_call) do
        [
          format_issue(
            issue_meta,
            message:
              "Sequential `Enum.filter |> Enum.map` pipeline traverses list twice. Prefer `for` comprehension or `Enum.flat_map`.",
            trigger: "|>",
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

  defp filter_map_pipeline?(
         {{:., _, [{:__aliases__, _, [:Enum]}, :filter]}, _, _},
         {{:., _, [{:__aliases__, _, [:Enum]}, :map]}, _, _}
       ),
       do: true

  defp filter_map_pipeline?(
         {{:., _, [{:__aliases__, _, [:Enum]}, :map]}, _, _},
         {{:., _, [{:__aliases__, _, [:Enum]}, :filter]}, _, _}
       ),
       do: true

  defp filter_map_pipeline?(_, _), do: false
end
