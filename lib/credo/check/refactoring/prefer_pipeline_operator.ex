defmodule OeditusCredo.Check.Refactoring.PreferPipelineOperator do
  @moduledoc """
  Flags consecutive variable assignments where each variable is used immediately
  as the first argument in the subsequent function call.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Assigning intermediate results to temporary variables just to pass them
      as the first argument in the next line is unidiomatic in Elixir.

      Bad:

          step1 = String.trim(input)
          step2 = String.downcase(step1)
          step3 = String.reverse(step2)

      Good:

          input
          |> String.trim()
          |> String.downcase()
          |> String.reverse()
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

  defp traverse({:__block__, _meta, statements} = ast, issues, issue_meta)
       when is_list(statements) and length(statements) >= 2 do
    new_issues = find_pipeable_chains(statements, issue_meta)
    {ast, new_issues ++ issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp find_pipeable_chains(statements, issue_meta) do
    indexed = Enum.with_index(statements)

    assignments =
      Enum.flat_map(indexed, fn
        {{:=, meta, [{lhs_var, _, nil}, rhs_call]}, idx} when is_atom(lhs_var) ->
          [{idx, meta, lhs_var, rhs_call}]

        _ ->
          []
      end)

    assignments
    |> Enum.reduce([], fn {idx, meta, lhs_var, rhs_call}, acc ->
      case acc do
        [] ->
          [[{idx, meta, lhs_var, rhs_call}]]

        [current_chain | rest_chains] ->
          {prev_idx, _prev_meta, prev_var, _prev_call} = List.last(current_chain)

          if idx == prev_idx + 1 and uses_var_as_first_arg?(rhs_call, prev_var) do
            [current_chain ++ [{idx, meta, lhs_var, rhs_call}] | rest_chains]
          else
            [[{idx, meta, lhs_var, rhs_call}] | acc]
          end
      end
    end)
    |> Enum.filter(fn chain -> length(chain) >= 2 end)
    |> Enum.map(fn chain ->
      {_first_idx, first_meta, _first_var, _first_call} = List.first(chain)
      vars = Enum.map_join(chain, " -> ", fn {_, _, v, _} -> Atom.to_string(v) end)

      format_issue(
        issue_meta,
        message: "Sequential assignments (`#{vars}`) can be refactored into a pipeline (`|>`).",
        trigger: "=",
        line_no: first_meta[:line]
      )
    end)
  end

  defp uses_var_as_first_arg?({_func, _, [{var_name, _, nil} | _rest]}, target_var)
       when var_name == target_var, do: true

  defp uses_var_as_first_arg?(
         {{:., _, [_module, _func]}, _, [{var_name, _, nil} | _rest]},
         target_var
       )
       when var_name == target_var, do: true

  defp uses_var_as_first_arg?(_, _), do: false
end
