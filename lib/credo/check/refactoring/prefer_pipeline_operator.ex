defmodule OeditusCredo.Check.Refactoring.PreferPipelineOperator do
  @moduledoc """
  Flags consecutive variable assignments where each variable is used immediately
  as the first argument in the subsequent function call.

  Only chains yielding at least two pipe stages are reported. Operators, literals
  and control-flow expressions are not pipeline stages. Intermediate bindings
  must not be reused in other arguments or after their consuming assignment.
  This is a conservative syntactic check, not interprocedural data-flow analysis.
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

      Bindings used later are not temporary: a pipeline must not remove them.
      Literal fixtures followed by one call are also left alone, avoiding a
      conflicting recommendation from `AvoidSinglePipe`.
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
      walk(SourceFile.ast(source_file), [], issue_meta, [])
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp walk({:__block__, _meta, statements}, issues, issue_meta, continuation) do
    issues = find_pipeable_chains(statements, issue_meta, continuation) ++ issues

    statements
    |> Enum.with_index()
    |> Enum.reduce(issues, fn {statement, index}, acc ->
      walk(statement, acc, issue_meta, Enum.drop(statements, index + 1) ++ continuation)
    end)
  end

  defp walk({kind, _, [_head, body]}, issues, issue_meta, _continuation)
       when kind in [:def, :defp, :->] do
    walk(body, issues, issue_meta, [])
  end

  defp walk({name, _meta, args}, issues, issue_meta, continuation) when is_list(args) do
    walk_children([name | args], issues, issue_meta, continuation)
  end

  defp walk({left, right}, issues, issue_meta, continuation) do
    walk_children([left, right], issues, issue_meta, continuation)
  end

  defp walk(list, issues, issue_meta, continuation) when is_list(list) do
    walk_children(list, issues, issue_meta, continuation)
  end

  defp walk(_node, issues, _issue_meta, _continuation), do: issues

  defp walk_children(children, issues, issue_meta, continuation) do
    children
    |> Enum.with_index()
    |> Enum.reduce(issues, fn {child, index}, acc ->
      siblings = List.delete_at(children, index)
      walk(child, acc, issue_meta, siblings ++ continuation)
    end)
  end

  defp find_pipeable_chains(statements, issue_meta, continuation) do
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
          {prev_idx, _prev_meta, prev_var, prev_call} = List.last(current_chain)

          if idx == prev_idx + 1 and function_call?(prev_call) and
               uses_var_as_first_arg?(rhs_call, prev_var) and
               disposable_binding?(prev_var, lhs_var, statements, idx, continuation) do
            [current_chain ++ [{idx, meta, lhs_var, rhs_call}] | rest_chains]
          else
            [[{idx, meta, lhs_var, rhs_call}] | acc]
          end
      end
    end)
    |> Enum.filter(&multiple_pipe_stages?/1)
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

  defp multiple_pipe_stages?([_, _, _ | _]), do: true
  defp multiple_pipe_stages?([{_, _, _, {_, _, [_ | _]}}, _]), do: true
  defp multiple_pipe_stages?(_), do: false

  defp uses_var_as_first_arg?({callee, _, [{var_name, _, nil} | rest]} = call, target_var)
       when var_name == target_var do
    function_call?(call) and not references_var?([callee | rest], target_var)
  end

  defp uses_var_as_first_arg?(_, _), do: false

  defp function_call?({{:., _, _}, _, args}) when is_list(args), do: true

  defp function_call?({name, _, args}) when is_atom(name) and is_list(args) do
    not Macro.operator?(name, length(args)) and
      not Macro.special_form?(name, length(args)) and
      name not in [:if, :unless, :cond, :with, :for, :quote, :def, :defp]
  end

  defp function_call?(_), do: false

  defp disposable_binding?(var, var, _statements, _idx, _continuation), do: true

  defp disposable_binding?(var, _next_var, statements, idx, continuation) do
    not references_var?(Enum.drop(statements, idx + 1) ++ continuation, var)
  end

  defp references_var?(ast, var) do
    {_ast, found?} =
      Macro.prewalk(ast, false, fn
        {^var, _, context} = node, _acc when is_atom(context) -> {node, true}
        node, acc -> {node, acc}
      end)

    found?
  end
end
