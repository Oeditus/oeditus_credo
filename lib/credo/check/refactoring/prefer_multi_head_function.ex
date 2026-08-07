defmodule OeditusCredo.Check.Refactoring.PreferMultiHeadFunction do
  @moduledoc """
  Flags top-level function bodies that use `if` or `cond` to branch on function parameters
  instead of defining multiple function heads with pattern matching.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Branching on function arguments inside the function body with `if` or `cond`
      violates Elixir's multi-head function idiom.

      Bad:

          def process(mode) do
            if mode == :fast do
              run_fast()
            else
              run_slow()
            end
          end

      Good:

          def process(:fast), do: run_fast()
          def process(:slow), do: run_slow()
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

  defp traverse({def_op, meta, [head, [do: body]]} = ast, issues, issue_meta)
       when def_op in [:def, :defp] do
    arg_names = extract_arg_names(head)

    issues =
      case root_conditional(body) do
        {:if, if_meta, cond_expr} ->
          if condition_references_arg?(cond_expr, arg_names) do
            func_name = extract_func_name(head)

            [
              format_issue(
                issue_meta,
                message:
                  "Function `#{func_name}` branches on parameter `#{inspect(arg_names)}` via `if`. Define multi-head function clauses instead.",
                trigger: "if",
                line_no: if_meta[:line] || meta[:line]
              )
              | issues
            ]
          else
            issues
          end

        {:cond, cond_meta, clauses} ->
          if cond_clauses_reference_args?(clauses, arg_names) do
            func_name = extract_func_name(head)

            [
              format_issue(
                issue_meta,
                message:
                  "Function `#{func_name}` dispatches logic on parameter `#{inspect(arg_names)}` via `cond`. Define multi-head function clauses instead.",
                trigger: "cond",
                line_no: cond_meta[:line] || meta[:line]
              )
              | issues
            ]
          else
            issues
          end

        _ ->
          issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp root_conditional({:if, meta, [cond_expr, _opts]}), do: {:if, meta, cond_expr}
  defp root_conditional({:cond, meta, [[do: clauses]]}), do: {:cond, meta, clauses}
  defp root_conditional({:__block__, _, [single]}), do: root_conditional(single)
  defp root_conditional(_), do: nil

  defp extract_arg_names({:when, _, [head, _guard]}), do: extract_arg_names(head)

  defp extract_arg_names({_name, _, args}) when is_list(args) do
    Enum.flat_map(args, fn
      {var, _, nil} when is_atom(var) -> [var]
      {:=, _, [{var, _, nil}, _]} when is_atom(var) -> [var]
      _ -> []
    end)
  end

  defp extract_arg_names(_), do: []

  defp extract_func_name({:when, _, [head, _guard]}), do: extract_func_name(head)
  defp extract_func_name({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp extract_func_name(_), do: "function"

  defp condition_references_arg?(cond_expr, arg_names) do
    {_ast, found?} =
      Macro.prewalk(cond_expr, false, fn
        {var, _, nil} = node, _acc when is_atom(var) ->
          if var in arg_names, do: {node, true}, else: {node, false}

        node, acc ->
          {node, acc}
      end)

    found?
  end

  defp cond_clauses_reference_args?(clauses, arg_names) when is_list(clauses) do
    Enum.any?(clauses, fn
      {:->, _, [[cond_expr], _body]} -> condition_references_arg?(cond_expr, arg_names)
      _ -> false
    end)
  end

  defp cond_clauses_reference_args?(_, _), do: false
end
