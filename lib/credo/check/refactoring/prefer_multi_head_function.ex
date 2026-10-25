defmodule OeditusCredo.Check.Refactoring.PreferMultiHeadFunction do
  @moduledoc """
  Flags top-level function bodies that use `if` or `cond` to branch on function parameters
  instead of defining multiple function heads with pattern matching.

  Only fully guard-compatible *discriminating* conditions are reported -- equality against a literal,
  membership in a literal list, or a type/emptiness guard (`is_nil/1`,
  `is_binary/1`, `is_atom/1`, ...). A plain boolean flag
  (`if opts[:write], do: ...`) is not a multi-head candidate: it has no
  pattern to match on, and splitting it would produce a confusing
  `def f(opts, true)` / `def f(opts, false)` pair.
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

      Only discriminating conditions are reported: equality with a literal,
      membership in a literal list, or a type/emptiness guard. A boolean flag
      (`if opts[:write], do: ...`) has no pattern to match on and is not a
      multi-head candidate.
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
          if discriminating_condition?(cond_expr, arg_names) do
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
          if cond_clauses_discriminate?(clauses, arg_names) do
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

  # A condition is only a multi-head candidate when it *discriminates* on the
  # argument: `mode == :fast`, `mode in [:a, :b]`, `is_nil(value)`. A bare
  # truthiness check (`if opts[:write]`, `if flag`) has no pattern to match on,
  # so it is not reported.
  defp discriminating_condition?(cond_expr, arg_names) do
    discriminator?(cond_expr, arg_names)
  end

  defp discriminator?({op, _, [lhs, rhs]}, arg_names) when op in [:==, :!=, :===, :!==] do
    (arg_reference?(lhs, arg_names) and literal?(rhs)) or
      (arg_reference?(rhs, arg_names) and literal?(lhs))
  end

  defp discriminator?({:in, _, [lhs, rhs]}, arg_names) do
    arg_reference?(lhs, arg_names) and literal_list?(rhs)
  end

  defp discriminator?({:not, _, [inner]}, arg_names), do: discriminator?(inner, arg_names)

  defp discriminator?({:and, _, [lhs, rhs]}, arg_names),
    do: discriminator?(lhs, arg_names) and discriminator?(rhs, arg_names)

  defp discriminator?({:or, _, [lhs, rhs]}, arg_names),
    do: discriminator?(lhs, arg_names) and discriminator?(rhs, arg_names)

  defp discriminator?({guard, _, [arg]}, arg_names)
       when guard in [
              :is_nil,
              :is_atom,
              :is_binary,
              :is_bitstring,
              :is_boolean,
              :is_float,
              :is_function,
              :is_integer,
              :is_list,
              :is_map,
              :is_number,
              :is_pid,
              :is_port,
              :is_reference,
              :is_tuple
            ] do
    arg_reference?(arg, arg_names)
  end

  defp discriminator?(_, _), do: false

  defp arg_reference?({var, _, ctx}, arg_names) when is_atom(var) and is_atom(ctx),
    do: var in arg_names

  defp arg_reference?(_, _), do: false

  defp literal?(value), do: is_atom(value) or is_number(value) or is_binary(value)

  defp literal_list?(list) when is_list(list) do
    Enum.all?(list, &(is_atom(&1) or is_number(&1) or is_binary(&1)))
  end

  defp literal_list?(_), do: false

  defp cond_clauses_discriminate?(clauses, arg_names) when is_list(clauses) do
    Enum.any?(clauses, fn
      {:->, _, [[condition], _]} -> discriminating_condition?(condition, arg_names)
      _ -> false
    end) and
      Enum.all?(clauses, fn
        {:->, _, [[true], _]} -> true
        {:->, _, [[condition], _]} -> discriminating_condition?(condition, arg_names)
        _ -> false
      end)
  end

  defp cond_clauses_discriminate?(_, _), do: false
end
