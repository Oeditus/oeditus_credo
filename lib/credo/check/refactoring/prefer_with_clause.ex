defmodule OeditusCredo.Check.Refactoring.PreferWithClause do
  @moduledoc """
  Flags nested `case` statements (pyramid of doom) that should be refactored into a `with` clause.

  A nested `case` is only reported when it is genuinely `with`-shaped: the
  success clause's body must be exactly the inner `case`, whose expression
  uses a variable bound by the outer success pattern. Cases with catch-all
  fallbacks are reported only when both steps have the same fallback body.
  Divergent parsing branches and fallback cascades are left alone.
  """

  use Credo.Check,
    base_priority: :high,
    category: :refactoring,
    explanations: [
      check: """
      Deeply nested `case` statements create unreadable code. Use `with` to chain sequential fallible operations cleanly.

      Bad:

          case step1() do
            {:ok, res1} ->
              case step2(res1) do
                {:ok, res2} -> {:ok, res2}
                _ -> nil
              end
            _ -> nil
          end

      Good:

          with {:ok, res1} <- step1(),
               {:ok, res2} <- step2(res1) do
            {:ok, res2}
          else
            _ -> nil
          end

      Single-success-clause cases and two-clause cases with identical catch-all
      fallbacks are candidates. Different fallbacks cannot be collapsed into
      one `with` failure path without changing behaviour.

      For non-exhaustive single-clause cases, preserve exceptions explicitly:

          else
            unmatched -> raise CaseClauseError, term: unmatched
          end
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

  defp traverse({:case, meta, [_expr, [do: clauses]]} = ast, issues, issue_meta)
       when is_list(clauses) do
    issues =
      if nested_case_candidate?(clauses) do
        [
          format_issue(
            issue_meta,
            message:
              "Found nested `case` statement. Refactor sequential fallible operations into `with`, with explicit `else` clauses preserving fallback values or `CaseClauseError` for unmatched input.",
            trigger: "case",
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

  defp nested_case_candidate?([{:->, _, [patterns, body]}]) when is_list(patterns) do
    case nested_case(body) do
      {:ok, {:case, _, [_, [do: [_single_clause]]]} = inner} ->
        dispatches_on_bound_var?(inner, patterns)

      _ ->
        false
    end
  end

  defp nested_case_candidate?([
         {:->, _, [patterns, {:case, _, [_expr, [do: inner_clauses]]} = inner]},
         fallback
       ]) do
    with [_, inner_fallback] <- inner_clauses,
         {:ok, outer_body} <- fallback_body(fallback),
         {:ok, inner_body} <- fallback_body(inner_fallback) do
      same_ast?(outer_body, inner_body) and
        not references_bound_vars?(outer_body, patterns) and
        dispatches_on_bound_var?(inner, patterns)
    else
      _ -> false
    end
  end

  defp nested_case_candidate?(_clauses), do: false

  defp fallback_body({:->, _, [[{:_, _, context}], body]}) when is_atom(context),
    do: {:ok, body}

  defp fallback_body(_), do: :error

  defp same_ast?(left, right), do: without_metadata(left) == without_metadata(right)

  defp without_metadata(ast) do
    Macro.prewalk(ast, fn
      {name, meta, args} when is_list(meta) -> {name, [], args}
      node -> node
    end)
  end

  defp references_bound_vars?(body, patterns) do
    Enum.any?(bound_vars(patterns), &var_referenced?(body, &1))
  end

  defp nested_case({:case, _, [_expr, _clauses]} = inner), do: {:ok, inner}
  defp nested_case({:__block__, _, [inner]}), do: nested_case(inner)
  defp nested_case(_), do: :error

  defp dispatches_on_bound_var?({:case, _, [expr, _clauses]}, patterns) do
    bound = bound_vars(patterns)
    Enum.any?(bound, &var_referenced?(expr, &1))
  end

  defp bound_vars(patterns) do
    patterns |> pattern_vars() |> Enum.uniq()
  end

  defp pattern_vars({:^, _, _}), do: []
  defp pattern_vars({:when, _, [pattern | _guards]}), do: pattern_vars(pattern)
  defp pattern_vars({:_, _, _}), do: []
  defp pattern_vars({var, _, ctx}) when is_atom(var) and is_atom(ctx), do: [var]
  defp pattern_vars({_, _, args}) when is_list(args), do: pattern_vars(args)
  defp pattern_vars({left, right}), do: pattern_vars([left, right])
  defp pattern_vars(patterns) when is_list(patterns), do: Enum.flat_map(patterns, &pattern_vars/1)
  defp pattern_vars(_), do: []

  defp var_referenced?(ast, var) do
    {_ast, found?} =
      Macro.prewalk(ast, false, fn
        {^var, _, ctx} = node, _acc when is_atom(ctx) -> {node, true}
        node, acc -> {node, acc}
      end)

    found?
  end
end
