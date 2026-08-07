defmodule OeditusCredo.Check.Refactoring.PreferCasePatternMatching do
  @moduledoc """
  Flags `if` or `cond` statements checking structural equality (atoms, tagged tuples,
  elem/2 checks, or repeating variable equality) where `case` pattern matching is preferred.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Using `if` or `cond` for tagged tuples, atoms, or repeating variable equality checks
      obscures structural pattern matching.

      Bad:

          if status == {:ok, data} do
            process(data)
          else
            handle_error()
          end

      Good:

          case status do
            {:ok, data} -> process(data)
            _ -> handle_error()
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

  defp traverse({:cond, meta, [[do: clauses]]} = ast, issues, issue_meta) when is_list(clauses) do
    vars_checked =
      Enum.flat_map(clauses, fn
        {:->, _, [[{:==, _, [{var, _, nil}, _rhs]}], _body]} when is_atom(var) -> [var]
        {:->, _, [[{:==, _, [_, {var, _, nil}]}], _body]} when is_atom(var) -> [var]
        _ -> []
      end)

    issues =
      if length(vars_checked) >= 2 and Enum.count(Enum.uniq(vars_checked)) == 1 do
        var_name = List.first(vars_checked)

        [
          format_issue(
            issue_meta,
            message:
              "`cond` checks equality of variable `#{var_name}` repeatedly. Prefer `case #{var_name} do` pattern matching.",
            trigger: "cond",
            line_no: meta[:line]
          )
          | issues
        ]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse({:if, meta, [condition, _opts]} = ast, issues, issue_meta) do
    issues =
      if matches_case_candidate?(condition) do
        [
          format_issue(
            issue_meta,
            message:
              "`if` condition performs structural equality check. Prefer `case` pattern matching.",
            trigger: "if",
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

  defp matches_case_candidate?({:==, _, [left, right]}) do
    pattern_literal?(left) or pattern_literal?(right) or tuple_elem_check?(left) or
      tuple_elem_check?(right)
  end

  defp matches_case_candidate?({:elem, _, [_, _]}), do: true
  defp matches_case_candidate?(_), do: false

  defp pattern_literal?({:{}, _, _}), do: true
  defp pattern_literal?({_, _}), do: true
  defp pattern_literal?(val) when is_atom(val) and val not in [true, false, nil], do: true
  defp pattern_literal?(_), do: false

  defp tuple_elem_check?({:elem, _, _}), do: true
  defp tuple_elem_check?(_), do: false
end
