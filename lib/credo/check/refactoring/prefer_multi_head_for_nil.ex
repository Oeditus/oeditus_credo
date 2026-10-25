defmodule OeditusCredo.Check.Refactoring.PreferMultiHeadForNil do
  @moduledoc """
  Flags `not is_nil(val)` guards in function definitions when multi-head pattern matching on `nil` should be used.

  Only the negated form is reported. A positive `when is_nil(val)` guard is
  already the most precise way to say "this clause is for `nil`" (and is often
  used to *narrow* a clause before falling through to a generic one), so it is
  not a smell.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Checking `not is_nil/1` in guards is unnecessary when pattern matching `nil` directly in multi-head functions.

      Bad:

          def process(val) when not is_nil(val) do
            ...
          end

      Good:

          def process(nil), do: :error
          def process(val), do: do_process(val)

      A positive `when is_nil(val)` guard is not reported: it is already the
      most precise way to match `nil` (and is commonly used to narrow a clause
      before a generic fallback).
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

  # Match definitions, not arbitrary `when` nodes: case patterns may themselves
  # be call-shaped AST (for example, a three-element tuple).
  defp traverse(
         {kind, _, [{:when, meta, [head, guard]}, _body]} = ast,
         issues,
         issue_meta
       )
       when kind in [:def, :defp] do
    issues =
      case find_nil_guard(guard) do
        nil ->
          issues

        var_name ->
          func_name = extract_func_name(head)

          [
            format_issue(
              issue_meta,
              message:
                "Function `#{func_name}` uses `is_nil(#{var_name})` in guard. Prefer pattern matching `nil` directly in multi-head clauses.",
              trigger: "is_nil",
              line_no: meta[:line]
            )
            | issues
          ]
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp find_nil_guard({:not, _, [{:is_nil, _, [{var, _, nil}]}]}) when is_atom(var), do: var
  defp find_nil_guard({:and, _, [left, right]}), do: find_nil_guard(left) || find_nil_guard(right)
  defp find_nil_guard({:or, _, [left, right]}), do: find_nil_guard(left) || find_nil_guard(right)
  defp find_nil_guard(_), do: nil

  defp extract_func_name({name, _, _}) when is_atom(name), do: Atom.to_string(name)
end
