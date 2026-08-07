defmodule OeditusCredo.Check.Refactoring.PreferMultiHeadForNil do
  @moduledoc """
  Flags guard checks `is_nil(val)` or `not is_nil(val)` in function definitions when multi-head pattern matching on `nil` should be used.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Checking `is_nil/1` in guards is unnecessary when pattern matching `nil` directly in multi-head functions.

      Bad:

          def process(val) when not is_nil(val) do
            ...
          end

      Good:

          def process(nil), do: :error
          def process(val), do: do_process(val)
      """
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params \\ []) do
    issue_meta = IssueMeta.for(source_file, params)
    Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
  end

  defp traverse({:when, meta, [head, guard]} = ast, issues, issue_meta) do
    issues =
      case find_nil_guard(guard) do
        nil ->
          issues

        var_name ->
          func_name = extract_func_name(head)
          [
            format_issue(
              issue_meta,
              message: "Function `#{func_name}` uses `is_nil(#{var_name})` in guard. Prefer pattern matching `nil` directly in multi-head clauses.",
              trigger: "is_nil",
              line_no: meta[:line]
            )
            | issues
          ]
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp find_nil_guard({:is_nil, _, [{var, _, nil}]}) when is_atom(var), do: var
  defp find_nil_guard({:not, _, [{:is_nil, _, [{var, _, nil}]}]}) when is_atom(var), do: var
  defp find_nil_guard({:and, _, [left, right]}), do: find_nil_guard(left) || find_nil_guard(right)
  defp find_nil_guard(_), do: nil

  defp extract_func_name({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp extract_func_name(_), do: "function"
end
