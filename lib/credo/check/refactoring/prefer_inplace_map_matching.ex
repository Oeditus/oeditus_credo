defmodule OeditusCredo.Check.Refactoring.PreferInplaceMapMatching do
  @moduledoc """
  Flags guards using `is_map(arg)` when the function argument can pattern match `%{}`
  or `%{} = arg` directly in the parameter list.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Guarding `is_map(arg)` in function definitions is redundant when you can pattern match
      `%{}` or `%{} = arg` directly in the parameter list.

      Bad:

          def process(opts) when is_map(opts) do
            ...
          end

      Good:

          def process(%{} = opts) do
            ...
          end
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
      case find_is_map_guard(guard) do
        nil ->
          issues

        var_name ->
          func_name = extract_func_name(head)
          [
            format_issue(
              issue_meta,
              message: "Function `#{func_name}` uses `is_map(#{var_name})` in guard. Prefer inplace pattern matching `%{} = #{var_name}` in parameters.",
              trigger: "is_map",
              line_no: meta[:line]
            )
            | issues
          ]
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp find_is_map_guard({:is_map, _, [{var_name, _, nil}]}) when is_atom(var_name), do: var_name
  defp find_is_map_guard({:and, _, [left, right]}), do: find_is_map_guard(left) || find_is_map_guard(right)
  defp find_is_map_guard(_), do: nil

  defp extract_func_name({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp extract_func_name(_), do: "function"
end
