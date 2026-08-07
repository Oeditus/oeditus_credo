defmodule OeditusCredo.Check.Refactoring.PreferInplaceListMatching do
  @moduledoc """
  Flags guard calls to `length(list)` (e.g., `length(l) > 0` or `length(l) == 0`)
  which perform O(N) list traversals in guards instead of pattern matching `[_ | _]` or `[]`.
  """

  use Credo.Check,
    base_priority: :high,
    category: :refactoring,
    explanations: [
      check: """
      Calling `length/1` in guards forces full O(N) list traversal.
      Use pattern matching `[_ | _]` for non-empty lists or `[]` for empty lists instead.

      Bad:

          def process(items) when length(items) > 0 do
            ...
          end

      Good:

          def process([_ | _] = items) do
            ...
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

  defp traverse({:when, meta, [head, guard]} = ast, issues, issue_meta) do
    issues =
      case find_length_guard(guard) do
        nil ->
          issues

        {var_name, op, count} ->
          func_name = extract_func_name(head)

          suggestion =
            if op in [:>, :>=, :!=] or (op == :== and count > 0), do: "[_ | _]", else: "[]"

          [
            format_issue(
              issue_meta,
              message:
                "Function `#{func_name}` calls O(N) `length(#{var_name}) #{op} #{count}` in guard. Prefer pattern matching `#{suggestion}`.",
              trigger: "length",
              line_no: meta[:line]
            )
            | issues
          ]
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp find_length_guard({op, _, [{:length, _, [{var_name, _, nil}]}, count]})
       when op in [:>, :>=, :==, :!=] and is_integer(count) and is_atom(var_name) do
    {var_name, op, count}
  end

  defp find_length_guard({op, _, [count, {:length, _, [{var_name, _, nil}]}]})
       when op in [:<, :<=, :==, :!=] and is_integer(count) and is_atom(var_name) do
    normalized_op =
      case op do
        :< -> :>
        :<= -> :>=
        other -> other
      end

    {var_name, normalized_op, count}
  end

  defp find_length_guard({:and, _, [left, right]}),
    do: find_length_guard(left) || find_length_guard(right)

  defp find_length_guard(_), do: nil

  defp extract_func_name({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp extract_func_name(_), do: "function"
end
