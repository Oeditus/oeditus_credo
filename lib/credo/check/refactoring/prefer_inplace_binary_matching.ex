defmodule OeditusCredo.Check.Refactoring.PreferInplaceBinaryMatching do
  @moduledoc """
  Flags guard checks `is_binary(s) and s != ""` or `byte_size(s) > 0`
  which can be pattern matched directly with `<<_::utf8, _::binary>>` or `<<_, _::binary>>`.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Checking binary type and non-emptiness in guards can be replaced with direct
      binary pattern matching in the function parameter list: `<<_::utf8, _::binary>>` or `<<_, _::binary>>`.

      Bad:

          def process(str) when is_binary(str) and str != "" do
            ...
          end

      Good:

          def process(<<_::utf8, _::binary>> = str) do
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
      case find_binary_nonempty_guard(guard) do
        nil ->
          issues

        var_name ->
          func_name = extract_func_name(head)

          [
            format_issue(
              issue_meta,
              message:
                "Function `#{func_name}` checks `is_binary(#{var_name})` and non-empty in guard. Prefer inplace binary matching `<<_::utf8, _::binary>>`.",
              trigger: "is_binary",
              line_no: meta[:line]
            )
            | issues
          ]
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp find_binary_nonempty_guard({:and, _, [left, right]}) do
    case {binary_check_var(left), nonempty_check_var(right)} do
      {var, var} when is_atom(var) and not is_nil(var) ->
        var

      _ ->
        case {binary_check_var(right), nonempty_check_var(left)} do
          {var, var} when is_atom(var) and not is_nil(var) -> var
          _ -> nil
        end
    end
  end

  defp find_binary_nonempty_guard(_), do: nil

  defp binary_check_var({:is_binary, _, [{var, _, nil}]}) when is_atom(var), do: var
  defp binary_check_var(_), do: nil

  defp nonempty_check_var({:!=, _, [{var, _, nil}, ""]}) when is_atom(var), do: var
  defp nonempty_check_var({:!=, _, ["", {var, _, nil}]}) when is_atom(var), do: var

  defp nonempty_check_var({:>, _, [{:byte_size, _, [{var, _, nil}]}, 0]}) when is_atom(var),
    do: var

  defp nonempty_check_var({:!=, _, [{:byte_size, _, [{var, _, nil}]}, 0]}) when is_atom(var),
    do: var

  defp nonempty_check_var(_), do: nil

  defp extract_func_name({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp extract_func_name(_), do: "function"
end
