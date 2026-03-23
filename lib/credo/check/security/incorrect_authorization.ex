defmodule OeditusCredo.Check.Security.IncorrectAuthorization do
  @moduledoc """
  Checks for suspicious authorization flow and ordering.

  MITRE reference: [CWE-863](https://cwe.mitre.org/data/definitions/863.html) --
  Incorrect Authorization.
  """

  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potentially incorrect authorization order ([CWE-863](https://cwe.mitre.org/data/definitions/863.html)).

      Authorization should be checked BEFORE performing sensitive operations.

      Bad:

          Repo.delete!(post)
          authorize!(user, :delete, post)

      Good:

          authorize!(user, :delete, post)
          Repo.delete!(post)
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_auth_indicators:
          "Additional authorization indicator substrings to recognize (default: [])"
      ]
    ]

  @sensitive_repo_calls ~w[delete delete! update update! insert insert!]
  @default_auth_indicators ~w[authorize authorize! can? permit? allowed? policy bodyguard]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      extra = Params.get(params, :extra_auth_indicators, __MODULE__)
      indicators = @default_auth_indicators ++ extra

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, indicators}))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false, extra_auth_indicators: []]

  defp traverse(
         {:def, meta, [{_func_name, _, _args}, [do: body]]} = ast,
         issues,
         {issue_meta, indicators}
       ) do
    statements = block_to_statements(body)

    if auth_after_sensitive_operation?(statements, indicators) do
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "authorization check appears after sensitive operation in function body"
         )
         | issues
       ]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _ctx), do: {ast, issues}

  defp block_to_statements({:__block__, _, statements}) when is_list(statements), do: statements
  defp block_to_statements(statement), do: [statement]

  defp auth_after_sensitive_operation?(statements, indicators) do
    {_seen_sensitive, seen_auth_after} =
      Enum.reduce(statements, {false, false}, fn stmt, {seen_sensitive, seen_auth_after} ->
        cond do
          contains_sensitive_repo_call?(stmt) and not seen_auth_after ->
            {true, seen_auth_after}

          contains_authorization?(stmt, indicators) and seen_sensitive ->
            {seen_sensitive, true}

          true ->
            {seen_sensitive, seen_auth_after}
        end
      end)

    seen_auth_after
  end

  defp contains_sensitive_repo_call?({{:., _, [{:__aliases__, _, [:Repo]}, call]}, _, _args})
       when is_atom(call) do
    Atom.to_string(call) in @sensitive_repo_calls
  end

  defp contains_sensitive_repo_call?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_sensitive_repo_call?/1)
  end

  defp contains_sensitive_repo_call?(_), do: false

  defp contains_authorization?({{:., _, [{:__aliases__, _, parts}, name]}, _, _args}, indicators)
       when is_list(parts) and is_atom(name) do
    auth_name?(Enum.join(parts, ".") <> "." <> Atom.to_string(name), indicators)
  end

  defp contains_authorization?({:., _, [_left, right_name]}, indicators)
       when is_atom(right_name) do
    auth_name?(Atom.to_string(right_name), indicators)
  end

  defp contains_authorization?({name, _, _args}, indicators) when is_atom(name) do
    auth_name?(Atom.to_string(name), indicators)
  end

  defp contains_authorization?({_, _, args}, indicators) when is_list(args) do
    Enum.any?(args, &contains_authorization?(&1, indicators))
  end

  defp contains_authorization?(_, _indicators), do: false

  defp auth_name?(name, indicators) do
    down = String.downcase(name)
    Enum.any?(indicators, &String.contains?(down, &1))
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential incorrect authorization (CWE-863): #{detail}.",
      trigger: "authorize",
      line_no: line_no
    )
  end
end
