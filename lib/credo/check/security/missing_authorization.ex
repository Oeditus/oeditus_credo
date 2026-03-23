defmodule OeditusCredo.Check.Security.MissingAuthorization do
  @moduledoc """
  Checks for sensitive operations that appear to lack authorization checks.

  MITRE reference: [CWE-862](https://cwe.mitre.org/data/definitions/862.html) --
  Missing Authorization.
  """

  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential missing authorization checks ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)).

      Sensitive operations such as `Repo.delete/2`, `Repo.update/2`,
      and `Repo.insert/2` should be protected by authorization checks.

      Bad:

          def delete(conn, %{"id" => id}) do
            post = Repo.get!(Post, id)
            Repo.delete!(post)
          end

      Good:

          def delete(conn, %{"id" => id}) do
            post = Repo.get!(Post, id)
            authorize!(conn.assigns.current_user, :delete, post)
            Repo.delete!(post)
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_auth_indicators:
          "Additional authorization indicator substrings to recognize (default: [])"
      ]
    ]

  @sensitive_repo_calls ~w[delete delete! update update! insert insert!]
  @default_auth_indicators ~w[authorize authorize! can? permit? allowed? current_user policy bodyguard]

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
         {:def, meta, [{func_name, _, _args}, [do: body]]} = ast,
         issues,
         {issue_meta, indicators}
       )
       when is_atom(func_name) do
    statements = block_to_statements(body)

    if has_sensitive_repo_call?(statements) and
         not has_authorization_check?(statements, indicators) do
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "function #{func_name} performs sensitive data operation without authorization"
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

  defp has_sensitive_repo_call?(statements),
    do: Enum.any?(statements, &contains_sensitive_repo_call?/1)

  defp contains_sensitive_repo_call?({{:., _, [{:__aliases__, _, [:Repo]}, call]}, _, _args})
       when is_atom(call) do
    Atom.to_string(call) in @sensitive_repo_calls
  end

  defp contains_sensitive_repo_call?({:|>, _, [left, right]}) do
    contains_sensitive_repo_call?(left) or contains_sensitive_repo_call?(right)
  end

  defp contains_sensitive_repo_call?({:__block__, _, statements}) when is_list(statements) do
    Enum.any?(statements, &contains_sensitive_repo_call?/1)
  end

  defp contains_sensitive_repo_call?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_sensitive_repo_call?/1)
  end

  defp contains_sensitive_repo_call?(_), do: false

  defp has_authorization_check?(statements, indicators) do
    Enum.any?(statements, &contains_authorization?(&1, indicators))
  end

  defp contains_authorization?(
         {{:., _, [{:__aliases__, _, mod_parts}, name]}, _, _args},
         indicators
       )
       when is_list(mod_parts) and is_atom(name) do
    full_name = Enum.join(mod_parts, ".") <> "." <> Atom.to_string(name)
    auth_name?(full_name, indicators)
  end

  defp contains_authorization?({:., _, [_left, right_name]}, indicators)
       when is_atom(right_name) do
    auth_name?(Atom.to_string(right_name), indicators)
  end

  defp contains_authorization?({:if, _, [cond_ast | _]}, indicators) do
    contains_authorization?(cond_ast, indicators)
  end

  defp contains_authorization?({:case, _, [expr | clauses]}, indicators) do
    contains_authorization?(expr, indicators) or
      Enum.any?(clauses, &contains_authorization?(&1, indicators))
  end

  defp contains_authorization?({:->, _, [patterns, body]}, indicators) do
    contains_authorization?(patterns, indicators) or contains_authorization?(body, indicators)
  end

  defp contains_authorization?({:__block__, _, statements}, indicators)
       when is_list(statements) do
    Enum.any?(statements, &contains_authorization?(&1, indicators))
  end

  defp contains_authorization?({name, _, _args}, indicators) when is_atom(name) do
    auth_name?(Atom.to_string(name), indicators)
  end

  defp contains_authorization?({_, _, args}, indicators) when is_list(args) do
    Enum.any?(args, &contains_authorization?(&1, indicators))
  end

  defp contains_authorization?(_, _indicators), do: false

  defp auth_name?(name, indicators) when is_binary(name) do
    down = String.downcase(name)
    Enum.any?(indicators, &String.contains?(down, &1))
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential missing authorization (CWE-862): #{detail}.",
      trigger: "Repo",
      line_no: line_no
    )
  end
end
