defmodule OeditusCredo.Check.Security.InsecureDirectObjectReference do
  @moduledoc """
  Checks for direct object access patterns that may permit IDOR.

  MITRE reference: [CWE-639](https://cwe.mitre.org/data/definitions/639.html) —
  Authorization Bypass Through User-Controlled Key.
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential Insecure Direct Object Reference (IDOR) vulnerabilities ([CWE-639](https://cwe.mitre.org/data/definitions/639.html)).

      Fetching resources by user-provided IDs without ownership or authorization
      checks can allow users to access other users' data.

      Bad:

          post = Repo.get!(Post, params["id"])

      Good:

          post = Repo.get!(Post, params["id"])
          authorize!(current_user, :read, post)
      """,
      params: []
    ]

  @repo_fetch_calls ~w[get get! get_by get_by!]
  @ownership_indicators ~w[current_user user_id owner_id authorize authorize! policy]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    source_file
    |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
  end

  defp traverse({:def, meta, [{_func_name, _, _args}, [do: body]]} = ast, issues, issue_meta) do
    statements = block_to_statements(body)

    if has_idor_pattern?(statements) and not has_ownership_check?(statements) do
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "Repo.get/get! with params-sourced id found without ownership/authorization check"
         )
         | issues
       ]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp block_to_statements({:__block__, _, statements}) when is_list(statements), do: statements
  defp block_to_statements(statement), do: [statement]

  defp has_idor_pattern?(statements) do
    Enum.any?(statements, &contains_idor_fetch?/1)
  end

  defp contains_idor_fetch?({{:., _, [{:__aliases__, _, [:Repo]}, fetch]}, _, args})
       when is_atom(fetch) and is_list(args) do
    Atom.to_string(fetch) in @repo_fetch_calls and Enum.any?(args, &params_id_access?/1)
  end

  defp contains_idor_fetch?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_idor_fetch?/1)
  end

  defp contains_idor_fetch?(_), do: false

  # params["id"] or params[:id]
  defp params_id_access?({{:., _, [Access, :get]}, _, [{:params, _, _}, key]}) do
    id_key?(key)
  end

  defp params_id_access?(
         {{:., _, [Access, :get]}, _, [{{:., _, [{:conn, _, _}, :params]}, _, _}, key]}
       ) do
    id_key?(key)
  end

  defp params_id_access?({:params, _, _}), do: true
  defp params_id_access?({:id, _, _}), do: true
  defp params_id_access?(_), do: false

  defp id_key?({:id, _, _}), do: true
  defp id_key?(:id), do: true
  defp id_key?("id"), do: true
  defp id_key?(_), do: false

  defp has_ownership_check?(statements) do
    Enum.any?(statements, &contains_ownership_indicator?/1)
  end

  defp contains_ownership_indicator?({name, _, _args}) when is_atom(name) do
    ownership_name?(Atom.to_string(name))
  end

  defp contains_ownership_indicator?({{:., _, [{:__aliases__, _, parts}, name]}, _, _args})
       when is_list(parts) and is_atom(name) do
    ownership_name?(Enum.join(parts, ".") <> "." <> Atom.to_string(name))
  end

  defp contains_ownership_indicator?({:., _, [_left, right_name]}) when is_atom(right_name) do
    ownership_name?(Atom.to_string(right_name))
  end

  defp contains_ownership_indicator?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_ownership_indicator?/1)
  end

  defp contains_ownership_indicator?(_), do: false

  defp ownership_name?(name) do
    down = String.downcase(name)
    Enum.any?(@ownership_indicators, &String.contains?(down, &1))
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential IDOR vulnerability (CWE-639): #{detail}.",
      trigger: "Repo.get",
      line_no: line_no
    )
  end
end
