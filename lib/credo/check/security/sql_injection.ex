defmodule OeditusCredo.Check.Security.SQLInjection do
  @moduledoc """
  Checks for patterns that may allow SQL injection through dynamic query construction.

  MITRE reference: [CWE-89](https://cwe.mitre.org/data/definitions/89.html) —
  Improper Neutralization of Special Elements used in an SQL Command
  ("SQL Injection").
  """
  use Credo.Check,
    base_priority: :higher,
    category: :warning,
    explanations: [
      check: """
      Detects potential SQL injection vulnerabilities ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)).

      Building SQL queries through string concatenation or interpolation with
      user-controlled input enables SQL injection attacks.

      Bad:

          Repo.query("SELECT * FROM users WHERE id = " <> id)
          Ecto.Adapters.SQL.query(Repo, "SELECT * FROM users WHERE name = '\#{name}'")
          fragment("SELECT * FROM users WHERE id = " <> ^id)

      Good:

          Repo.query("SELECT * FROM users WHERE id = $1", [id])
          from(u in User, where: u.id == ^id)
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @sql_keywords ~w[SELECT INSERT UPDATE DELETE DROP CREATE ALTER TRUNCATE EXEC EXECUTE]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{}, false), do: []
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  # Detect: Repo.query("SQL..." <> var)
  # AST: {{:., _, [Repo, :query]}, _, [concat_arg | _]}
  defp traverse(
         {{:., _, [{:__aliases__, _, repo_mod}, func]}, meta, args} = ast,
         issues,
         issue_meta
       )
       when func in [:query, :query!] and is_list(args) do
    with repo_name when repo_name in [:Repo, :SQL] <- List.last(repo_mod),
         [first_arg | _] <- args,
         true <- sql_concat?(first_arg) or sql_interpolated?(first_arg) do
      {ast, [issue_for(issue_meta, meta[:line], "string concatenation in SQL query") | issues]}
    else
      _ -> {ast, issues}
    end
  end

  # Detect: Ecto.Adapters.SQL.query(Repo, "SQL..." <> var)
  defp traverse(
         {{:., _, [{:__aliases__, _, [:Ecto, :Adapters, :SQL]}, func]}, meta, args} = ast,
         issues,
         issue_meta
       )
       when func in [:query, :query!] and is_list(args) do
    query_arg =
      case args do
        [_, query_arg | _] -> query_arg
        [query_arg] -> query_arg
        _ -> nil
      end

    if query_arg && (sql_concat?(query_arg) or sql_interpolated?(query_arg)) do
      {ast, [issue_for(issue_meta, meta[:line], "string concatenation in SQL query") | issues]}
    else
      {ast, issues}
    end
  end

  # Detect: fragment("SQL..." <> var)
  defp traverse({:fragment, meta, [_ | _] = args} = ast, issues, issue_meta) do
    [first_arg | _] = args

    if sql_concat?(first_arg) or sql_interpolated?(first_arg) do
      {ast, [issue_for(issue_meta, meta[:line], "string concatenation in fragment()") | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  # Check if the AST node is a <> concatenation containing an SQL keyword
  defp sql_concat?({:<>, _, [left, _right]}) do
    string_contains_sql?(left)
  end

  defp sql_concat?(_), do: false

  # Check if the AST node is a string interpolation containing SQL
  defp sql_interpolated?({:<<>>, _, parts}) when is_list(parts) do
    parts
    |> Enum.filter(&is_binary/1)
    |> Enum.any?(&contains_sql_keyword?/1)
  end

  defp sql_interpolated?(_), do: false

  defp string_contains_sql?({:<<>>, _, [str]}) when is_binary(str) do
    contains_sql_keyword?(str)
  end

  defp string_contains_sql?(str) when is_binary(str) do
    contains_sql_keyword?(str)
  end

  # Recurse into nested <> (left-associative)
  defp string_contains_sql?({:<>, _, [left, _right]}) do
    string_contains_sql?(left)
  end

  defp string_contains_sql?(_), do: false

  defp contains_sql_keyword?(str) when is_binary(str) do
    upper = String.upcase(str)
    Enum.any?(@sql_keywords, &String.contains?(upper, &1))
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential SQL injection: #{detail}. Use parameterized queries instead.",
      trigger: "SQL",
      line_no: line_no
    )
  end
end
