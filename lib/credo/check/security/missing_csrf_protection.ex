defmodule OeditusCredo.Check.Security.MissingCSRFProtection do
  @moduledoc """
  Checks for missing or bypassed CSRF protection in web/API flows.

  MITRE reference: [CWE-352](https://cwe.mitre.org/data/definitions/352.html) —
  Cross-Site Request Forgery (CSRF).
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential missing or disabled CSRF protection ([CWE-352](https://cwe.mitre.org/data/definitions/352.html)).

      This check covers both:
      1) Web/API pipelines handling state-changing routes without CSRF protection.
      2) Explicit CSRF removal or bypass patterns.

      Bad:

          pipeline :api do
            plug :accepts, ["json"]
          end

          Plug.Conn.delete_csrf_token(conn)

      Good:

          pipeline :browser do
            plug :protect_from_forgery
          end
      """,
      params: []
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    source_file
    |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
  end

  # pipeline :api do ... end
  defp traverse({:pipeline, meta, [pipe_name, [do: body]]} = ast, issues, issue_meta) do
    statements = block_to_statements(body)

    issues =
      if api_pipeline?(pipe_name) and not has_protect_from_forgery?(statements) do
        [
          issue_for(
            issue_meta,
            meta[:line],
            "API pipeline without :protect_from_forgery (or equivalent CSRF protection)"
          )
          | issues
        ]
      else
        issues
      end

    {ast, issues}
  end

  # post/put/patch/delete route declarations outside protected pipeline context
  defp traverse({method, meta, _args} = ast, issues, issue_meta)
       when method in [:post, :put, :patch, :delete] do
    {ast,
     [
       issue_for(
         issue_meta,
         meta[:line],
         "state-changing route `#{method}` detected; ensure CSRF protection is enabled"
       )
       | issues
     ]}
  end

  # Plug.Conn.delete_csrf_token(conn)
  defp traverse(
         {{:., _, [{:__aliases__, _, [:Plug, :Conn]}, :delete_csrf_token]}, meta, _args} = ast,
         issues,
         issue_meta
       ) do
    {ast, [issue_for(issue_meta, meta[:line], "explicit CSRF token deletion detected") | issues]}
  end

  # put_private(conn, :plug_skip_csrf_protection, true)-style bypass hints
  defp traverse({name, meta, args} = ast, issues, issue_meta)
       when name in [:put_private, :assign] and is_list(args) do
    issues =
      if Enum.any?(args, &csrf_bypass_key?/1) do
        [issue_for(issue_meta, meta[:line], "potential CSRF bypass flag assignment") | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp block_to_statements({:__block__, _, statements}) when is_list(statements), do: statements
  defp block_to_statements(statement), do: [statement]

  defp api_pipeline?(name) when is_atom(name), do: name == :api
  defp api_pipeline?(_), do: false

  defp has_protect_from_forgery?(statements) do
    Enum.any?(statements, fn
      {:plug, _, [plug_name | _rest]} ->
        plug_name
        |> plug_name_to_string()
        |> String.downcase()
        |> String.contains?("protect_from_forgery")

      _ ->
        false
    end)
  end

  defp plug_name_to_string({:__aliases__, _, parts}) when is_list(parts),
    do: Enum.join(parts, ".")

  defp plug_name_to_string(name) when is_atom(name), do: Atom.to_string(name)
  defp plug_name_to_string(_), do: ""

  defp csrf_bypass_key?(:plug_skip_csrf_protection), do: true
  defp csrf_bypass_key?("plug_skip_csrf_protection"), do: true
  defp csrf_bypass_key?(:csrf_disabled), do: true
  defp csrf_bypass_key?("csrf_disabled"), do: true
  defp csrf_bypass_key?(_), do: false

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential CSRF protection issue (CWE-352): #{detail}.",
      trigger: "csrf",
      line_no: line_no
    )
  end
end
