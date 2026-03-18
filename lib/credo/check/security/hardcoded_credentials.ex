defmodule OeditusCredo.Check.Security.HardcodedCredentials do
  @moduledoc """
  Checks for hard-coded secrets and credential-like values in source code.

  MITRE reference: [CWE-798](https://cwe.mitre.org/data/definitions/798.html) —
  Use of Hard-coded Credentials.
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects hardcoded credentials and sensitive endpoints ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)).

      Hardcoded secrets in source code are vulnerable to leaks and accidental
      exposure through repositories, logs, and error reports.

      This check extends previous hardcoded value detection by adding explicit
      credential-name-based checks (password, secret, token, api_key, etc.).

      Bad:

          @api_key "sk_live_..."
          password = "super-secret"
          token = "abc123"

      Better:

          api_key = System.fetch_env!("API_KEY")
          password = Application.fetch_env!(:my_app, :password)
      """,
      params: [
        exclude_test_files: "Set to false to check test files"
      ]
    ]

  @url_pattern ~r/https?:\/\/[^\s"']+/
  @ip_pattern ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/

  @credential_terms ~w[
    password passwd pwd secret token api_key apikey access_token refresh_token
    private_key secret_key credential credentials auth_key
  ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)
    exclude_test = Params.get(params, :exclude_test_files, __MODULE__)

    if exclude_test and test_file?(source_file.filename) do
      []
    else
      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults do
    [exclude_test_files: true]
  end

  # Detect literal strings for URL/IP patterns
  defp traverse({:<<>>, meta, [string]} = ast, issues, issue_meta) when is_binary(string) do
    issues =
      cond do
        Regex.match?(@url_pattern, string) and not localhost?(string) ->
          [issue_for(issue_meta, meta[:line], "hardcoded URL") | issues]

        Regex.match?(@ip_pattern, string) and not local_ip?(string) ->
          [issue_for(issue_meta, meta[:line], "hardcoded IP address") | issues]

        true ->
          issues
      end

    {ast, issues}
  end

  # Detect assignment: password = "..."
  defp traverse({:=, meta, [left, right]} = ast, issues, issue_meta) do
    if credential_name?(left) and literal_string?(right) do
      {ast, [issue_for(issue_meta, meta[:line], "hardcoded credential value") | issues]}
    else
      {ast, issues}
    end
  end

  # Detect module attributes: @api_key "..."
  defp traverse({:@, meta, [{attr_name, _, args}]} = ast, issues, issue_meta)
       when is_atom(attr_name) and is_list(args) do
    if credential_name?(attr_name) and Enum.any?(args, &literal_string?/1) do
      {ast,
       [issue_for(issue_meta, meta[:line], "hardcoded credential module attribute") | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp credential_name?({name, _, _}) when is_atom(name), do: credential_name?(name)

  defp credential_name?(name) when is_atom(name) do
    down = name |> Atom.to_string() |> String.downcase()
    Enum.any?(@credential_terms, &String.contains?(down, &1))
  end

  defp credential_name?(_), do: false

  defp literal_string?({:<<>>, _, [str]}) when is_binary(str), do: true
  defp literal_string?(str) when is_binary(str), do: true
  defp literal_string?(_), do: false

  defp test_file?(filename) do
    String.ends_with?(filename, "_test.exs") or String.contains?(filename, "/test/")
  end

  defp localhost?(url) do
    String.contains?(url, "localhost") or String.contains?(url, "127.0.0.1")
  end

  defp local_ip?(ip) do
    String.starts_with?(ip, "127.") or String.starts_with?(ip, "192.168.") or
      String.starts_with?(ip, "10.") or ip == "0.0.0.0"
  end

  defp issue_for(issue_meta, line_no, type) do
    format_issue(
      issue_meta,
      message:
        "Potential hardcoded credential (CWE-798): #{type}. Use runtime configuration instead.",
      trigger: type,
      line_no: line_no || 1
    )
  end
end
