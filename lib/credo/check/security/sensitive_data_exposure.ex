defmodule OeditusCredo.Check.Security.SensitiveDataExposure do
  @moduledoc """
  Checks for logging/output patterns that may expose sensitive information.

  MITRE reference: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) --
  Exposure of Sensitive Information to an Unauthorized Actor.
  """

  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential sensitive data exposure in logs or console output ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)).

      Logging sensitive fields (passwords, tokens, secrets, credentials) can leak
      confidential data into log storage and observability systems.

      Bad:

          Logger.info("params: \#{inspect(params)}")
          IO.inspect(user.password_hash)

      Good:

          Logger.info("user login", user_id: user.id)
      """,
      params: [
        exclude_test_files: "Set to false to also check test files (default: true)",
        extra_sensitive_terms:
          "Additional sensitive field name substrings to detect (default: [])"
      ]
    ]

  @default_sensitive_terms ~w[
    password passwd pwd password_hash secret token api_key apikey
    access_token refresh_token credential credentials private_key
    secret_key ssn credit_card cvv cvc pin otp jwt bearer
  ]

  @logging_mods [[:Logger], [:IO]]
  @logging_functions ~w[debug info warning warn error inspect puts]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      extra = Params.get(params, :extra_sensitive_terms, __MODULE__)
      terms = @default_sensitive_terms ++ extra

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, terms}))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: true, extra_sensitive_terms: []]

  # Logger.info(...) / IO.inspect(...)
  defp traverse(
         {{:., _, [{:__aliases__, _, mod_parts}, fun]}, meta, args} = ast,
         issues,
         {issue_meta, terms}
       )
       when is_list(mod_parts) and is_atom(fun) and is_list(args) do
    if logging_call?(mod_parts, fun) and args_contain_sensitive_data?(args, terms) do
      {ast, [issue_for(issue_meta, meta[:line], "#{Enum.join(mod_parts, ".")}.#{fun}") | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _ctx), do: {ast, issues}

  defp logging_call?(mod_parts, fun) do
    mod_parts in @logging_mods and Atom.to_string(fun) in @logging_functions
  end

  defp args_contain_sensitive_data?(args, terms) do
    Enum.any?(args, &contains_sensitive_data?(&1, terms))
  end

  defp contains_sensitive_data?({:inspect, _, inner_args}, terms) when is_list(inner_args) do
    Enum.any?(inner_args, &contains_sensitive_data?(&1, terms))
  end

  defp contains_sensitive_data?({{:., _, [_left, :inspect]}, _, inner_args}, terms)
       when is_list(inner_args) do
    Enum.any?(inner_args, &contains_sensitive_data?(&1, terms))
  end

  defp contains_sensitive_data?({{:., _, [left, attr]}, _, _args}, terms) when is_atom(attr) do
    contains_sensitive_data?(left, terms) or sensitive_name?(Atom.to_string(attr), terms)
  end

  defp contains_sensitive_data?({:., _, [_left, attr]}, terms) when is_atom(attr) do
    sensitive_name?(Atom.to_string(attr), terms)
  end

  defp contains_sensitive_data?({name, _, _args}, terms) when is_atom(name) do
    sensitive_name?(Atom.to_string(name), terms)
  end

  defp contains_sensitive_data?({:<<>>, _, parts}, terms) when is_list(parts) do
    Enum.any?(parts, fn
      part when is_binary(part) -> sensitive_name?(part, terms)
      {_, _, _} = ast -> contains_sensitive_data?(ast, terms)
      _ -> false
    end)
  end

  defp contains_sensitive_data?({_, _, args}, terms) when is_list(args) do
    Enum.any?(args, &contains_sensitive_data?(&1, terms))
  end

  defp contains_sensitive_data?(str, terms) when is_binary(str), do: sensitive_name?(str, terms)
  defp contains_sensitive_data?(_, _terms), do: false

  defp sensitive_name?(name, terms) when is_binary(name) do
    down = String.downcase(name)
    Enum.any?(terms, &String.contains?(down, &1))
  end

  defp test_file?(filename) do
    String.ends_with?(filename, "_test.exs") or String.contains?(filename, "/test/")
  end

  defp issue_for(issue_meta, line_no, trigger) do
    format_issue(
      issue_meta,
      message:
        "Potential sensitive data exposure (CWE-200): logging/output call references sensitive fields.",
      trigger: trigger,
      line_no: line_no
    )
  end
end
