defmodule OeditusCredo.Check.Security.UnsafeDeserialization do
  @moduledoc """
  Checks for unsafe deserialization calls over untrusted input.

  MITRE reference: [CWE-502](https://cwe.mitre.org/data/definitions/502.html) —
  Deserialization of Untrusted Data.
  """
  use Credo.Check,
    base_priority: :higher,
    category: :warning,
    explanations: [
      check: """
      Detects potential unsafe deserialization vulnerabilities ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)).

      Deserializing untrusted binary data can execute malicious payloads or
      construct dangerous terms.

      Bad:

          :erlang.binary_to_term(data)
          Plug.Crypto.non_executable_binary_to_term(data)

      Better:

          :erlang.binary_to_term(data, [:safe])
          # Validate and authenticate payload origin before deserialization
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
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

  # :erlang.binary_to_term(term)
  defp traverse({{:., _, [:erlang, :binary_to_term]}, meta, args} = ast, issues, issue_meta)
       when is_list(args) do
    if safe_option_present?(args) do
      {ast, issues}
    else
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           ":erlang.binary_to_term/1 or /2 without [:safe] option"
         )
         | issues
       ]}
    end
  end

  # Plug.Crypto.non_executable_binary_to_term(term)
  defp traverse(
         {{:., _, [{:__aliases__, _, [:Plug, :Crypto]}, :non_executable_binary_to_term]}, meta,
          _args} =
           ast,
         issues,
         issue_meta
       ) do
    {ast,
     [
       issue_for(
         issue_meta,
         meta[:line],
         "Plug.Crypto.non_executable_binary_to_term/1 requires strict trust boundary validation"
       )
       | issues
     ]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp safe_option_present?([_data, opts]) when is_list(opts) do
    :safe in opts
  end

  defp safe_option_present?(_), do: false

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential unsafe deserialization (CWE-502): #{detail}.",
      trigger: "binary_to_term",
      line_no: line_no
    )
  end
end
