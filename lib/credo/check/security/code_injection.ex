defmodule OeditusCredo.Check.Security.CodeInjection do
  @moduledoc """
  Checks for dynamic evaluation patterns that may lead to code injection.

  MITRE reference: [CWE-94](https://cwe.mitre.org/data/definitions/94.html) —
  Improper Control of Generation of Code ("Code Injection").
  """
  use Credo.Check,
    base_priority: :higher,
    category: :warning,
    explanations: [
      check: """
      Detects potential code injection vulnerabilities ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)).

      Functions like `Code.eval_string/1`, `Code.eval_quoted/1`, and
      `Code.eval_file/1` can execute arbitrary code and should be avoided,
      especially with user-controlled input.

      Bad:

          Code.eval_string(user_input)
          Code.eval_quoted(ast_from_user)
          Code.eval_file(params["file"])

      Good:

          # Use pattern matching, parsers, or safe DSLs instead of eval
          Jason.decode!(json_input)
      """,
      params: []
    ]

  @dangerous_functions [:eval_string, :eval_quoted, :eval_file]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    source_file
    |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
  end

  # Code.eval_string/1,2,3  Code.eval_quoted/1,2,3  Code.eval_file/1,2
  defp traverse(
         {{:., _, [{:__aliases__, _, [:Code]}, func]}, meta, _args} = ast,
         issues,
         issue_meta
       )
       when func in @dangerous_functions do
    {ast,
     [
       issue_for(issue_meta, meta[:line], "Code.#{func}")
       | issues
     ]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp issue_for(issue_meta, line_no, func_name) do
    format_issue(
      issue_meta,
      message:
        "Potential code injection (CWE-94): #{func_name} can execute arbitrary code. " <>
          "Avoid eval with untrusted input.",
      trigger: func_name,
      line_no: line_no
    )
  end
end
