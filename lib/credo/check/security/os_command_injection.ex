defmodule OeditusCredo.Check.Security.OSCommandInjection do
  @moduledoc """
  Checks for patterns that may allow OS command injection.

  MITRE reference: [CWE-78](https://cwe.mitre.org/data/definitions/78.html) —
  Improper Neutralization of Special Elements used in an OS Command
  ("OS Command Injection").
  """
  use Credo.Check,
    base_priority: :higher,
    category: :warning,
    explanations: [
      check: """
      Detects potential OS command injection vulnerabilities ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)).

      Passing user-controlled input to system command functions can allow
      attackers to execute arbitrary OS commands.

      Bad:

          System.cmd(user_input, [])
          System.shell("ls " <> user_input)
          :os.cmd(String.to_charlist(params["cmd"]))

      Good:

          System.cmd("ls", ["-la", safe_dir])
          # Always use literal command names with System.cmd
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

  # System.shell/1 -- always dangerous (runs through shell)
  defp traverse(
         {{:., _, [{:__aliases__, _, [:System]}, :shell]}, meta, _args} = ast,
         issues,
         issue_meta
       ) do
    {ast,
     [
       issue_for(
         issue_meta,
         meta[:line],
         "System.shell/1 passes input through the OS shell -- use System.cmd/3 instead"
       )
       | issues
     ]}
  end

  # System.cmd/2,3 with non-literal first argument
  defp traverse(
         {{:., _, [{:__aliases__, _, [:System]}, :cmd]}, meta, [command | _rest]} = ast,
         issues,
         issue_meta
       ) do
    if literal_string?(command) do
      {ast, issues}
    else
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "System.cmd/3 with non-literal command -- use a literal string for the executable"
         )
         | issues
       ]}
    end
  end

  # :os.cmd/1
  defp traverse(
         {{:., _, [:os, :cmd]}, meta, _args} = ast,
         issues,
         issue_meta
       ) do
    {ast,
     [
       issue_for(
         issue_meta,
         meta[:line],
         ":os.cmd/1 executes through the OS shell -- use System.cmd/3 with a literal command"
       )
       | issues
     ]}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp literal_string?({:<<>>, _, [str]}) when is_binary(str), do: true
  defp literal_string?(str) when is_binary(str), do: true
  defp literal_string?(_), do: false

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential OS command injection (CWE-78): #{detail}.",
      trigger: "System.cmd",
      line_no: line_no
    )
  end
end
