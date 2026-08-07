defmodule OeditusCredo.Check.Refactoring.PreferStringBoundariesOverRegex do
  @moduledoc """
  Flags `Regex.match?` calls used for basic prefix/suffix checks which should use `String.starts_with?/2` or `String.ends_with?/2`.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Calling `Regex.match?` for simple prefix/suffix string matching adds unnecessary regex engine compilation overhead.

      Bad:

          Regex.match?(~r/^https:/, url)

      Good:

          String.starts_with?(url, "https:")
      """
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params \\ []) do
    issue_meta = IssueMeta.for(source_file, params)
    Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
  end

  defp traverse(
         {{:., meta, [{:__aliases__, _, [:Regex]}, :match?]}, _, [regex, _str]} = ast,
         issues,
         issue_meta
       ) do
    if simple_regex_boundary?(regex) do
      issue =
        format_issue(
          issue_meta,
          message:
            "`Regex.match?` used for prefix/suffix check. Prefer `String.starts_with?/2` or `String.ends_with?/2`.",
          trigger: "Regex.match?",
          line_no: meta[:line]
        )

      {ast, [issue | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp simple_regex_boundary?({:sigil_r, _, [{:<<>>, _, [pattern]}, _opts]})
       when is_binary(pattern) do
    String.starts_with?(pattern, "^") or String.ends_with?(pattern, "$")
  end

  defp simple_regex_boundary?(_), do: false
end
