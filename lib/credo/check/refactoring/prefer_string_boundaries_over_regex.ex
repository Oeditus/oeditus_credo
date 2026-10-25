defmodule OeditusCredo.Check.Refactoring.PreferStringBoundariesOverRegex do
  @moduledoc """
  Flags literal regex prefix checks which can use `String.starts_with?/2`.

  Only regexes that are *exactly* a plain literal prefix (`~r/^abc/`) are
  reported. Anything the string functions cannot express is ignored: a `$`
  anchor also matches before a trailing newline, and regex metacharacters,
  alternation, character classes or flags change the meaning.
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

      Only plain literal prefixes are reported. A `$` anchor is not reported:
      unlike `String.ends_with?/2`, it also matches before a trailing newline,
      so the rewrite would not be equivalent. Regexes containing
      metacharacters, alternation, character classes or flags are ignored too.
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{}, false), do: []

  def run(%SourceFile{} = source_file, params) do
    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      issue_meta = IssueMeta.for(source_file, params)
      Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

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

  # Only a bare literal prefix (`~r/^abc/`) is a `String.starts_with?/2` in
  # disguise. A `$`-anchored regex is deliberately excluded: `$` also matches
  # just before a trailing newline, so `Regex.match?(~r/^[0-9a-f]{6}$/, hex)`
  # accepts `"abcdef\n"` while `String.ends_with?/2` would not, and the
  # rewrite would silently change behaviour.
  defp simple_regex_boundary?({:sigil_r, _, [{:<<>>, _, [pattern]}, []]})
       when is_binary(pattern) do
    case String.split_at(pattern, 1) do
      {"^", body} -> plain_literal?(body)
      _ -> false
    end
  end

  defp simple_regex_boundary?(_), do: false

  # A prefix is only a plain literal when it contains no regex metacharacter
  # and no escape sequence, i.e. when `String.starts_with?/2` means the same
  # thing.
  defp plain_literal?(""), do: false

  defp plain_literal?(body),
    do:
      not String.contains?(body, [
        "\\",
        ".",
        "^",
        "$",
        "*",
        "+",
        "?",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "|"
      ])
end
