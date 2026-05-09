defmodule OeditusCredo.Check.Readability.UnnecessaryInterpolatingSigil do
  @moduledoc """
  Checks for interpolating sigils (`~s`, `~c`, `~w`) that contain no
  interpolation and could be replaced with their non-interpolating uppercase
  counterparts (`~S`, `~C`, `~W`).

  Using the uppercase variant makes the intent explicit: the content is static
  and will never contain dynamic expressions. It also avoids accidental
  interpolation if a `#{}` sequence is later added to what was meant to be a
  literal string.

  This check is particularly relevant in combination with
  `OeditusCredo.Check.Security.XSSVulnerability` (CWE-79): when `raw/1` or
  `Phoenix.HTML.raw/1` receives a sigil argument, using the uppercase variant
  makes it immediately obvious to both the reader and the static analyser
  that the content is developer-controlled.
  """
  use Credo.Check,
    base_priority: :low,
    category: :readability,
    explanations: [
      check: """
      Detects lowercase (interpolating) sigils that contain no interpolation.

      When a sigil body has no `\#{}` expressions, the lowercase variant
      (`~s`, `~c`, `~w`) behaves identically to its uppercase
      counterpart (`~S`, `~C`, `~W`), but misleads the reader into
      expecting dynamic content.

      Bad:

          html = ~s"<div class=\\"box\\">static</div>"
          words = ~w"foo bar baz"

      Good:

          html = ~S"<div class=\\"box\\">static</div>"
          words = ~W"foo bar baz"

      This is especially important inside `raw/1` and `Phoenix.HTML.raw/1`,
      where `~S` makes it clear the content is a compile-time literal and
      not user input (see `OeditusCredo.Check.Security.XSSVulnerability`).
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @interpolating_sigils %{
    sigil_s: "~S",
    sigil_c: "~C",
    sigil_w: "~W"
  }

  @doc false
  @impl true
  def run(%SourceFile{}, false), do: []

  def run(%SourceFile{} = source_file, params) do
    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      issue_meta = IssueMeta.for(source_file, params)

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  for {sigil, uppercase} <- @interpolating_sigils do
    defp traverse(
           {unquote(sigil), meta, [{:<<>>, _, parts}, _modifiers]} = ast,
           issues,
           issue_meta
         ) do
      if Enum.all?(parts, &is_binary/1) do
        {ast,
         [
           issue_for(
             issue_meta,
             meta[:line],
             "~#{unquote(sigil) |> Atom.to_string() |> String.at(-1)}",
             unquote(uppercase)
           )
           | issues
         ]}
      else
        {ast, issues}
      end
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp issue_for(issue_meta, line_no, from, to) do
    format_issue(
      issue_meta,
      message: "#{from} sigil contains no interpolation -- use #{to} to signal static content.",
      trigger: from,
      line_no: line_no
    )
  end
end
