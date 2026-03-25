defmodule OeditusCredo.Check.Warning.InlineJavascript do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Avoid inline JavaScript event handlers in LiveView templates.

      Use phx-* bindings instead of onclick, onchange, etc.

      Bad:

          <button onclick="alert('hi')">Click</button>

      Good:

          <button phx-click="show_alert">Click</button>
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @inline_js_attrs ["onclick", "onchange", "onkeyup", "onkeydown", "onsubmit", "onload"]

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
      if heex_file?(source_file) do
        source_file
        |> Credo.Code.to_lines()
        |> check_for_inline_js(issue_meta)
      else
        []
      end
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp heex_file?(%SourceFile{filename: filename}) do
    String.ends_with?(filename, [".heex", ".leex"])
  end

  defp check_for_inline_js(lines, issue_meta) do
    lines
    |> Enum.with_index(1)
    |> Enum.flat_map(fn {{_, line}, line_no} ->
      if has_inline_js?(line) do
        [issue_for(issue_meta, line_no)]
      else
        []
      end
    end)
  end

  defp has_inline_js?(line) do
    Enum.any?(@inline_js_attrs, fn attr ->
      String.contains?(line, attr <> "=")
    end)
  end

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Use phx-* bindings instead of inline JavaScript event handlers",
      trigger: "onclick",
      line_no: line_no
    )
  end
end
