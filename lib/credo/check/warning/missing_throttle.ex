defmodule OeditusCredo.Check.Warning.MissingThrottle do
  use Credo.Check,
    base_priority: :low,
    category: :warning,
    explanations: [
      check: """
      Form inputs with phx-change, phx-keyup, or phx-input should include phx-debounce or phx-throttle.

      This prevents excessive server events and improves performance.

      Bad:

          <input type="text" phx-change="search" />

      Good:

          <input type="text" phx-change="search" phx-debounce="300" />
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @trigger_events ["phx-change", "phx-keyup", "phx-input"]
  @throttle_attrs ["phx-debounce", "phx-throttle"]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      if heex_file?(source_file) do
        source_file
        |> Credo.Code.to_lines()
        |> check_for_missing_throttle(issue_meta)
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

  defp check_for_missing_throttle(lines, issue_meta) do
    lines
    |> Enum.with_index(1)
    |> Enum.flat_map(fn {{_, line}, line_no} ->
      if has_trigger_event?(line) and not has_throttle?(line) do
        [issue_for(issue_meta, line_no)]
      else
        []
      end
    end)
  end

  defp has_trigger_event?(line) do
    Enum.any?(@trigger_events, &String.contains?(line, &1))
  end

  defp has_throttle?(line) do
    Enum.any?(@throttle_attrs, &String.contains?(line, &1))
  end

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Add phx-debounce or phx-throttle to prevent excessive server events",
      trigger: "phx-change",
      line_no: line_no
    )
  end
end
