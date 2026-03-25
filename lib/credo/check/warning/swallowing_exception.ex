defmodule OeditusCredo.Check.Warning.SwallowingException do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Swallowing exceptions in try/rescue without re-raising or logging hides errors.

      Always log exceptions or re-raise them to maintain observability.

      Bad:

          try do
            risky_operation()
          rescue
            _ -> :error
          end

      Good:

          try do
            risky_operation()
          rescue
            e ->
              Logger.error("Operation failed", error: inspect(e))
              :error
          end
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

  defp traverse({:try, meta, [[do: _do_block, rescue: rescue_clauses]]} = ast, issues, issue_meta)
       when is_list(rescue_clauses) do
    issues =
      if has_silent_rescue?(rescue_clauses) do
        [issue_for(issue_meta, meta[:line]) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  defp has_silent_rescue?(clauses) do
    Enum.any?(clauses, fn
      {:->, _, [_pattern, body]} ->
        not has_logging_or_reraise?(body)
    end)
  end

  defp has_logging_or_reraise?({:__block__, _, statements}) when is_list(statements) do
    Enum.any?(statements, &has_logging_or_reraise?/1)
  end

  # Check for Logger calls
  defp has_logging_or_reraise?({{:., _, [{:__aliases__, _, [:Logger]}, _func]}, _, _}), do: true

  # Check for :erlang.error or raise
  defp has_logging_or_reraise?({{:., _, [:erlang, :error]}, _, _}), do: true
  defp has_logging_or_reraise?({:raise, _, _}), do: true
  defp has_logging_or_reraise?({:reraise, _, _}), do: true

  # Recursively check nested structures
  defp has_logging_or_reraise?({_form, _, args}) when is_list(args) do
    Enum.any?(args, &has_logging_or_reraise?/1)
  end

  defp has_logging_or_reraise?(_), do: false

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Rescue clause swallows exception without logging or re-raising",
      trigger: "rescue",
      line_no: line_no
    )
  end
end
