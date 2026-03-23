defmodule OeditusCredo.Check.Warning.MissingTelemetryInObanWorker do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Oban workers should emit telemetry events for observability.

      Instrumenting Oban workers with telemetry allows monitoring job execution,
      duration, success/failure rates, and helps debug production issues.

      Bad:

          defmodule MyApp.Worker do
            use Oban.Worker

            def perform(%Oban.Job{args: args}) do
              do_work(args)
            end
          end

      Good:

          defmodule MyApp.Worker do
            use Oban.Worker

            def perform(%Oban.Job{args: args}) do
              :telemetry.span([:oban, :job, :execute], %{worker: __MODULE__}, fn ->
                result = do_work(args)
                {result, %{}}
              end)
            end
          end
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

  defp traverse(
         {:defmodule, _, [{:__aliases__, _, _module_name}, [do: module_body]]} = ast,
         issues,
         issue_meta
       ) do
    if uses_oban_worker?(module_body) do
      issues =
        case find_perform_function(module_body) do
          {:ok, perform_meta, perform_body} ->
            if has_telemetry?(perform_body) do
              issues
            else
              [issue_for(issue_meta, perform_meta[:line]) | issues]
            end

          :not_found ->
            issues
        end

      {ast, issues}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  defp uses_oban_worker?(module_body) do
    {_ast, found} =
      Macro.prewalk(module_body, false, fn
        {:use, _, [{:__aliases__, _, [:Oban, :Worker]} | _]} = ast, _acc ->
          {ast, true}

        ast, acc ->
          {ast, acc}
      end)

    found
  end

  defp find_perform_function({:__block__, _, statements}) do
    find_perform_in_statements(statements)
  end

  defp find_perform_function(statement) do
    find_perform_in_statements([statement])
  end

  defp find_perform_in_statements(statements) do
    Enum.find_value(statements, :not_found, fn
      {:def, meta, [{:perform, _, _}, [do: body]]} ->
        {:ok, meta, body}

      {:def, meta, [{:perform, _, _}, body]} when is_list(body) ->
        {:ok, meta, Keyword.get(body, :do)}

      _ ->
        nil
    end)
  end

  defp has_telemetry?(body) do
    {_ast, found} =
      Macro.prewalk(body, false, fn
        {{:., _, [:telemetry, func]}, _, _} = ast, _acc when func in [:execute, :span] ->
          {ast, true}

        {{:., _, [{:__aliases__, _, [:telemetry]}, func]}, _, _} = ast, _acc
        when func in [:execute, :span] ->
          {ast, true}

        ast, acc ->
          {ast, acc}
      end)

    found
  end

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Oban worker perform/1 should emit telemetry events for observability",
      trigger: "perform",
      line_no: line_no
    )
  end
end
