defmodule OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      LiveView mount/3 callbacks should emit telemetry events for observability.

      Instrumenting LiveView mounts helps track which LiveViews are being accessed,
      how long they take to initialize, and can help identify performance bottlenecks.

      Bad:

          defmodule MyAppWeb.DashboardLive do
            use MyAppWeb, :live_view

            def mount(_params, _session, socket) do
              data = load_expensive_data()
              {:ok, assign(socket, data: data)}
            end
          end

      Good:

          defmodule MyAppWeb.DashboardLive do
            use MyAppWeb, :live_view

            def mount(_params, _session, socket) do
              :telemetry.execute(
                [:phoenix, :live_view, :mount],
                %{system_time: System.system_time()},
                %{module: __MODULE__}
              )
              data = load_expensive_data()
              {:ok, assign(socket, data: data)}
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

  defp traverse(
         {:defmodule, _, [{:__aliases__, _, _module_name}, [do: module_body]]} = ast,
         issues,
         issue_meta
       ) do
    if uses_live_view?(module_body) do
      issues =
        case find_mount_function(module_body) do
          {:ok, mount_meta, mount_body} ->
            if has_telemetry?(mount_body) do
              issues
            else
              [issue_for(issue_meta, mount_meta[:line]) | issues]
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

  defp uses_live_view?(module_body) do
    {_ast, found} =
      Macro.prewalk(module_body, false, fn
        {:use, _, [{:__aliases__, _, [:Phoenix, :LiveView]} | _]} = ast, _acc ->
          {ast, true}

        # Also detect `use MyAppWeb, :live_view` pattern
        {:use, _, [{:__aliases__, _, _}, :live_view]} = ast, _acc ->
          {ast, true}

        ast, acc ->
          {ast, acc}
      end)

    found
  end

  defp find_mount_function({:__block__, _, statements}) do
    find_mount_in_statements(statements)
  end

  defp find_mount_function(statement) do
    find_mount_in_statements([statement])
  end

  defp find_mount_in_statements(statements) do
    Enum.find_value(statements, :not_found, fn
      {:def, meta, [{:mount, _, [_, _, _]}, [do: body]]} ->
        {:ok, meta, body}

      {:def, meta, [{:mount, _, [_, _, _]}, body]} when is_list(body) ->
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
      message: "LiveView mount/3 should emit telemetry events for observability",
      trigger: "mount",
      line_no: line_no
    )
  end
end
