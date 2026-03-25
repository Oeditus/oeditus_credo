defmodule OeditusCredo.Check.Warning.UnmanagedTask do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Use Task.Supervisor for spawning tasks to prevent memory leaks.

      Unmanaged tasks can cause memory leaks if they crash or never complete.

      Bad:

          Task.async(fn -> do_work() end)
          Task.start(fn -> background_job() end)

      Good:

          Task.Supervisor.async_nolink(MyApp.TaskSupervisor, fn -> do_work() end)
          Task.Supervisor.start_child(MyApp.TaskSupervisor, fn -> background_job() end)
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

  defp traverse({{:., meta, [{:__aliases__, _, [:Task]}, func]}, _, _} = ast, issues, issue_meta)
       when func in [:async, :start, :start_link] do
    {ast, [issue_for(issue_meta, meta[:line], func) | issues]}
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  defp issue_for(issue_meta, line_no, func) do
    format_issue(
      issue_meta,
      message:
        "Use Task.Supervisor.#{func}_nolink instead of Task.#{func} to prevent memory leaks",
      trigger: "Task.#{func}",
      line_no: line_no
    )
  end
end
