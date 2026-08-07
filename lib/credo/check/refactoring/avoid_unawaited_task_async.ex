defmodule OeditusCredo.Check.Refactoring.AvoidUnawaitedTaskAsync do
  @moduledoc """
  Flags standalone `Task.async` calls whose return task struct is ignored (fire-and-forget background jobs), which should use `Task.Supervisor.start_child/2` or `Task.start/1`.
  """

  use Credo.Check,
    base_priority: :high,
    category: :refactoring,
    explanations: [
      check: """
      `Task.async` links the calling process to the task and expects `Task.await`. Ignoring the task handle can cause unhandled exit signals to crash the calling process if the task fails. Use `Task.Supervisor.start_child/2` or `Task.start/1` for fire-and-forget tasks.

      Bad:

          Task.async(fn -> send_email(user) end)

      Good:

          Task.Supervisor.start_child(MyApp.TaskSupervisor, fn -> send_email(user) end)
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

  # Statement in block: Task.async(...)
  defp traverse({:__block__, _meta, statements} = ast, issues, issue_meta)
       when is_list(statements) do
    new_issues =
      Enum.flat_map(statements, fn
        {{:., meta, [{:__aliases__, _, [:Task]}, :async]}, _, _} ->
          [
            format_issue(
              issue_meta,
              message:
                "Un-awaited `Task.async` used for background task. Use `Task.Supervisor.start_child/2` or `Task.start/1` for fire-and-forget tasks.",
              trigger: "Task.async",
              line_no: meta[:line]
            )
          ]

        _ ->
          []
      end)

    {ast, new_issues ++ issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}
end
