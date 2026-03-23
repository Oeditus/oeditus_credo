defmodule OeditusCredo.Check.Warning.SyncOverAsync do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Blocking operations in LiveView event handlers or GenServer callbacks cause performance issues.

      Offload expensive operations to async tasks or background jobs.

      Bad:

          def handle_event("save", params, socket) do
            user = Repo.get!(User, params["id"])
            {:noreply, assign(socket, :user, user)}
          end

      Good:

          def handle_event("save", params, socket) do
            socket = assign_async(socket, :user, fn ->
              {:ok, %{user: Repo.get!(User, params["id"])}}
            end)
            {:noreply, socket}
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_blocking_modules: "Additional module atoms to treat as blocking (default: [])",
        callback_functions:
          "Callback function names to check (default: [:handle_event, :handle_call, :handle_info, :handle_cast, :handle_continue])"
      ]
    ]

  @default_blocking_modules [:Repo, :HTTPoison, :Req, :File, :System]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      extra_blocking = Params.get(params, :extra_blocking_modules, __MODULE__)
      blocking = @default_blocking_modules ++ extra_blocking
      callbacks = Params.get(params, :callback_functions, __MODULE__)

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, blocking, callbacks}))
    end
  end

  @doc false
  @impl true
  def param_defaults do
    [
      exclude_test_files: false,
      extra_blocking_modules: [],
      callback_functions: [
        :handle_event,
        :handle_call,
        :handle_info,
        :handle_cast,
        :handle_continue
      ]
    ]
  end

  # Match callback functions (runtime list, so check in body instead of guard)
  defp traverse(
         {:def, meta, [{func_name, _, _args} = _head, [do: body]]} = ast,
         issues,
         {issue_meta, blocking, callbacks}
       ) do
    if func_name in callbacks do
      issues =
        if has_blocking_calls?(body, blocking) do
          [issue_for(issue_meta, meta[:line], func_name) | issues]
        else
          issues
        end

      {ast, issues}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _ctx) do
    {ast, issues}
  end

  defp has_blocking_calls?({:__block__, _, statements}, blocking) when is_list(statements) do
    Enum.any?(statements, &has_blocking_calls?(&1, blocking))
  end

  # Check for blocking module calls
  defp has_blocking_calls?({{:., _, [{:__aliases__, _, aliases}, _func]}, _, _}, blocking) do
    List.last(aliases) in blocking
  end

  # Recursively check nested structures
  defp has_blocking_calls?({_form, _, args}, blocking) when is_list(args) do
    Enum.any?(args, &has_blocking_calls?(&1, blocking))
  end

  defp has_blocking_calls?(_, _blocking), do: false

  defp issue_for(issue_meta, line_no, func_name) do
    format_issue(
      issue_meta,
      message: "Blocking operation in #{func_name} - consider using async tasks",
      trigger: "#{func_name}",
      line_no: line_no
    )
  end
end
