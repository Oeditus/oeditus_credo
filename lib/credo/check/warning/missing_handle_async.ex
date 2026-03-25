defmodule OeditusCredo.Check.Warning.MissingHandleAsync do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      LiveView handle_event with blocking operations should use start_async and handle_async.

      This prevents blocking the LiveView process and provides better UX.

      Bad:

          def handle_event("load", _params, socket) do
            data = Repo.all(Post)
            {:noreply, assign(socket, :posts, data)}
          end

      Good:

          def handle_event("load", _params, socket) do
            {:noreply, start_async(socket, :posts, fn -> Repo.all(Post) end)}
          end

          def handle_async(:posts, {:ok, posts}, socket) do
            {:noreply, assign(socket, :posts, posts)}
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_blocking_modules: "Additional module atoms to treat as blocking (default: [])"
      ]
    ]

  @default_blocking_modules [:Repo, :HTTPoison, :Req]

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
      extra = Params.get(params, :extra_blocking_modules, __MODULE__)
      blocking = @default_blocking_modules ++ extra

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, blocking}))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false, extra_blocking_modules: []]

  defp traverse(
         {:def, meta, [{:handle_event, _, _}, [do: body]]} = ast,
         issues,
         {issue_meta, blocking}
       ) do
    issues =
      if has_blocking_calls?(body, blocking) and not has_async_call?(body) do
        [issue_for(issue_meta, meta[:line]) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _ctx) do
    {ast, issues}
  end

  defp has_blocking_calls?({:__block__, _, statements}, blocking) when is_list(statements) do
    Enum.any?(statements, &has_blocking_calls?(&1, blocking))
  end

  defp has_blocking_calls?({{:., _, [{:__aliases__, _, aliases}, _]}, _, _}, blocking) do
    List.last(aliases) in blocking
  end

  defp has_blocking_calls?({_form, _, args}, blocking) when is_list(args) do
    Enum.any?(args, &has_blocking_calls?(&1, blocking))
  end

  defp has_blocking_calls?(_, _blocking), do: false

  defp has_async_call?({:__block__, _, statements}) when is_list(statements) do
    Enum.any?(statements, &has_async_call?/1)
  end

  defp has_async_call?({:start_async, _, _}), do: true
  defp has_async_call?({:assign_async, _, _}), do: true

  defp has_async_call?({_form, _, args}) when is_list(args) do
    Enum.any?(args, &has_async_call?/1)
  end

  defp has_async_call?(_), do: false

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Use start_async and handle_async for blocking operations in handle_event",
      trigger: "handle_event",
      line_no: line_no
    )
  end
end
