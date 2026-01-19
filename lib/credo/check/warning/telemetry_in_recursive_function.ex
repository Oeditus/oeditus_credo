defmodule OeditusCredo.Check.Warning.TelemetryInRecursiveFunction do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Telemetry events should not be emitted inside recursive functions.

      Emitting telemetry in recursive functions causes metric spam and performance
      degradation. Instead, wrap the entire recursive operation with telemetry.

      Bad:

          defp process_list([head | tail]) do
            :telemetry.execute([:app, :process_item], %{})  # Called N times!
            do_work(head)
            process_list(tail)
          end
          defp process_list([]), do: :ok

      Good:

          def process_list(items) do
            :telemetry.span([:app, :process_list], %{count: length(items)}, fn ->
              {do_process_list(items), %{}}
            end)
          end

          defp do_process_list([]), do: :ok
          defp do_process_list([head | tail]) do
            do_work(head)
            do_process_list(tail)
          end
      """,
      params: []
    ]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    source_file
    |> Credo.Code.prewalk(&traverse(&1, &2, issue_meta))
  end

  # Traverse and check functions
  defp traverse({:def, meta, [{name, _, args}, [do: body]]} = ast, issues, issue_meta)
       when is_atom(name) and is_list(args) do
    issues = check_function(name, length(args), body, meta, issues, issue_meta)
    {ast, issues}
  end

  defp traverse({:defp, meta, [{name, _, args}, [do: body]]} = ast, issues, issue_meta)
       when is_atom(name) and is_list(args) do
    issues = check_function(name, length(args), body, meta, issues, issue_meta)
    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp check_function(name, arity, body, meta, issues, issue_meta) do
    if calls_self?(body, name, arity) and has_telemetry?(body) do
      [issue_for(issue_meta, meta[:line], name, arity) | issues]
    else
      issues
    end
  end

  defp calls_self?(nil, _target_name, _target_arity), do: false
  defp calls_self?(body, _target_name, _target_arity) when is_atom(body), do: false
  defp calls_self?(body, _target_name, _target_arity) when is_number(body), do: false
  defp calls_self?(body, _target_name, _target_arity) when is_binary(body), do: false

  defp calls_self?(body, target_name, target_arity) do
    {_ast, found} =
      Macro.prewalk(body, false, fn
        # Direct function call: function_name(args...)
        {^target_name, _, args} = ast, _acc when is_list(args) and length(args) == target_arity ->
          {ast, true}

        ast, acc ->
          {ast, acc}
      end)

    found
  end

  defp has_telemetry?(body) when is_atom(body), do: false
  defp has_telemetry?(body) when is_number(body), do: false
  defp has_telemetry?(body) when is_binary(body), do: false

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

  defp issue_for(issue_meta, line_no, name, arity) do
    format_issue(
      issue_meta,
      message:
        "Telemetry should not be emitted inside recursive function #{name}/#{arity} - wrap the entire operation instead",
      trigger: "#{name}",
      line_no: line_no
    )
  end
end
