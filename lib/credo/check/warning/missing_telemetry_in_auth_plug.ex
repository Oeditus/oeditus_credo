defmodule OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Authentication and authorization plugs should emit telemetry events for observability.

      Instrumenting auth plugs helps track login attempts, success/failure rates,
      authentication latency, and can help identify security issues.

      Bad:

          defmodule MyAppWeb.Plugs.Authenticate do
            import Plug.Conn

            def call(conn, _opts) do
              case verify_token(conn) do
                {:ok, user} -> assign(conn, :current_user, user)
                {:error, _} -> halt(conn)
              end
            end
          end

      Good:

          defmodule MyAppWeb.Plugs.Authenticate do
            import Plug.Conn

            def call(conn, _opts) do
              start_time = System.monotonic_time()
              result = verify_token(conn)
              
              duration = System.monotonic_time() - start_time
              :telemetry.execute(
                [:auth, :verify_token],
                %{duration: duration},
                %{result: elem(result, 0)}
              )
              
              case result do
                {:ok, user} -> assign(conn, :current_user, user)
                {:error, _} -> halt(conn)
              end
            end
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_auth_plug_names: "Additional auth plug name substrings to detect (default: [])"
      ]
    ]

  @default_auth_plug_names ["auth", "authenticate", "authorize", "require_user", "ensure_auth"]

  @doc false
  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      extra = Params.get(params, :extra_auth_plug_names, __MODULE__)
      plug_names = @default_auth_plug_names ++ extra

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, plug_names}))
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false, extra_auth_plug_names: []]

  defp traverse(
         {:defmodule, _, [{:__aliases__, _, module_name}, [do: module_body]]} = ast,
         issues,
         {issue_meta, plug_names}
       ) do
    if auth_plug_module?(module_name, plug_names) do
      issues =
        case find_call_function(module_body) do
          {:ok, call_meta, call_body} ->
            if has_telemetry?(call_body) do
              issues
            else
              [issue_for(issue_meta, call_meta[:line]) | issues]
            end

          :not_found ->
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

  # Detect auth-related module names
  defp auth_plug_module?(module_name, plug_names) when is_list(module_name) do
    module_str = module_name |> Enum.join(".") |> String.downcase()
    Enum.any?(plug_names, &String.contains?(module_str, &1))
  end

  defp auth_plug_module?(_, _plug_names), do: false

  defp find_call_function({:__block__, _, statements}) do
    find_call_in_statements(statements)
  end

  defp find_call_function(statement) do
    find_call_in_statements([statement])
  end

  defp find_call_in_statements(statements) do
    Enum.find_value(statements, :not_found, fn
      {:def, meta, [{:call, _, [_, _]}, [do: body]]} ->
        {:ok, meta, body}

      {:def, meta, [{:call, _, [_, _]}, body]} when is_list(body) ->
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

  defp test_file?(filename) do
    String.ends_with?(filename, "_test.exs") or String.contains?(filename, "/test/")
  end

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Authentication/authorization plug should emit telemetry events for observability",
      trigger: "call",
      line_no: line_no
    )
  end
end
