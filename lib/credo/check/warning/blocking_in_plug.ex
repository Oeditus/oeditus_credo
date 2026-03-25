defmodule OeditusCredo.Check.Warning.BlockingInPlug do
  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Expensive blocking operations in Plug functions slow down request processing.

      Move expensive operations to background jobs or async tasks.

      Bad:

          plug :load_user_data

          def load_user_data(conn, _opts) do
            user = Repo.get!(User, conn.assigns.user_id)
            assign(conn, :user, user)
          end

      Good:

          # Load user data in the controller action instead
          def show(conn, params) do
            user = Repo.get!(User, params["id"])
            render(conn, "show.html", user: user)
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        extra_blocking_modules: "Additional module atoms to treat as blocking (default: [])"
      ]
    ]

  @default_blocking_modules [:Repo, :HTTPoison, :Req, :File]

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

  # Check functions that might be used as plugs (accept conn as first arg)
  defp traverse(
         {:def, meta, [{func_name, _, [{:conn, _, _} | _rest]}, [do: body]]} = ast,
         issues,
         {issue_meta, blocking}
       ) do
    issues =
      if has_blocking_calls?(body, blocking) do
        [issue_for(issue_meta, meta[:line], func_name) | issues]
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

  defp has_blocking_calls?({{:., _, [{:__aliases__, _, aliases}, _func]}, _, _}, blocking) do
    List.last(aliases) in blocking
  end

  defp has_blocking_calls?({_form, _, args}, blocking) when is_list(args) do
    Enum.any?(args, &has_blocking_calls?(&1, blocking))
  end

  defp has_blocking_calls?(_, _blocking), do: false

  defp issue_for(issue_meta, line_no, func_name) do
    format_issue(
      issue_meta,
      message: "Blocking operation in plug function #{func_name} - consider moving to controller",
      trigger: "#{func_name}",
      line_no: line_no
    )
  end
end
