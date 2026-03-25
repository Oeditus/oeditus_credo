defmodule OeditusCredo.Check.Warning.MissingErrorHandling do
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Pattern matching on `{:ok, result}` without handling the error case can lead to crashes.

      When a function returns `{:ok, value} | {:error, reason}`, pattern matching directly
      with `{:ok, result} = function()` will raise a `MatchError` if an error tuple is returned.

      Bad:

          {:ok, user} = Accounts.get_user(id)

      Good:

          case Accounts.get_user(id) do
            {:ok, user} -> user
            {:error, reason} -> handle_error(reason)
          end

      Or use `with`:

          with {:ok, user} <- Accounts.get_user(id) do
            user
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

  defp traverse({:=, meta, [left, _right]} = ast, issues, issue_meta) do
    issues =
      if ok_tuple_pattern?(left) do
        [issue_for(issue_meta, meta[:line]) | issues]
      else
        issues
      end

    {ast, issues}
  end

  defp traverse(ast, issues, _issue_meta) do
    {ast, issues}
  end

  # Match any tuple with :ok as first element
  # 2-element tuple represented as {:ok, meta, [value]}
  defp ok_tuple_pattern?({:ok, _, [_value]}), do: true
  # Or as just {:ok, value}
  defp ok_tuple_pattern?({:ok, _}), do: true
  # 3+ element tuples represented as {:{}, meta, [:ok | rest]}
  defp ok_tuple_pattern?({:{}, _, [:ok | _]}), do: true
  defp ok_tuple_pattern?(_), do: false

  defp issue_for(issue_meta, line_no) do
    format_issue(
      issue_meta,
      message: "Pattern match on :ok tuple without error handling can cause MatchError",
      trigger: "{:ok, _}",
      line_no: line_no
    )
  end
end
