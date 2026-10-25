defmodule OeditusCredo.Check.Refactoring.PreferTaggedTuplesForErrors do
  @moduledoc """
  Flags `try...rescue` blocks used for ordinary control flow instead of returning tagged tuples `{:ok, val}` / `{:error, reason}`.

  Only a `try` whose entire purpose is to catch an exception and turn it into a
  value is reported. A `try` with an `after` (or `else`) block is doing resource
  cleanup or result normalisation, which has no tagged-tuple equivalent, and is
  left alone.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :refactoring,
    explanations: [
      check: """
      Using `try...rescue` for ordinary control flow is inefficient on BEAM. Prefer safe functions returning tagged tuples `{:ok, val}` / `{:error, reason}`.

      Bad:

          try do
            String.to_integer(str)
          rescue
            ArgumentError -> :invalid
          end

      Good:

          case Integer.parse(str) do
            {num, ""} -> {:ok, num}
            _ -> :invalid
          end

      A `try` with an `after` block is not reported: it exists to release a
      resource (a file handle, a lock, a counter), which a tagged tuple cannot
      express.
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

  defp traverse({:try, meta, [args]} = ast, issues, issue_meta) do
    if control_flow_try?(args) do
      issue =
        format_issue(
          issue_meta,
          message:
            "Found `try...rescue` block used for control flow. Prefer safe functions returning `{:ok, val}` or `{:error, reason}`.",
          trigger: "try",
          line_no: meta[:line]
        )

      {ast, [issue | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  # A `try` with an `after` block is doing resource cleanup, not control flow,
  # and a `try` with an `else` block is normalising results rather than
  # rescuing. Neither has a tagged-tuple equivalent, so neither is reported.
  #
  # `try`'s AST contains one keyword-list argument, unwrapped by traverse/3.
  defp control_flow_try?([_ | _] = clauses) do
    Keyword.keyword?(clauses) and Keyword.has_key?(clauses, :rescue) and
      not Keyword.has_key?(clauses, :after) and not Keyword.has_key?(clauses, :else)
  end

  defp control_flow_try?(_), do: false
end
