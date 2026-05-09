defmodule OeditusCredo.Check.Warning.UnsafeMapAccess do
  @moduledoc """
  Detects bracket access (`map[:key]`) on maps with atom keys where
  dot access (`map.key`) would be safer.

  Bracket access silently returns `nil` on missing keys, letting
  errors propagate far from the source. Dot access raises a
  `KeyError` immediately and enables Elixir 1.20+ type-aware
  key propagation.

  Requires the `typle` package and Elixir >= 1.20; silently
  skipped otherwise.
  """

  use Credo.Check,
    base_priority: :normal,
    category: :warning,
    explanations: [
      check: """
      Using bracket access (`map[:key]`) on a map with atom keys silently
      returns `nil` when the key is missing. The `nil` then propagates and
      surfaces as a confusing error far from the source.

      Prefer dot access, which raises a `KeyError` on missing keys and allows
      Elixir 1.20's type system to propagate key requirements across call sites.

      Bad:

          config = %{timeout: 5000}
          config[:timeout]

      Good:

          config = %{timeout: 5000}
          config.timeout

      This check requires the `typle` package and Elixir >= 1.20.
      When either is unavailable, the check is silently skipped.
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @min_elixir_version "1.20.0-rc.0"

  @doc false
  @impl true
  def run(%SourceFile{}, false), do: []

  def run(%SourceFile{} = source_file, params) do
    with true <- typle_available?(),
         true <- elixir_sufficient?(),
         false <-
           Params.get(params, :exclude_test_files, __MODULE__) and
             test_file?(source_file.filename) do
      run_with_typle(source_file, params)
    else
      _ -> []
    end
  end

  @doc false
  @impl true
  def param_defaults, do: [exclude_test_files: false]

  defp run_with_typle(source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    # credo:disable-for-lines:7
    case apply(Typle.Inference, :infer_file, [source_file.filename]) do
      {:ok, %{types: %{} = types}} when map_size(types) > 0 ->
        Credo.Code.prewalk(source_file, &traverse(&1, &2, issue_meta, types))

      _ ->
        []
    end
  end

  # Match bracket access: expr[:atom_key]
  # AST: {{:., [from_brackets: true, ...], [Access, :get]}, _, [receiver, key]}
  defp traverse(
         {{:., meta, [Access, :get]}, call_meta, [receiver, key]} = ast,
         issues,
         issue_meta,
         type_map
       )
       when is_atom(key) do
    if Keyword.get(meta, :from_brackets, false) or
         Keyword.get(call_meta, :from_brackets, false) do
      receiver_type = receiver_type(receiver, type_map)

      if map_type?(receiver_type) do
        {ast, [issue_for(issue_meta, meta[:line], key) | issues]}
      else
        {ast, issues}
      end
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta, _type_map) do
    {ast, issues}
  end

  defp receiver_type({_form, meta, _args}, type_map) when is_list(meta) do
    line = Keyword.get(meta, :line, 0)
    col = Keyword.get(meta, :column, 0)
    Map.get(type_map, {line, col})
  end

  defp receiver_type(_, _type_map), do: nil

  defp map_type?(nil), do: false
  defp map_type?(%{kind: :map}), do: true

  defp map_type?(%{kind: :union, params: members}) when is_list(members) do
    Enum.any?(members, &map_type?/1)
  end

  defp map_type?(_), do: false

  defp typle_available? do
    Code.ensure_loaded?(Typle) and Code.ensure_loaded?(Typle.Inference)
  end

  defp elixir_sufficient? do
    Version.match?(System.version(), ">= #{@min_elixir_version}")
  end

  defp issue_for(issue_meta, line_no, key) do
    format_issue(
      issue_meta,
      message:
        "Use dot access (`map.#{key}`) instead of bracket access (`map[:#{key}]`) on maps " <>
          "to handle missing keys explicitly.",
      trigger: "Access.get",
      line_no: line_no
    )
  end
end
