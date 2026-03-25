defmodule OeditusCredo.Check.Security.TOCTOU do
  @moduledoc """
  Checks for file access flows vulnerable to TOCTOU race conditions.

  MITRE reference: [CWE-367](https://cwe.mitre.org/data/definitions/367.html) —
  Time-of-check Time-of-use (TOCTOU) Race Condition.
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects Time-of-Check-Time-of-Use race conditions ([CWE-367](https://cwe.mitre.org/data/definitions/367.html)).

      Checking a file's existence with `File.exists?/1` and then operating on it
      introduces a race window where the file may be modified or deleted.

      Bad:

          if File.exists?(path) do
            {:ok, data} = File.read(path)
          end

      Good:

          case File.read(path) do
            {:ok, data} -> process(data)
            {:error, :enoent} -> handle_missing()
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @check_functions ~w[exists? stat stat!]
  @use_functions ~w[read read! write write! rm rm! open stream! cp cp! rename rename!]

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

  # Match: if File.exists?(path) do ... File.read(path) ... end
  defp traverse({:if, meta, [condition, blocks]} = ast, issues, issue_meta)
       when is_list(blocks) do
    body = Keyword.get(blocks, :do)
    check_var = file_check_variable(condition)

    if check_var && file_use_on_variable?(body, check_var) do
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "File.exists?/stat check followed by File operation in if-body"
         )
         | issues
       ]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  # Extract the variable name from File.exists?(var) in condition
  defp file_check_variable({{:., _, [{:__aliases__, _, [:File]}, check_func]}, _, [arg]})
       when is_atom(check_func) do
    if Atom.to_string(check_func) in @check_functions, do: extract_var_name(arg), else: nil
  end

  defp file_check_variable({:not, _, [inner]}), do: file_check_variable(inner)
  defp file_check_variable({:!, _, [inner]}), do: file_check_variable(inner)
  defp file_check_variable(_), do: nil

  defp extract_var_name({name, _, ctx}) when is_atom(name) and is_atom(ctx), do: name
  defp extract_var_name(_), do: nil

  # Does the body contain a File.read/write/etc. call on the same variable?
  defp file_use_on_variable?(body, var_name) do
    walk_ast(body, fn
      {{:., _, [{:__aliases__, _, [:File]}, use_func]}, _, [arg | _]} when is_atom(use_func) ->
        Atom.to_string(use_func) in @use_functions and extract_var_name(arg) == var_name

      _ ->
        false
    end)
  end

  defp walk_ast(node, pred) do
    if pred.(node) do
      true
    else
      case node do
        {_, _, args} when is_list(args) -> Enum.any?(args, &walk_ast(&1, pred))
        list when is_list(list) -> Enum.any?(list, &walk_ast(&1, pred))
        {left, right} -> walk_ast(left, pred) or walk_ast(right, pred)
        _ -> false
      end
    end
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message:
        "Potential TOCTOU race condition (CWE-367): #{detail}. Use atomic file operations or try/rescue.",
      trigger: "File.exists?",
      line_no: line_no
    )
  end
end
