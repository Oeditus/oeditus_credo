defmodule OeditusCredo.Check.Security.PathTraversal do
  @moduledoc """
  Checks for file path usage patterns that may allow path traversal.

  MITRE reference: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) —
  Improper Limitation of a Pathname to a Restricted Directory
  ("Path Traversal").
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential path traversal vulnerabilities ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)).

      Building file paths directly from user input can allow `../` traversal
      and unauthorized file access.

      Bad:

          File.read!(params["file"])
          File.write!("/tmp/" <> filename, content)

      Good:

          safe = Path.basename(filename)
          File.read!(Path.join("/safe/dir", safe))
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @file_calls ~w[read read! write write! open stream! rm rm!]

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

  defp traverse(
         {{:., _, [{:__aliases__, _, [:File]}, call]}, meta, args} = ast,
         issues,
         issue_meta
       )
       when is_atom(call) and is_list(args) do
    if Atom.to_string(call) in @file_calls and Enum.any?(args, &unsafe_path_argument?/1) do
      {ast,
       [
         issue_for(issue_meta, meta[:line], "File.#{call} called with user-controlled path")
         | issues
       ]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  # ".../" <> filename
  defp unsafe_path_argument?({:<>, _, [_left, right]}) do
    path_variable?(right)
  end

  # params["file"] / params[:path]
  defp unsafe_path_argument?({{:., _, [Access, :get]}, _, [{:params, _, _}, key]}) do
    fileish_key?(key)
  end

  defp unsafe_path_argument?({:params, _, _}), do: true

  # File.read(path_var)
  defp unsafe_path_argument?({name, _, _}) when is_atom(name) do
    path_variable_name?(Atom.to_string(name))
  end

  defp unsafe_path_argument?(_), do: false

  defp path_variable?(ast), do: unsafe_path_argument?(ast)

  defp fileish_key?("file"), do: true
  defp fileish_key?("path"), do: true
  defp fileish_key?(:file), do: true
  defp fileish_key?(:path), do: true
  defp fileish_key?({:file, _, _}), do: true
  defp fileish_key?({:path, _, _}), do: true
  defp fileish_key?(_), do: false

  defp path_variable_name?(name) do
    down = String.downcase(name)

    String.contains?(down, "file") or String.contains?(down, "path") or
      String.contains?(down, "dir")
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential path traversal (CWE-22): #{detail}.",
      trigger: "File",
      line_no: line_no
    )
  end
end
