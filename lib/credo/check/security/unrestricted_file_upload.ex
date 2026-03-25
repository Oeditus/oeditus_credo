defmodule OeditusCredo.Check.Security.UnrestrictedFileUpload do
  @moduledoc """
  Checks for file upload handlers that may accept dangerous file types.

  MITRE reference: [CWE-434](https://cwe.mitre.org/data/definitions/434.html) —
  Unrestricted Upload of File with Dangerous Type.
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential unrestricted file upload ([CWE-434](https://cwe.mitre.org/data/definitions/434.html)).

      Upload handlers that write files to disk without validating content_type,
      file extension, or file size can allow upload of dangerous files.

      Bad:

          def upload(conn, %{"file" => %Plug.Upload{} = upload}) do
            File.cp!(upload.path, "/uploads/\#{upload.filename}")
          end

      Good:

          @allowed_extensions ~w[.jpg .jpeg .png .gif]

          def upload(conn, %{"file" => %Plug.Upload{} = upload}) do
            ext = Path.extname(upload.filename) |> String.downcase()
            if ext in @allowed_extensions, do: ...
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @file_write_calls ~w[cp cp! copy copy! write write! rename rename!]
  @validation_indicators ~w[extname content_type extension mime_type allowed validate file_type]

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

  defp traverse({:def, meta, [{func_name, _, args}, [do: body]]} = ast, issues, issue_meta)
       when is_atom(func_name) do
    if has_upload_param?(args) do
      statements = block_to_statements(body)

      if has_file_write?(statements) and not has_upload_validation?(statements) do
        {ast,
         [
           issue_for(
             issue_meta,
             meta[:line],
             "#{func_name} writes uploaded file without content-type or extension validation"
           )
           | issues
         ]}
      else
        {ast, issues}
      end
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp block_to_statements({:__block__, _, statements}) when is_list(statements), do: statements
  defp block_to_statements(statement), do: [statement]

  defp has_upload_param?(args) when is_list(args) do
    Enum.any?(args, fn
      {:%{}, _, pairs} when is_list(pairs) ->
        Enum.any?(pairs, fn
          {_key, {:%, _, [{:__aliases__, _, parts}, _]}} ->
            Enum.join(parts, ".") |> String.contains?("Upload")

          _ ->
            false
        end)

      _ ->
        false
    end)
  end

  defp has_upload_param?(_), do: false

  defp has_file_write?(statements) do
    Enum.any?(statements, &contains_file_write?/1)
  end

  defp contains_file_write?({{:., _, [{:__aliases__, _, [:File]}, call]}, _, _args})
       when is_atom(call) do
    Atom.to_string(call) in @file_write_calls
  end

  defp contains_file_write?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_file_write?/1)
  end

  defp contains_file_write?(_), do: false

  defp has_upload_validation?(statements) do
    Enum.any?(statements, &contains_validation?/1)
  end

  defp contains_validation?({name, _, _args}) when is_atom(name) do
    validation_name?(Atom.to_string(name))
  end

  defp contains_validation?({{:., _, [{:__aliases__, _, [:Path]}, :extname]}, _, _args}) do
    true
  end

  defp contains_validation?({{:., _, [_left, attr]}, _, _args}) when is_atom(attr) do
    validation_name?(Atom.to_string(attr))
  end

  defp contains_validation?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_validation?/1)
  end

  defp contains_validation?(_), do: false

  defp validation_name?(name) do
    down = String.downcase(name)
    Enum.any?(@validation_indicators, &String.contains?(down, &1))
  end

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential unrestricted file upload (CWE-434): #{detail}.",
      trigger: "upload",
      line_no: line_no
    )
  end
end
