defmodule OeditusCredo.Check.Security.ImproperInputValidation do
  @moduledoc """
  Checks for missing validation/sanitization of external input.

  MITRE reference: [CWE-20](https://cwe.mitre.org/data/definitions/20.html) —
  Improper Input Validation.
  """
  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential improper input validation patterns ([CWE-20](https://cwe.mitre.org/data/definitions/20.html)).

      Controller actions should validate/sanitize user input before using it in
      sensitive operations.

      Bad:

          def create(conn, %{"name" => name}) do
            Repo.insert!(%User{name: name})
          end

      Good:

          changeset =
            User.changeset(%User{}, params)
            |> validate_required([:name])
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)"
      ]
    ]

  @sensitive_calls ~w[insert insert! update update! delete delete! query query!]
  @validation_indicators ~w[changeset validate validate_required validate_format cast sanitize]

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

  defp traverse({:def, meta, [{_name, _, args}, [do: body]]} = ast, issues, issue_meta) do
    params_bound? = params_argument?(args)
    statements = block_to_statements(body)

    if params_bound? and has_sensitive_op_using_params?(statements) and
         not has_validation?(statements) do
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "params appear in sensitive operation without visible validation"
         )
         | issues
       ]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _issue_meta), do: {ast, issues}

  defp params_argument?(args) when is_list(args) do
    Enum.any?(args, fn
      {:params, _, _} -> true
      {:%{}, _, _} -> true
      _ -> false
    end)
  end

  defp params_argument?(_), do: false

  defp block_to_statements({:__block__, _, statements}) when is_list(statements), do: statements
  defp block_to_statements(statement), do: [statement]

  defp has_sensitive_op_using_params?(statements) do
    Enum.any?(statements, &contains_sensitive_use?/1)
  end

  defp contains_sensitive_use?({{:., _, [{:__aliases__, _, [:Repo]}, call]}, _, args})
       when is_atom(call) and is_list(args) do
    Atom.to_string(call) in @sensitive_calls and Enum.any?(args, &contains_params_access?/1)
  end

  defp contains_sensitive_use?(
         {{:., _, [{:__aliases__, _, [:Ecto, :Changeset]}, :cast]}, _, args}
       )
       when is_list(args) do
    Enum.any?(args, &contains_params_access?/1)
  end

  defp contains_sensitive_use?({_, _, args}) when is_list(args) do
    Enum.any?(args, &contains_sensitive_use?/1)
  end

  defp contains_sensitive_use?(_), do: false

  defp contains_params_access?({:params, _, _}), do: true
  defp contains_params_access?({{:., _, [Access, :get]}, _, [{:params, _, _}, _key]}), do: true

  defp contains_params_access?({_, _, args}) when is_list(args),
    do: Enum.any?(args, &contains_params_access?/1)

  defp contains_params_access?(_), do: false

  defp has_validation?(statements) do
    Enum.any?(statements, &contains_validation?/1)
  end

  defp contains_validation?({{:., _, [{:__aliases__, _, parts}, name]}, _, _args})
       when is_list(parts) and is_atom(name) do
    validation_name?(Enum.join(parts, ".") <> "." <> Atom.to_string(name))
  end

  defp contains_validation?({:., _, [_left, right_name]}) when is_atom(right_name) do
    validation_name?(Atom.to_string(right_name))
  end

  defp contains_validation?({name, _, _args}) when is_atom(name) do
    validation_name?(Atom.to_string(name))
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
      message: "Potential improper input validation (CWE-20): #{detail}.",
      trigger: "params",
      line_no: line_no
    )
  end
end
