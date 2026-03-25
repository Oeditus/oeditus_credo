defmodule OeditusCredo.Check.Security.MissingAuthentication do
  @moduledoc """
  Checks for sensitive controller actions that appear to lack authentication.

  MITRE reference: [CWE-306](https://cwe.mitre.org/data/definitions/306.html) --
  Missing Authentication for Critical Function.
  """

  use Credo.Check,
    base_priority: :high,
    category: :warning,
    explanations: [
      check: """
      Detects potential missing authentication in controller actions ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)).

      Sensitive controller actions should be protected by an authentication plug.
      This check accepts any plug name containing "auth" as an authentication indicator.

      Bad:

          defmodule MyAppWeb.AdminController do
            use MyAppWeb, :controller

            def delete(conn, params) do
              ...
            end
          end

      Good:

          defmodule MyAppWeb.AdminController do
            use MyAppWeb, :controller
            plug :require_authentication

            def delete(conn, params) do
              ...
            end
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        sensitive_actions:
          "List of action name strings considered sensitive (default: index, show, create, new, update, edit, delete, destroy)"
      ]
    ]

  @default_sensitive_actions ~w[index show create new update edit delete destroy]

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
      actions = Params.get(params, :sensitive_actions, __MODULE__)

      source_file
      |> Credo.Code.prewalk(&traverse(&1, &2, {issue_meta, actions}))
    end
  end

  @doc false
  @impl true
  def param_defaults do
    [exclude_test_files: false, sensitive_actions: @default_sensitive_actions]
  end

  defp traverse(
         {:defmodule, meta, [module_ast, [do: body]]} = ast,
         issues,
         {issue_meta, actions}
       ) do
    module_name = module_name(module_ast)
    statements = block_to_statements(body)

    if controller_module?(module_name) and has_sensitive_action?(statements, actions) and
         not has_auth_plug?(statements) do
      {ast,
       [
         issue_for(
           issue_meta,
           meta[:line],
           "controller has sensitive actions but no auth plug in module pipeline"
         )
         | issues
       ]}
    else
      {ast, issues}
    end
  end

  defp traverse(ast, issues, _ctx), do: {ast, issues}

  defp module_name({:__aliases__, _, parts}) when is_list(parts), do: Enum.join(parts, ".")
  defp module_name(_), do: ""

  defp controller_module?(name) do
    String.ends_with?(name, "Controller") or
      String.contains?(String.downcase(name), "controller")
  end

  defp block_to_statements({:__block__, _, statements}) when is_list(statements), do: statements
  defp block_to_statements(statement), do: [statement]

  defp has_sensitive_action?(statements, actions) do
    Enum.any?(statements, fn
      {:def, _, [{name, _, _args}, _]} when is_atom(name) ->
        Atom.to_string(name) in actions

      {:defp, _, [{name, _, _args}, _]} when is_atom(name) ->
        Atom.to_string(name) in actions

      _ ->
        false
    end)
  end

  defp has_auth_plug?(statements) do
    Enum.any?(statements, fn
      {:plug, _, [plug_name | _rest]} ->
        plug_name_to_string(plug_name)
        |> String.downcase()
        |> String.contains?("auth")

      _ ->
        false
    end)
  end

  defp plug_name_to_string({:__aliases__, _, parts}) when is_list(parts),
    do: Enum.join(parts, ".")

  defp plug_name_to_string(name) when is_atom(name), do: Atom.to_string(name)
  defp plug_name_to_string(_), do: ""

  defp issue_for(issue_meta, line_no, detail) do
    format_issue(
      issue_meta,
      message: "Potential missing authentication (CWE-306): #{detail}.",
      trigger: "plug",
      line_no: line_no
    )
  end
end
