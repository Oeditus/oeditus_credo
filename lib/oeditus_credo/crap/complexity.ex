defmodule OeditusCredo.Crap.Complexity do
  @moduledoc false

  # Ported from ExCrap (https://github.com/germsvel/ex_crap), MIT License,
  # Copyright (c) 2026 The Software League. See NOTICE.md for the full notice.
  #
  # Parses source with `Code.string_to_quoted/1`; analyzed code is not compiled or
  # evaluated. Results include module, function, arity, line, and complexity.
  #
  # Decision-point rules:
  # - Each discovered def/defp/defmacro/defmacrop starts with base complexity 1.
  # - if/unless add 1.
  # - case/cond/receive branches add 1 each.
  # - with generators and else branches add 1 each.
  # - try adds 1; else/rescue/catch clauses add 1 each.
  # - for generators and filters add 1 each.
  # - Boolean and/or/&&/|| operators add 1 each, including in guards.
  # - Multiple clauses for the same MFA are aggregated by summing clause paths and decisions.

  @definition_kinds [:def, :defp, :defmacro, :defmacrop]

  @doc false
  def from_string(source) when is_binary(source) do
    case Code.string_to_quoted(source) do
      {:ok, quoted} ->
        if malformed_executable_container?(quoted) do
          {:error, :invalid_source}
        else
          {:ok, quoted |> functions(nil) |> aggregate_clauses()}
        end

      {:error, _reason} ->
        {:error, :invalid_source}
    end
  end

  def from_string(_source), do: {:error, :invalid_source}

  @doc false
  def from_file(path) when is_binary(path) do
    case File.read(path) do
      {:ok, source} -> from_string(source)
      {:error, reason} -> {:error, reason}
    end
  end

  def from_file(_path), do: {:error, :invalid_path}

  defp functions(quoted, module), do: functions(quoted, module, MapSet.new(), MapSet.new(), %{})

  defp functions(
         {:defmodule, _meta, [module_ast, [do: body]]},
         current_module,
         _local_protocols,
         _local_modules,
         _local_aliases
       ) do
    module = module_name(module_ast, current_module)

    functions(
      body,
      module,
      MapSet.new(),
      MapSet.new(),
      %{}
    )
  end

  defp functions(
         {:defimpl, _meta, args},
         current_module,
         local_protocols,
         local_modules,
         local_aliases
       ) do
    case defimpl_parts(args, current_module) do
      {:ok, protocol_ast, for_ast, body} ->
        protocol_ast
        |> defimpl_module_names(
          for_ast,
          current_module,
          local_protocols,
          local_modules,
          local_aliases
        )
        |> Enum.flat_map(&functions(body, &1))

      :error ->
        []
    end
  end

  defp functions(
         {kind, meta, [head, [do: body]]},
         module,
         _local_protocols,
         _local_modules,
         _local_aliases
       )
       when kind in @definition_kinds do
    {function, arity, guards} = function_name_arity_and_guards(head)

    [
      %{
        module: module,
        function: function,
        arity: arity,
        line: meta[:line],
        complexity: 1 + decision_count(guards) + decision_count(body)
      }
    ]
  end

  defp functions(
         {:__block__, _meta, expressions},
         module,
         local_protocols,
         local_modules,
         local_aliases
       ) do
    {results, _protocols, _modules, _aliases} =
      Enum.reduce(expressions, {[], local_protocols, local_modules, local_aliases}, fn expression,
                                                                                       {results,
                                                                                        protocols,
                                                                                        modules,
                                                                                        aliases} ->
        expression_results =
          functions(expression, module, protocols, modules, aliases)

        updated_protocols =
          expression
          |> local_protocol_modules(module)
          |> MapSet.new()
          |> MapSet.union(protocols)

        updated_modules =
          expression
          |> local_module_declarations(module)
          |> MapSet.new()
          |> MapSet.union(modules)

        updated_aliases = Map.merge(aliases, local_alias_declarations(expression, module))

        {results ++ expression_results, updated_protocols, updated_modules, updated_aliases}
      end)

    results
  end

  defp functions(list, module, local_protocols, local_modules, local_aliases)
       when is_list(list) do
    Enum.flat_map(list, &functions(&1, module, local_protocols, local_modules, local_aliases))
  end

  defp functions({branch, _meta, args}, module, local_protocols, local_modules, local_aliases)
       when branch in [:if, :unless] do
    case List.last(args) do
      branches when is_list(branches) ->
        Enum.flat_map(
          Keyword.values(branches),
          &functions(&1, module, local_protocols, local_modules, local_aliases)
        )

      _other ->
        []
    end
  end

  defp functions(_quoted, _module, _local_protocols, _local_modules, _local_aliases), do: []

  defp malformed_executable_container?(quoted),
    do: malformed_executable_container?(quoted, nil, false, MapSet.new())

  defp malformed_executable_container?(
         {:defmodule, _meta, [module_ast, [do: body]]},
         current_module,
         _in_executable?,
         _implemented_definitions
       ) do
    implemented_definitions =
      body
      |> implemented_definitions()
      |> maybe_include_embedded_template_declarations(body)

    not module_name_ast?(module_ast) ||
      malformed_executable_container?(
        body,
        module_name(module_ast, current_module),
        true,
        implemented_definitions
      )
  end

  defp malformed_executable_container?(
         {:defmodule, _meta, _args},
         _current_module,
         _in_executable?,
         _implemented_definitions
       ),
       do: true

  defp malformed_executable_container?(
         {:defimpl, _meta, args},
         current_module,
         _in_executable?,
         _implemented_definitions
       ) do
    case defimpl_parts(args, current_module) do
      {:ok, protocol_ast, for_ast, body} ->
        not defimpl_name_ast?(protocol_ast, for_ast) ||
          malformed_executable_container?(
            body,
            current_module,
            true,
            implemented_definitions(body)
          )

      :error ->
        true
    end
  end

  defp malformed_executable_container?(
         {kind, _meta, [head]},
         _current_module,
         true,
         implemented_definitions
       )
       when kind in @definition_kinds do
    case definition_key(kind, head) do
      {:ok, key} -> not MapSet.member?(implemented_definitions, key)
      :error -> true
    end
  end

  defp malformed_executable_container?(
         {kind, _meta, [head, [do: body]]},
         current_module,
         true,
         _implemented_definitions
       )
       when kind in @definition_kinds do
    case definition_key(kind, head) do
      {:ok, _key} -> malformed_executable_container?(body, current_module, false, MapSet.new())
      :error -> true
    end
  end

  defp malformed_executable_container?(
         {branch, _meta, args},
         current_module,
         in_executable?,
         implemented_definitions
       )
       when branch in [:if, :unless] do
    case List.last(args) do
      branches when is_list(branches) ->
        branches
        |> Keyword.values()
        |> Enum.any?(
          &malformed_executable_container?(
            &1,
            current_module,
            in_executable?,
            implemented_definitions
          )
        )

      _other ->
        false
    end
  end

  defp malformed_executable_container?(
         {:__block__, _meta, expressions},
         current_module,
         in_executable?,
         implemented_definitions
       ) do
    Enum.any?(
      expressions,
      &malformed_executable_container?(
        &1,
        current_module,
        in_executable?,
        implemented_definitions
      )
    )
  end

  defp malformed_executable_container?(
         list,
         current_module,
         in_executable?,
         implemented_definitions
       )
       when is_list(list) do
    Enum.any?(
      list,
      &malformed_executable_container?(
        &1,
        current_module,
        in_executable?,
        implemented_definitions
      )
    )
  end

  defp malformed_executable_container?(
         _quoted,
         _current_module,
         _in_executable?,
         _implemented_definitions
       ),
       do: false

  defp module_name_ast?(module_ast) when is_atom(module_ast), do: valid_module_atom?(module_ast)

  defp module_name_ast?(module_ast),
    do: module_alias?(module_ast) or module_concat_ast?(module_ast)

  defp module_alias?({:__aliases__, _meta, parts}) when is_list(parts) do
    Enum.all?(parts, &module_alias_part?/1)
  end

  defp module_alias?(_ast), do: false

  defp module_alias_part?({:__MODULE__, _meta, nil}), do: true
  defp module_alias_part?(part), do: is_atom(part)

  defp module_concat_ast?(
         {{:., _dot_meta, [{:__aliases__, _alias_meta, [:Module]}, :concat]}, _call_meta, args}
       ) do
    module_concat_args?(args)
  end

  defp module_concat_ast?(_ast), do: false

  defp module_concat_args?([left, right]),
    do: module_concat_arg?(left) and module_concat_arg?(right)

  defp module_concat_args?([parts]) when is_list(parts),
    do: Enum.all?(parts, &module_concat_arg?/1)

  defp module_concat_args?(_args), do: false

  defp module_concat_arg?({:__MODULE__, _meta, nil}), do: true
  defp module_concat_arg?(arg) when is_atom(arg), do: true
  defp module_concat_arg?(arg), do: module_alias?(arg)

  defp valid_module_atom?(module) do
    module
    |> Atom.to_string()
    |> String.starts_with?("Elixir.")
  end

  defp implemented_definitions(body) do
    body
    |> definitions_with_bodies()
    |> MapSet.new()
  end

  defp definitions_with_bodies({:__block__, _meta, expressions}) do
    Enum.flat_map(expressions, &definitions_with_bodies/1)
  end

  defp definitions_with_bodies({kind, _meta, [head, [do: _body]]})
       when kind in @definition_kinds do
    case definition_key(kind, head) do
      {:ok, key} -> [key]
      :error -> []
    end
  end

  defp definitions_with_bodies({branch, _meta, args}) when branch in [:if, :unless] do
    case List.last(args) do
      branches when is_list(branches) ->
        branches
        |> Keyword.values()
        |> Enum.flat_map(&definitions_with_bodies/1)

      _other ->
        []
    end
  end

  defp definitions_with_bodies(list) when is_list(list),
    do: Enum.flat_map(list, &definitions_with_bodies/1)

  defp definitions_with_bodies(_quoted), do: []

  defp maybe_include_embedded_template_declarations(implemented_definitions, body) do
    if embeds_templates?(body) do
      MapSet.union(implemented_definitions, MapSet.new(bodyless_public_definitions(body)))
    else
      implemented_definitions
    end
  end

  defp embeds_templates?({:__block__, _meta, expressions}),
    do: Enum.any?(expressions, &embeds_templates?/1)

  defp embeds_templates?({:embed_templates, _meta, _args}), do: true

  defp embeds_templates?(_quoted), do: false

  defp bodyless_public_definitions({:__block__, _meta, expressions}) do
    Enum.flat_map(expressions, &bodyless_public_definitions/1)
  end

  defp bodyless_public_definitions({:def, _meta, [head]}) do
    case definition_key(:def, head) do
      {:ok, key} -> [key]
      :error -> []
    end
  end

  defp bodyless_public_definitions(_quoted), do: []

  defp definition_key(kind, {:when, _meta, [head | _guards]}), do: definition_key(kind, head)

  defp definition_key(kind, {name, _meta, nil}) when is_atom(name), do: {:ok, {kind, name, 0}}

  defp definition_key(kind, {name, _meta, args}) when is_atom(name) and is_list(args),
    do: {:ok, {kind, name, length(args)}}

  defp definition_key(_kind, _head), do: :error

  defp local_protocol_modules({:__block__, _meta, expressions}, current_module) do
    Enum.flat_map(expressions, &local_protocol_modules(&1, current_module))
  end

  defp local_protocol_modules({:defprotocol, _meta, [protocol_ast, [do: _body]]}, current_module)
       when not is_nil(current_module) do
    if module_name_ast?(protocol_ast), do: [module_name(protocol_ast, current_module)], else: []
  end

  defp local_protocol_modules(_quoted, _current_module), do: []

  defp local_module_declarations({:__block__, _meta, expressions}, current_module) do
    Enum.flat_map(expressions, &local_module_declarations(&1, current_module))
  end

  defp local_module_declarations({:defmodule, _meta, [module_ast, [do: _body]]}, current_module)
       when not is_nil(current_module) do
    if module_name_ast?(module_ast), do: [module_name(module_ast, current_module)], else: []
  end

  defp local_module_declarations(_quoted, _current_module), do: []

  defp local_alias_declarations({:alias, _meta, [alias_ast, opts]}, current_module)
       when is_list(opts) do
    alias_declaration(alias_ast, opts, current_module)
  end

  defp local_alias_declarations(
         {:alias, _meta, [{{:., _dot_meta, [base_ast, :{}]}, _group_meta, grouped_aliases}]},
         current_module
       )
       when is_list(grouped_aliases) do
    base_module = alias_declaration_module_name(base_ast, current_module)

    Enum.reduce(grouped_aliases, %{}, fn alias_ast, aliases ->
      case alias_name(alias_ast, []) do
        {:ok, alias_name} ->
          Map.put(aliases, alias_name, Module.concat([base_module, module_name(alias_ast, nil)]))

        :error ->
          aliases
      end
    end)
  end

  defp local_alias_declarations({:alias, _meta, [alias_ast]}, current_module) do
    alias_declaration(alias_ast, [], current_module)
  end

  defp local_alias_declarations(_quoted, _current_module), do: %{}

  defp alias_declaration(alias_ast, opts, current_module) do
    case alias_name(alias_ast, opts) do
      {:ok, alias_name} ->
        %{alias_name => alias_declaration_module_name(alias_ast, current_module)}

      _other ->
        %{}
    end
  end

  defp alias_name({:__aliases__, _meta, parts}, []) when is_list(parts) do
    case List.last(parts) do
      alias_name when is_atom(alias_name) -> {:ok, alias_name}
      _other -> :error
    end
  end

  defp alias_name(_alias_ast, []) do
    :error
  end

  defp alias_name(_alias_ast, opts) do
    case Keyword.fetch(opts, :as) do
      {:ok, {:__aliases__, _meta, [alias_name]}} when is_atom(alias_name) -> {:ok, alias_name}
      {:ok, alias_name} when is_atom(alias_name) -> {:ok, alias_name}
      {:ok, _other} -> :error
      :error -> :error
    end
  end

  defp alias_declaration_module_name(alias_ast, current_module) do
    parent = if current_module_reference?(alias_ast), do: current_module

    module_name(alias_ast, parent)
  end

  defp defimpl_parts([protocol_ast, opts, [do: body]], current_module) when is_list(opts) do
    with {:ok, for_ast} <- defimpl_for_ast(opts, current_module) do
      {:ok, protocol_ast, for_ast, body}
    end
  end

  defp defimpl_parts([protocol_ast, [do: body]], current_module)
       when not is_nil(current_module) do
    {:ok, protocol_ast, current_module, body}
  end

  defp defimpl_parts([protocol_ast, opts], _current_module) when is_list(opts) do
    with {:ok, for_ast} <- Keyword.fetch(opts, :for),
         {:ok, body} <- Keyword.fetch(opts, :do) do
      {:ok, protocol_ast, for_ast, body}
    end
  end

  defp defimpl_parts(_args, _current_module), do: :error

  defp defimpl_for_ast(opts, current_module) do
    case Keyword.fetch(opts, :for) do
      {:ok, for_ast} -> {:ok, for_ast}
      :error when not is_nil(current_module) -> {:ok, current_module}
      :error -> :error
    end
  end

  defp defimpl_name_ast?(protocol_ast, for_ast) when is_list(for_ast) do
    defimpl_protocol_ast?(protocol_ast) and Enum.all?(for_ast, &defimpl_target_ast?/1)
  end

  defp defimpl_name_ast?(protocol_ast, for_ast),
    do: defimpl_protocol_ast?(protocol_ast) and defimpl_target_ast?(for_ast)

  defp defimpl_protocol_ast?(protocol_ast),
    do: module_name_ast?(protocol_ast) or module_concat_ast?(protocol_ast)

  defp defimpl_target_ast?(for_ast) when is_atom(for_ast), do: true
  defp defimpl_target_ast?(for_ast), do: module_alias?(for_ast) or module_concat_ast?(for_ast)

  defp aggregate_clauses(functions) do
    functions
    |> Enum.group_by(&{&1.module, &1.function, &1.arity})
    |> Enum.map(fn {_key, clauses} ->
      first = Enum.min_by(clauses, &(&1.line || 0))

      complexity = clauses |> Enum.map(& &1.complexity) |> Enum.sum()

      %{first | complexity: complexity}
    end)
    |> Enum.sort_by(&{inspect(&1.module), &1.line || 0, &1.function, &1.arity})
  end

  defp module_name({:__aliases__, _meta, [{:__MODULE__, _module_meta, nil} | parts]}, nil),
    do: Module.concat(parts)

  defp module_name({:__aliases__, _meta, [{:__MODULE__, _module_meta, nil} | parts]}, parent),
    do: Module.concat([parent | parts])

  defp module_name({:__aliases__, _meta, parts}, nil), do: Module.concat(parts)
  defp module_name({:__aliases__, _meta, parts}, parent), do: Module.concat([parent | parts])
  defp module_name(module, _parent) when is_atom(module), do: module

  defp module_name(
         {{:., _dot_meta, [{:__aliases__, _meta, [:Module]}, :concat]}, _call_meta, args},
         current_module
       ) do
    args
    |> module_concat_parts(current_module)
    |> Module.concat()
  end

  defp module_concat_parts([parts], current_module) when is_list(parts),
    do: Enum.map(parts, &module_concat_part(&1, current_module))

  defp module_concat_parts(parts, current_module),
    do: Enum.map(parts, &module_concat_part(&1, current_module))

  defp module_concat_part({:__MODULE__, _meta, nil}, current_module), do: current_module

  defp module_concat_part({:__aliases__, _meta, _parts} = alias_ast, _current_module),
    do: module_name(alias_ast, nil)

  defp module_concat_part(module, _current_module) when is_atom(module), do: module

  defp protocol_module_name(protocol_ast, current_module, local_protocols, local_aliases)
       when not is_nil(current_module) do
    local_protocol = module_name(protocol_ast, current_module)

    cond do
      aliased_module = alias_module_name(protocol_ast, local_aliases) ->
        aliased_module

      current_module_reference?(protocol_ast) or MapSet.member?(local_protocols, local_protocol) ->
        local_protocol

      true ->
        module_name(protocol_ast, nil)
    end
  end

  defp protocol_module_name(protocol_ast, _current_module, _local_protocols, _local_aliases),
    do: module_name(protocol_ast, nil)

  defp defimpl_module_names(
         protocol_ast,
         for_ast,
         current_module,
         local_protocols,
         local_modules,
         local_aliases
       ) do
    case for_ast do
      nil -> [nil]
      targets -> List.wrap(targets)
    end
    |> Enum.map(
      &defimpl_module_name(
        protocol_ast,
        &1,
        current_module,
        local_protocols,
        local_modules,
        local_aliases
      )
    )
  end

  defp defimpl_module_name(
         protocol_ast,
         for_module,
         current_module,
         local_protocols,
         _local_modules,
         local_aliases
       )
       when is_atom(for_module) do
    Module.concat([
      protocol_module_name(protocol_ast, current_module, local_protocols, local_aliases),
      for_module
    ])
  end

  defp defimpl_module_name(
         protocol_ast,
         for_ast,
         current_module,
         local_protocols,
         local_modules,
         local_aliases
       ) do
    Module.concat([
      protocol_module_name(protocol_ast, current_module, local_protocols, local_aliases),
      target_module_name(for_ast, current_module, local_modules, local_aliases)
    ])
  end

  defp target_module_name(for_ast, nil, _local_modules, _local_aliases),
    do: module_name(for_ast, nil)

  defp target_module_name(for_ast, current_module, local_modules, local_aliases) do
    local_module = module_name(for_ast, current_module)

    cond do
      aliased_module = alias_module_name(for_ast, local_aliases) ->
        aliased_module

      current_module_reference?(for_ast) or MapSet.member?(local_modules, local_module) ->
        local_module

      true ->
        module_name(for_ast, nil)
    end
  end

  defp alias_module_name({:__aliases__, _meta, [alias_name | parts]}, local_aliases) do
    case Map.fetch(local_aliases, alias_name) do
      {:ok, module} -> Module.concat([module | parts])
      :error -> nil
    end
  end

  defp alias_module_name(_ast, _local_aliases), do: nil

  defp current_module_reference?({:__MODULE__, _meta, nil}), do: true

  defp current_module_reference?({:__aliases__, _meta, parts}),
    do: Enum.any?(parts, &current_module_reference?/1)

  defp current_module_reference?(
         {{:., _dot_meta, [{:__aliases__, _meta, [:Module]}, :concat]}, _call_meta, args}
       ) do
    Enum.any?(List.flatten(args), &current_module_reference?/1)
  end

  defp current_module_reference?(_ast), do: false

  defp function_name_arity_and_guards({:when, _meta, [head | guards]}) do
    {name, arity, existing_guards} = function_name_arity_and_guards(head)
    {name, arity, existing_guards ++ guards}
  end

  defp function_name_arity_and_guards({name, _meta, nil}) when is_atom(name), do: {name, 0, []}

  defp function_name_arity_and_guards({name, _meta, args}) when is_atom(name),
    do: {name, length(args), []}

  defp decision_count(list) when is_list(list),
    do: Enum.reduce(list, 0, &(&2 + decision_count(&1)))

  defp decision_count({:->, _meta, [patterns, body]}),
    do: decision_count(patterns) + decision_count(body)

  defp decision_count({operator, _meta, args}) when operator in [:and, :or, :&&, :||] do
    1 + decision_count(args)
  end

  defp decision_count({branch, _meta, args}) when branch in [:if, :unless] do
    1 + decision_count(args)
  end

  defp decision_count({branch, _meta, args}) when branch in [:case, :cond] do
    branch_count(args) + decision_count(args)
  end

  defp decision_count({:with, _meta, args}) do
    generator_count(args) + arrow_count(keyword_value(args, :else)) + decision_count(args)
  end

  defp decision_count({:<-, _meta, args}) do
    decision_count(args)
  end

  defp decision_count({:try, _meta, args}) do
    1 + arrow_count(keyword_value(args, :else)) + arrow_count(keyword_value(args, :rescue)) +
      arrow_count(keyword_value(args, :catch)) + decision_count(args)
  end

  defp decision_count({:for, _meta, args}) when is_list(args) do
    comprehension_qualifier_count(args) + decision_count(args)
  end

  defp decision_count({:receive, _meta, args}) do
    branch_count(args) + receive_after_count(args) + decision_count(args)
  end

  defp decision_count({:fn, _meta, clauses}) do
    arrow_count(clauses) + decision_count(clauses)
  end

  defp decision_count({:defmodule, _meta, _args}), do: 0
  defp decision_count({_name, _meta, args}) when is_list(args), do: decision_count(args)
  defp decision_count({_left, right}), do: decision_count(right)
  defp decision_count(_quoted), do: 0

  defp branch_count(args), do: args |> keyword_value(:do) |> arrow_count()

  defp keyword_value(args, key) do
    args
    |> Enum.reverse()
    |> Enum.find(&(Keyword.keyword?(&1) and Keyword.has_key?(&1, key)))
    |> case do
      nil -> nil
      keyword -> Keyword.get(keyword, key)
    end
  end

  defp arrow_count(clauses) when is_list(clauses),
    do: Enum.count(clauses, &match?({:->, _meta, _clause}, &1))

  defp arrow_count({:__block__, _meta, clauses}), do: arrow_count(clauses)
  defp arrow_count({:->, _meta, _clause}), do: 1
  defp arrow_count(_other), do: 0

  defp generator_count(args), do: Enum.count(args, &match?({:<-, _meta, _args}, &1))

  defp comprehension_qualifier_count(args) do
    Enum.count(args, fn
      {:<-, _meta, _args} -> true
      keyword when is_list(keyword) -> false
      _filter -> true
    end)
  end

  defp receive_after_count(args), do: if(keyword_value(args, :after), do: 1, else: 0)
end
