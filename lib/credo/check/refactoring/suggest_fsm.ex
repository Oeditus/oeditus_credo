defmodule OeditusCredo.Check.Refactoring.SuggestFSM do
  @moduledoc """
  Detects modules that manage entity lifecycle through imperative
  status/state field manipulation and suggests using a finite state
  machine library instead.

  The check looks for Ecto Enum status fields, case-branching on
  status values, imperative transitions (`put_change`, struct
  updates), and transition-verb function names. When enough evidence
  accumulates, it suggests replacing the pattern with `Finitomata`
  or `:gen_statem`.
  """

  use Credo.Check,
    base_priority: :low,
    category: :refactoring,
    explanations: [
      check: """
      Modules that manage entity lifecycle through plain imperative code --
      branching on a `status`/`state` field, manually setting it to new values,
      scattering guards across multiple function heads -- should consider using
      a proper finite state machine instead.

      Suggested replacements:
      - `Finitomata` -- an Elixir FSM library with PlantUML/Mermaid diagram input,
        callbacks, supervision, history, and telemetry.
      - `:gen_statem` -- the OTP built-in state machine behaviour.

      Bad:

          defmodule MyApp.Order do
            use Ecto.Schema

            schema "orders" do
              field :status, Ecto.Enum, values: [:draft, :pending, :paid, :shipped, :delivered]
            end

            def pay(order) do
              case order.status do
                :draft -> {:error, :not_ready}
                :pending -> Ecto.Changeset.change(order, status: :paid)
                :paid -> {:error, :already_paid}
                _ -> {:error, :invalid}
              end
            end
          end

      Good:

          defmodule MyApp.OrderFSM do
            @fsm \"\"\"
            draft --> |submit| pending
            pending --> |pay| paid
            paid --> |ship| shipped
            shipped --> |deliver| delivered
            \"\"\"

            use Finitomata, fsm: @fsm, syntax: :flowchart

            @impl Finitomata
            def on_transition(:pending, :pay, _payload, state),
              do: {:ok, :paid, state}
          end
      """,
      params: [
        exclude_test_files: "Set to true to skip test files (default: false)",
        status_field_names: "Field names to watch (default: [:status, :state])",
        min_states: "Minimum distinct status values to trigger (default: 3)"
      ]
    ]

  import OeditusCredo.Helpers, only: [test_file?: 1]

  @status_fields ~w(status state)a

  @transition_verbs ~w(
    activate deactivate publish unpublish archive unarchive
    suspend resume complete cancel approve reject
    enable disable start stop pause draft
    submit finalize close reopen expire revoke
    block unblock lock unlock freeze thaw
  )a

  @doc false
  @impl true
  def run(%SourceFile{}, false), do: []

  def run(%SourceFile{} = source_file, params) do
    if Params.get(params, :exclude_test_files, __MODULE__) and
         test_file?(source_file.filename) do
      []
    else
      issue_meta = IssueMeta.for(source_file, params)
      status_fields = Params.get(params, :status_field_names, __MODULE__)
      min_states = Params.get(params, :min_states, __MODULE__)

      source_file
      |> Credo.Code.prewalk(&traverse_module(&1, &2, {issue_meta, status_fields, min_states}))
    end
  end

  @doc false
  @impl true
  def param_defaults do
    [exclude_test_files: false, status_field_names: @status_fields, min_states: 3]
  end

  # --- Module-level: detect defmodule and analyze its body ---

  defp traverse_module(
         {:defmodule, meta, [_name, [do: body]]} = ast,
         issues,
         {issue_meta, status_fields, min_states}
       ) do
    # Pass 0: resolve module attribute definitions (@statuses, etc.)
    attr_map = collect_module_attributes(body)

    # Pass 1: collect schema status fields and their declared states
    schema_states = collect_schema_states(body, status_fields, attr_map)

    # Pass 2: collect branching sites on status fields
    branching_evidence = collect_branching(body, status_fields)

    # Pass 3: collect imperative status transitions (put_change, struct updates)
    transition_evidence = collect_transitions(body, status_fields)

    # Pass 4: collect transition-verb function names
    verb_functions = collect_verb_functions(body)

    all_states =
      MapSet.union(schema_states, branching_evidence.states)
      |> MapSet.union(transition_evidence.states)

    has_schema? = MapSet.size(schema_states) > 0
    has_branching? = branching_evidence.count > 0
    has_transitions? = transition_evidence.count > 0
    has_verb_functions? = length(verb_functions) >= 2

    # Require schema-level evidence + at least one behavioral signal,
    # OR strong behavioral evidence alone (branching + transitions)
    should_flag? =
      MapSet.size(all_states) >= min_states and
        ((has_schema? and (has_branching? or has_transitions? or has_verb_functions?)) or
           (has_branching? and has_transitions?))

    if should_flag? do
      states_str =
        all_states |> MapSet.to_list() |> Enum.sort() |> Enum.map_join(", ", &inspect/1)

      message =
        "Module manages #{MapSet.size(all_states)} status values (#{states_str}) imperatively -- " <>
          "consider replacing with Finitomata or :gen_statem"

      {ast, [issue_for(issue_meta, meta[:line], message) | issues]}
    else
      {ast, issues}
    end
  end

  defp traverse_module(ast, issues, _state), do: {ast, issues}

  # --- Pass 0: Module attribute collection ---

  defp collect_module_attributes(body) do
    {_, attrs} =
      Macro.prewalk(body, %{}, fn
        # @attr_name [literal_list]
        {:@, _, [{attr_name, _, [list]}]} = ast, acc
        when is_atom(attr_name) and is_list(list) ->
          atoms = Enum.filter(list, &is_atom/1)

          if atoms != [] do
            {ast, Map.put(acc, attr_name, atoms)}
          else
            {ast, acc}
          end

        # @attr_name ~W(...)a  --  the sigil expands to a list at AST level
        {:@, _, [{attr_name, _, [{:sigil_W, _, _} = sigil]}]} = ast, acc
        when is_atom(attr_name) ->
          atoms = extract_sigil_atoms(sigil)

          if atoms != [] do
            {ast, Map.put(acc, attr_name, atoms)}
          else
            {ast, acc}
          end

        # @attr_name ~w(...)a  --  lowercase sigil variant
        {:@, _, [{attr_name, _, [{:sigil_w, _, _} = sigil]}]} = ast, acc
        when is_atom(attr_name) ->
          atoms = extract_sigil_atoms(sigil)

          if atoms != [] do
            {ast, Map.put(acc, attr_name, atoms)}
          else
            {ast, acc}
          end

        ast, acc ->
          {ast, acc}
      end)

    attrs
  end

  defp extract_sigil_atoms({sigil_name, meta, _} = sigil)
       when sigil_name in [:sigil_W, :sigil_w] do
    modifier = Keyword.get(meta, :delimiter, "") |> detect_modifier(sigil)

    if modifier == "a" do
      case sigil do
        {_, _, [{:<<>>, _, [str]}, []]} when is_binary(str) ->
          str |> String.split() |> Enum.map(&String.to_atom/1)

        {_, _, [{:<<>>, _, [str]}, [?a]]} when is_binary(str) ->
          str |> String.split() |> Enum.map(&String.to_atom/1)

        _ ->
          []
      end
    else
      []
    end
  end

  # The modifier for ~W(...)a / ~w(...)a appears as the second element
  # of the sigil tuple args (a charlist like [?a]).
  defp detect_modifier(_delimiter, {_, _, [_str, [?a]]}), do: "a"
  defp detect_modifier(_delimiter, _), do: ""

  # --- Pass 1: Schema status fields ---

  defp collect_schema_states(body, status_fields, attr_map) do
    {_, states} =
      Macro.prewalk(body, MapSet.new(), &find_schema_fields(&1, &2, status_fields, attr_map))

    states
  end

  # field :status, Ecto.Enum, values: [...]
  defp find_schema_fields(
         {:field, _, [field_name, {:__aliases__, _, [:Ecto, :Enum]}, opts]} = ast,
         acc,
         status_fields,
         attr_map
       )
       when is_atom(field_name) do
    if field_name in status_fields do
      values = extract_enum_values(opts, attr_map)
      {ast, Enum.reduce(values, acc, &MapSet.put(&2, &1))}
    else
      {ast, acc}
    end
  end

  # field :status, Ecto.Enum (without keyword opts -- less common but possible)
  defp find_schema_fields(ast, acc, _status_fields, _attr_map), do: {ast, acc}

  defp extract_enum_values(opts, attr_map) when is_list(opts) do
    case Keyword.get(opts, :values) do
      values when is_list(values) ->
        Enum.filter(values, &is_atom/1)

      # values: @attr_name -- module attribute reference
      {:@, _, [{attr_name, _, _}]} when is_atom(attr_name) ->
        Map.get(attr_map, attr_name, [])

      _ ->
        []
    end
  end

  defp extract_enum_values(_, _attr_map), do: []

  # --- Pass 2: Branching on status ---

  defp collect_branching(body, status_fields) do
    {_, evidence} =
      Macro.prewalk(body, %{count: 0, states: MapSet.new()}, fn
        # case record.status do ... end (dot access: {{:., _, [_, :field]}, _, []})
        {:case, _, [{{:., _, [_receiver, field]}, _, _args}, [do: clauses]]} = ast, acc
        when is_atom(field) ->
          if field in status_fields do
            states = extract_clause_atoms(clauses)
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, states)}}
          else
            {ast, acc}
          end

        # case status do ... end (bare variable named status/state)
        {:case, _, [{field, _, context}, [do: clauses]]} = ast, acc
        when is_atom(field) and is_atom(context) ->
          if field in status_fields do
            states = extract_clause_atoms(clauses)
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, states)}}
          else
            {ast, acc}
          end

        # case get_field(changeset, :status) do ... end
        {:case, _, [{accessor, _, [_changeset, field]}, [do: clauses]]} = ast, acc
        when accessor in [:get_field, :get_change, :fetch_field!] and is_atom(field) ->
          if field in status_fields do
            states = extract_clause_atoms(clauses)
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, states)}}
          else
            {ast, acc}
          end

        # case Map.get(record, :status) do ... end
        {:case, _,
         [{{:., _, [{:__aliases__, _, [:Map]}, :get]}, _, [_record, field]}, [do: clauses]]} =
            ast,
        acc
        when is_atom(field) ->
          if field in status_fields do
            states = extract_clause_atoms(clauses)
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, states)}}
          else
            {ast, acc}
          end

        ast, acc ->
          {ast, acc}
      end)

    evidence
  end

  defp extract_clause_atoms(clauses) when is_list(clauses) do
    Enum.reduce(clauses, MapSet.new(), fn
      {:->, _, [[pattern], _body]}, acc ->
        extract_atom_from_pattern(pattern, acc)

      _, acc ->
        acc
    end)
  end

  defp extract_clause_atoms(_), do: MapSet.new()

  defp extract_atom_from_pattern(atom, acc) when is_atom(atom) and atom not in [true, false, nil],
    do: MapSet.put(acc, atom)

  defp extract_atom_from_pattern({:__block__, _, [atom]}, acc)
       when is_atom(atom) and atom not in [true, false, nil],
       do: MapSet.put(acc, atom)

  defp extract_atom_from_pattern(_, acc), do: acc

  # --- Pass 3: Imperative transitions ---

  # credo:disable-for-lines:71
  defp collect_transitions(body, status_fields) do
    {_, evidence} =
      Macro.prewalk(body, %{count: 0, states: MapSet.new()}, fn
        # put_change(changeset, :status, :value) -- non-piped, 3 args
        {:put_change, _, [_cs, field, value]} = ast, acc when is_atom(field) ->
          if field in status_fields and is_atom(value) and value not in [true, false, nil] do
            {ast, %{acc | count: acc.count + 1, states: MapSet.put(acc.states, value)}}
          else
            {ast, acc}
          end

        # |> put_change(:status, :value) -- piped, 2 args (first arg is implicit)
        {:put_change, _, [field, value]} = ast, acc when is_atom(field) ->
          if field in status_fields and is_atom(value) and value not in [true, false, nil] do
            {ast, %{acc | count: acc.count + 1, states: MapSet.put(acc.states, value)}}
          else
            {ast, acc}
          end

        # force_change(changeset, :status, :value) -- non-piped, 3 args
        {:force_change, _, [_cs, field, value]} = ast, acc when is_atom(field) ->
          if field in status_fields and is_atom(value) and value not in [true, false, nil] do
            {ast, %{acc | count: acc.count + 1, states: MapSet.put(acc.states, value)}}
          else
            {ast, acc}
          end

        # |> force_change(:status, :value) -- piped, 2 args
        {:force_change, _, [field, value]} = ast, acc when is_atom(field) ->
          if field in status_fields and is_atom(value) and value not in [true, false, nil] do
            {ast, %{acc | count: acc.count + 1, states: MapSet.put(acc.states, value)}}
          else
            {ast, acc}
          end

        # Ecto.Changeset.change(record, status: :value) -- non-piped
        {:change, _, [_record, updates]} = ast, acc when is_list(updates) ->
          new_states = extract_status_from_keyword(updates, status_fields)

          if MapSet.size(new_states) > 0 do
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, new_states)}}
          else
            {ast, acc}
          end

        # |> change(status: :value) -- piped, 1 arg (keyword list)
        {:change, _, [updates]} = ast, acc when is_list(updates) ->
          new_states = extract_status_from_keyword(updates, status_fields)

          if MapSet.size(new_states) > 0 do
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, new_states)}}
          else
            {ast, acc}
          end

        # %{record | status: :value} (struct update syntax)
        {:%{}, _, [{:|, _, [_record, updates]}]} = ast, acc when is_list(updates) ->
          new_states = extract_status_from_keyword(updates, status_fields)

          if MapSet.size(new_states) > 0 do
            {ast, %{acc | count: acc.count + 1, states: MapSet.union(acc.states, new_states)}}
          else
            {ast, acc}
          end

        ast, acc ->
          {ast, acc}
      end)

    evidence
  end

  defp extract_status_from_keyword(kw, status_fields) when is_list(kw) do
    Enum.reduce(kw, MapSet.new(), fn
      {field, value}, acc
      when is_atom(field) and is_atom(value) and value not in [true, false, nil] ->
        if field in status_fields, do: MapSet.put(acc, value), else: acc

      _, acc ->
        acc
    end)
  end

  # --- Pass 4: Transition-verb functions ---

  defp collect_verb_functions(body) do
    {_, funcs} =
      Macro.prewalk(body, [], fn
        {:def, _, [{name, _, _} | _]} = ast, acc when is_atom(name) ->
          if name in @transition_verbs or has_verb_prefix?(name) do
            {ast, [name | acc]}
          else
            {ast, acc}
          end

        {:defp, _, [{name, _, _} | _]} = ast, acc when is_atom(name) ->
          if name in @transition_verbs or has_verb_prefix?(name) do
            {ast, [name | acc]}
          else
            {ast, acc}
          end

        ast, acc ->
          {ast, acc}
      end)

    Enum.uniq(funcs)
  end

  defp has_verb_prefix?(name) do
    name_str = Atom.to_string(name)

    Enum.any?(@transition_verbs, fn verb ->
      verb_str = Atom.to_string(verb)

      String.starts_with?(name_str, verb_str <> "_") or
        String.ends_with?(name_str, "_" <> verb_str)
    end)
  end

  defp issue_for(issue_meta, line_no, message) do
    format_issue(
      issue_meta,
      message: message,
      trigger: "defmodule",
      line_no: line_no
    )
  end
end
