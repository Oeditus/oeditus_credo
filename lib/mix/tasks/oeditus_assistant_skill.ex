defmodule Mix.Tasks.OeditusAssistantSkill do
  @moduledoc """
  Generates an AI assistant skill file (`SKILL.md`) for lightweight local PR review using
  OeditusCredo rules.

  Supported target assistants: `claude`, `openai`, `gemini`.

  ## Usage

      mix oeditus_assistant_skill claude    # writes to .claude/skills/oeditus/SKILL.md
      mix oeditus_assistant_skill openai    # writes to .openai/skills/oeditus/SKILL.md
      mix oeditus_assistant_skill gemini    # writes to .gemini/skills/oeditus/SKILL.md

  ## Options

      --stdout        Prints the generated skill markdown to stdout
      -o, --output    Writes the skill markdown to a custom file path
  """

  use Mix.Task

  @shortdoc "Generates an AI assistant skill for Claude, OpenAI, or Gemini"

  @valid_targets ["claude", "openai", "gemini"]

  @impl Mix.Task
  def run(args) do
    {opts, pos_args, _} =
      OptionParser.parse(args,
        switches: [stdout: :boolean, output: :string],
        aliases: [o: :output]
      )

    case pos_args do
      [raw_target | _] ->
        target = String.downcase(raw_target)

        if target in @valid_targets do
          content = generate(target)

          cond do
            opts[:stdout] ->
              IO.puts(content)

            path = opts[:output] || default_output_path(target) ->
              path |> Path.dirname() |> File.mkdir_p!()
              File.write!(path, content)
              Mix.shell().info("Generated #{target} assistant skill at #{path}")
          end
        else
          raise_invalid_target(raw_target)
        end

      [] ->
        raise_missing_target()
    end
  end

  defp default_output_path("claude"), do: ".claude/skills/oeditus/SKILL.md"
  defp default_output_path("openai"), do: ".openai/skills/oeditus/SKILL.md"
  defp default_output_path("gemini"), do: ".gemini/skills/oeditus/SKILL.md"

  @spec raise_invalid_target(String.t()) :: no_return()
  defp raise_invalid_target(target) do
    Mix.raise(
      "Invalid target assistant: #{inspect(target)}. Expected one of: #{Enum.join(@valid_targets, ", ")}\n" <>
        "Usage: mix oeditus_assistant_skill <claude|openai|gemini> [--stdout] [-o PATH]"
    )
  end

  @spec raise_missing_target() :: no_return()
  defp raise_missing_target do
    Mix.raise(
      "Missing target assistant. Expected one of: #{Enum.join(@valid_targets, ", ")}\n" <>
        "Usage: mix oeditus_assistant_skill <claude|openai|gemini> [--stdout] [-o PATH]"
    )
  end

  @doc """
  Returns the full markdown content of the skill file for the specified target assistant.
  """
  @spec generate(String.t()) :: String.t()
  def generate(target) when target in @valid_targets do
    [
      frontmatter(),
      header(target),
      overview(target),
      error_handling_rules(),
      database_and_performance_rules(),
      liveview_and_concurrency_rules(),
      code_quality_rules(),
      telemetry_rules(),
      readability_rules(),
      idiomatic_refactoring_rules(),
      fsm_refactoring_rules(),
      security_injection_rules(),
      security_auth_rules(),
      security_data_protection_rules(),
      security_input_file_rules(),
      security_web_rules(),
      security_race_condition_rules(),
      standard_credo_rules(),
      footer()
    ]
    |> Enum.join("\n")
  end

  # ── Sections ──────────────────────────────────────────────────────────

  defp frontmatter do
    """
    ---
    name: oeditus
    description: Evaluates Elixir pull requests, diffs, and code snippets for Elixir-specific code smells, anti-patterns, security risks, and unidiomatic constructs, proposing idiomatic refactorings directly without external dependencies.
    ---
    """
  end

  defp header("claude") do
    """
    # Elixir PR Code Reviewer Skill (Claude Code)
    """
  end

  defp header("openai") do
    """
    # Elixir PR Code Reviewer Skill (OpenAI / Codex / ChatGPT)
    """
  end

  defp header("gemini") do
    """
    # Elixir PR Code Reviewer Skill (Google Antigravity / Gemini)
    """
  end

  defp overview(_target) do
    """
    A pure LLM-driven Skill for evaluating Elixir Pull Requests, git diffs, and source code files locally before shaping PRs. It identifies anti-patterns, explains Elixir idiomatic guidelines, and provides refactored code blocks directly without failing CI or requiring external analysis engines.

    ## Skill Overview

    When activated to review Elixir code or Pull Request changes:
    1. Directly inspect the target Elixir files (`.ex`, `.exs`) or git diffs.
    2. Evaluate the code against the **Oeditus Anti-Patterns & Refactoring Rules Catalog** below.
    3. Skip checks requiring full compilation/runtime metrics (such as coverage data or CRAP scores) and focus on pure code structure, safety, and readability.
    4. Generate a structured, actionable PR Code Review report with line numbers, explanation, and Before (`❌ Bad`)/After (`✅ Good`) code snippets.

    ---

    ## 🔍 Anti-Patterns & Refactoring Rules Catalog
    """
  end

  defp error_handling_rules do
    """
    ### 🚨 Error Handling

    #### Rule: Never pattern-match on `{:ok, _}` without handling errors
    - **Anti-Pattern**: Using `{:ok, result} = some_function()` will crash with `MatchError` if the function returns `{:error, reason}`. Always use `case` or `with` to handle both success and error tuples.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      {:ok, user} = Accounts.get_user(id)

      # ✅ Good
      case Accounts.get_user(id) do
        {:ok, user} -> user
        {:error, reason} -> handle_error(reason)
      end
      ```

    #### Rule: Always handle error branches in `case` statements
    - **Anti-Pattern**: A `case` statement that only matches `{:ok, val}` or `true` without matching `{:error, _}` or `false`/`nil` will raise `CaseClauseError` at runtime when an error occurs.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      case HTTP.get(url) do
        {:ok, response} -> process(response)
      end

      # ✅ Good
      case HTTP.get(url) do
        {:ok, response} -> process(response)
        {:error, reason} -> Logger.error("HTTP request failed: \#{inspect(reason)}")
      end
      ```

    #### Rule: Do not swallow exceptions in `try/rescue`
    - **Anti-Pattern**: Rescuing exceptions without logging or re-raising hides bugs and makes debugging impossible.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      try do
        do_work()
      rescue
        _ -> :ok
      end

      # ✅ Good
      try do
        do_work()
      rescue
        e in RuntimeError ->
          Logger.error("Failed to do work: \#{Exception.message(e)}")
          {:error, e}
      end
      ```
    """
  end

  defp database_and_performance_rules do
    """
    ### ⚡ Database & Performance

    #### Rule: Avoid N+1 database queries in loops
    - **Anti-Pattern**: Executing database queries (`Repo.get`, `Repo.one`, etc.) inside `Enum.map`, `Enum.each`, or comprehensions generates N+1 queries.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      users |> Enum.map(fn user -> Repo.get(Profile, user.profile_id) end)

      # ✅ Good
      profile_ids = Enum.map(users, & &1.profile_id)
      profiles = Repo.all(from p in Profile, where: p.id in ^profile_ids)
      ```

    #### Rule: Do not fetch all records then filter with `Enum`
    - **Anti-Pattern**: Fetching all DB records via `Repo.all/1` and filtering in memory with `Enum.filter/2` transfers unnecessary data from the database.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      Repo.all(User) |> Enum.filter(& &1.active)

      # ✅ Good
      Repo.all(from u in User, where: u.active == true)
      ```

    #### Rule: Preload associations in queries instead of accessing unloaded fields
    - **Anti-Pattern**: Accessing association fields on Ecto structs without preloading causes `Ecto.AssociationNotLoadedError`.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      user = Repo.get(User, id)
      user.posts.title

      # ✅ Good
      user = Repo.get(User, id) |> Repo.preload(:posts)
      ```
    """
  end

  defp liveview_and_concurrency_rules do
    """
    ### 🔄 LiveView & Concurrency

    #### Rule: Always supervise async tasks with `Task.Supervisor`
    - **Anti-Pattern**: Calling `Task.async/1` or `Task.start/1` directly without a supervisor creates unmanaged processes that can crash silently or leak resources.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      Task.async(fn -> do_work() end)

      # ✅ Good
      Task.Supervisor.async(MyApp.TaskSupervisor, fn -> do_work() end)
      ```

    #### Rule: Await or handle `Task.async` tasks
    - **Anti-Pattern**: Spawning `Task.async/1` without calling `Task.await/2` or `Task.yield/2` leaves caller message queues accumulating uncollected task results.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      task = Task.async(fn -> fetch_data() end)
      # task result never awaited

      # ✅ Good
      task = Task.Supervisor.async(MyApp.TaskSupervisor, fn -> fetch_data() end)
      data = Task.await(task)
      ```

    #### Rule: Avoid blocking operations in GenServer / LiveView process loops
    - **Anti-Pattern**: Synchronous HTTP requests, heavy file I/O, or DB calls inside `handle_info` or `handle_call` freeze the process loop.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      def handle_call(:fetch, _from, socket) do
        data = HTTP.get!(url)
        {:reply, data, socket}
      end

      # ✅ Good
      def handle_info(:fetch, socket) do
        task = Task.Supervisor.async(MyApp.TaskSupervisor, fn -> HTTP.get!(url) end)
        {:noreply, assign(socket, :task, task)}
      end
      ```

    #### Rule: Use `phx-debounce` or `phx-throttle` on form inputs
    - **Anti-Pattern**: Form text inputs using `phx-change` without throttling send a LiveView websocket event on every single keystroke.
    - **Refactoring**:
      ```heex
      <%!-- ❌ Bad --%>
      <input type="text" name="search" phx-change="search" />

      <%!-- ✅ Good --%>
      <input type="text" name="search" phx-change="search" phx-debounce="300" />
      ```
    """
  end

  defp code_quality_rules do
    """
    ### 🧹 Code Quality & Struct Access

    #### Rule: Do not perform direct struct updates when changesets are appropriate
    - **Anti-Pattern**: Updating Ecto struct fields directly with `%{struct | field: val}` or `Map.put` bypasses validation and field casting.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      %{user | email: new_email}

      # ✅ Good
      User.changeset(user, %{email: new_email})
      ```

    #### Rule: Prefer dot notation `struct.field` over bracket access `struct[:field]`
    - **Anti-Pattern**: Structs do not implement the `Access` protocol by default. Using `struct[:field]` raises `UndefinedFunctionError` unless `Access` is explicitly implemented.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      user[:name]

      # ✅ Good
      user.name
      ```

    #### Rule: Avoid callback hell and deeply nested `case` statements
    - **Anti-Pattern**: Nesting multiple `case` statements inside clauses obscures happy paths.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      case step1() do
        {:ok, a} ->
          case step2(a) do
            {:ok, b} -> process(b)
            error -> error
          end
        error -> error
      end

      # ✅ Good
      with {:ok, a} <- step1(),
           {:ok, b} <- step2(a) do
        process(b)
      end
      ```
    """
  end

  defp telemetry_rules do
    """
    ### 📡 Telemetry & Observability

    #### Rule: Instrument authentication/authorization plugs with telemetry
    - **Anti-Pattern**: Auth plugs should emit telemetry events in `call/2` to track login/authorization attempts and latency.

    #### Rule: Instrument external HTTP calls with telemetry
    - **Anti-Pattern**: Calling HTTP clients (`Req`, `Finch`, `HTTPoison`, `Tesla`) without `:telemetry.span/3` hides external network latency.

    #### Rule: Never emit telemetry events inside recursive loop bodies
    - **Anti-Pattern**: Calling `:telemetry.execute/3` on every iteration of a recursive function spams metrics and degrades performance. Wrap the whole call block instead.
    """
  end

  defp readability_rules do
    """
    ### 📖 Readability & Sigils

    #### Rule: Use non-interpolating (uppercase) sigils when there is no interpolation
    - **Anti-Pattern**: Using `~s`, `~c`, or `~w` when the body contains no `\#{}` expressions implies dynamic evaluation.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      ~s(static string without interpolation)

      # ✅ Good
      ~S(static string without interpolation)
      ```
    """
  end

  defp idiomatic_refactoring_rules do
    """
    ### 💡 Idiomatic Elixir Refactoring

    #### Rule: Prefer `case` pattern matching over `if` / `cond`
    - **Anti-Pattern**: Checking status tuples or structural values with `if` or `cond`.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      if result == {:ok, val} do
        process(val)
      end

      # ✅ Good
      case result do
        {:ok, val} -> process(val)
        _ -> :ok
      end
      ```

    #### Rule: Prefer multi-head function clauses over `if`/`cond` in function bodies
    - **Anti-Pattern**: Branching inside a function body on atom values or nil arguments.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      def process(action) do
        if action == :start do
          do_start()
        else
          do_stop()
        end
      end

      # ✅ Good
      def process(:start), do: do_start()
      def process(:stop), do: do_stop()
      ```

    #### Rule: Prefer pipe operator `|>` over sequential variable assignments
    - **Anti-Pattern**: Assigning single-use intermediate variables line by line.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      a = String.trim(str)
      b = String.downcase(a)

      # ✅ Good
      str |> String.trim() |> String.downcase()
      ```

    #### Rule: Avoid single-stage pipe operators `x |> f()`
    - **Anti-Pattern**: Piping a variable into a single function call (`x |> f()`) adds unnecessary noise.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      data |> process()

      # ✅ Good
      process(data)
      ```

    #### Rule: Prefer inplace `%{} = map` pattern matching over `is_map/1` guard
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      def handle(arg) when is_map(arg), do: ...

      # ✅ Good
      def handle(%{} = arg), do: ...
      ```

    #### Rule: Prefer pattern matching `[_ | _]` over `length(list) > 0` in guards
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      def process(l) when length(l) > 0, do: ...

      # ✅ Good
      def process([_ | _] = l), do: ...
      ```

    #### Rule: Prefer pattern matching `<<_::utf8, _::binary>>` over `is_binary` non-empty guards
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      def handle(s) when is_binary(s) and s != "", do: ...

      # ✅ Good
      def handle(<<_::utf8, _::binary>> = s), do: ...
      ```

    #### Rule: Prefer pattern destructuring over `elem/2` or `Map.get/2`
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      name = Map.get(user, :name)
      val = elem(tuple, 1)

      # ✅ Good
      %{name: name} = user
      {_, val} = tuple
      ```

    #### Rule: Prefer multi-head clauses matching `nil` over `is_nil/1` guards
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      def process(val) when is_nil(val), do: :default

      # ✅ Good
      def process(nil), do: :default
      ```

    #### Rule: Prefer `for` comprehensions over `Enum.filter |> Enum.map`
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      list |> Enum.filter(& &1.active) |> Enum.map(& &1.id)

      # ✅ Good
      for %{active: true, id: id} <- list, do: id
      ```

    #### Rule: Prefer prepending `[item | list]` over `list ++ [item]`
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      items ++ [new_item]

      # ✅ Good
      [new_item | items] # then Enum.reverse if order matters
      ```

    #### Rule: Prefer `String.starts_with?/2` / `String.ends_with?/2` over `Regex.match?`
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      Regex.match?(~r/^prefix_/, str)

      # ✅ Good
      String.starts_with?(str, "prefix_")
      ```

    #### Rule: Prefer capture syntax `&Module.func/1` over `fn x -> Module.func(x) end`
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      Enum.map(list, fn x -> String.trim(x) end)

      # ✅ Good
      Enum.map(list, &String.trim/1)
      ```

    #### Rule: Prefer short field capture `& &1.field` over `fn x -> x.field end`
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      Enum.map(users, fn u -> u.id end)

      # ✅ Good
      Enum.map(users, & &1.id)
      ```

    #### Rule: Prefer `Map.merge/2` over chained `Map.put` calls
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      map |> Map.put(:a, 1) |> Map.put(:b, 2)

      # ✅ Good
      Map.merge(map, %{a: 1, b: 2})
      ```
    """
  end

  defp fsm_refactoring_rules do
    """
    #### Rule: Suggest Finite State Machines for complex status transitions
    - **Anti-Pattern**: Managing complex state transitions via imperative status columns and conditional `case`/`if` branches in domain modules. Suggest using `Finitomata` or `:gen_statem`.
    """
  end

  defp security_injection_rules do
    """
    ### 🛡️ Security Rules (CWE Top 25)

    #### Rule: Prevent SQL Injection (CWE-89)
    - **Anti-Pattern**: Interpolating strings directly inside `fragment/1` or raw SQL strings in Ecto queries. Always use query parameters `^var`.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      from(u in User, where: fragment("name = '\#{user_input}'"))

      # ✅ Good
      from(u in User, where: fragment("name = ?", ^user_input))
      ```

    #### Rule: Prevent OS Command Injection (CWE-78)
    - **Anti-Pattern**: Passing untrusted user input directly into `System.cmd/3` or `:os.cmd/1`.

    #### Rule: Prevent Code Injection (CWE-94)
    - **Anti-Pattern**: Executing user-controlled strings with `Code.eval_string/3` or `Code.compile_string/2`.

    #### Rule: Prevent Cross-Site Scripting (XSS) (CWE-79)
    - **Anti-Pattern**: Wrapping unsanitized user strings in `Phoenix.HTML.raw/1` inside HEEx/LEEx templates.
    """
  end

  defp security_auth_rules do
    """
    #### Rule: Enforce Missing Authentication (CWE-306) & Authorization (CWE-862)
    - **Anti-Pattern**: Controller endpoints or LiveView routes accessible without authentication plugs or policy checks.
    - **Anti-Pattern**: Negated role checks (`if user.role != :admin`) for security authorization decisions (`CWE-863`).

    #### Rule: Prevent Insecure Direct Object References (IDOR) (CWE-639)
    - **Anti-Pattern**: Looking up DB entities using raw user parameters (`id`) without scoping to `current_user`.
    - **Refactoring**:
      ```elixir
      # ❌ Bad
      Repo.get(Document, params["id"])

      # ✅ Good
      Repo.get_by(Document, id: params["id"], user_id: current_user.id)
      ```
    """
  end

  defp security_data_protection_rules do
    """
    #### Rule: Prevent Sensitive Data Exposure (CWE-200)
    - **Anti-Pattern**: Logging passwords, API tokens, or credit card numbers, or deriving `@derive {Inspect, except: [...]}` missing secret fields.

    #### Rule: Prevent Hardcoded Credentials (CWE-798)
    - **Anti-Pattern**: Hardcoding secret keys, passwords, or tokens directly in source code. Use `System.fetch_env!/1` or `Application.compile_env/3`.

    #### Rule: Avoid Unsafe Deserialization (CWE-502)
    - **Anti-Pattern**: Calling `:erlang.binary_to_term(data)` on untrusted binary data. Use `:erlang.binary_to_term(data, [:safe])`.
    """
  end

  defp security_input_file_rules do
    """
    #### Rule: Validate Input & File Operations (CWE-20, CWE-22, CWE-434)
    - **Anti-Pattern**: Using user input directly in file path operations (`File.read`, `File.write!`) without sanitizing (`Path.expand`, `Path.basename`).
    - **Anti-Pattern**: Handling file uploads without checking file extensions, MIME types, or size limits.
    """
  end

  defp security_web_rules do
    """
    #### Rule: Enforce CSRF Protection (CWE-352) & Prevent SSRF (CWE-918)
    - **Anti-Pattern**: Router pipelines performing state changes without `:protect_from_forgery`.
    - **Anti-Pattern**: Making HTTP client requests to arbitrary user-supplied URLs without domain/IP allowlisting.
    """
  end

  defp security_race_condition_rules do
    """
    #### Rule: Avoid Time-of-Check to Time-of-Use (TOCTOU) Race Conditions (CWE-367)
    - **Anti-Pattern**: Calling `File.exists?/1` immediately followed by `File.read/1`. Perform the operation directly and handle `{:error, :enoent}`.
    """
  end

  defp standard_credo_rules do
    """
    ### ⚙️ Standard Credo Guidelines

    - Use `dbg` and `IO.inspect` only for local debugging; remove before committing.
    - Never include `IEx.pry` in committed code.
    - Do not evaluate `Application.get_env` inside module attributes `@attr`. Use `Application.compile_env/3` or move to runtime.
    - Keep line lengths under 120 characters.
    - Use `with` only when there are multiple clauses.
    """
  end

  defp footer do
    """
    ---

    *Auto-generated by `mix oeditus_assistant_skill` from OeditusCredo v#{OeditusCredo.version()}.*
    *Run `mix oeditus_assistant_skill <claude|openai|gemini>` to regenerate.*
    """
  end
end
