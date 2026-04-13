defmodule Mix.Tasks.OeditusAssistantRules do
  @moduledoc """
  Generates `.aiassistant/rules/oeditus.md` with coding rules derived from
  OeditusCredo checks and the standard Credo checks enabled by this project.

  The generated file is intended for remote AI assistants (Copilot, Cursor,
  Cody, etc.) so they avoid producing code that would trigger credo warnings.

  ## Usage

      mix oeditus_assistant_rules            # writes to .aiassistant/rules/oeditus.md
      mix oeditus_assistant_rules --stdout   # prints to stdout instead
      mix oeditus_assistant_rules -o PATH    # writes to a custom path
  """

  use Mix.Task

  @shortdoc "Generates AI assistant rules from OeditusCredo checks"

  @default_output ".aiassistant/rules/oeditus.md"

  @impl Mix.Task
  def run(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [stdout: :boolean, output: :string],
        aliases: [o: :output]
      )

    content = generate()

    cond do
      opts[:stdout] ->
        IO.puts(content)

      path = opts[:output] || @default_output ->
        path |> Path.dirname() |> File.mkdir_p!()
        File.write!(path, content)
        Mix.shell().info("Generated AI assistant rules at #{path}")
    end
  end

  @doc """
  Returns the full markdown content of the rules file.
  """
  @spec generate() :: String.t()
  def generate do
    [
      header(),
      error_handling_rules(),
      database_and_performance_rules(),
      liveview_and_concurrency_rules(),
      code_quality_rules(),
      telemetry_rules(),
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

  defp header do
    """
    # Elixir/Phoenix Coding Rules (OeditusCredo)

    These rules are enforced by static analysis via [OeditusCredo](https://hex.pm/packages/oeditus_credo).
    Follow them to avoid credo warnings and to keep the codebase safe and idiomatic.
    """
  end

  defp error_handling_rules do
    """
    ## Error Handling

    ### Never pattern-match on `{:ok, _}` without handling errors

    Using `{:ok, result} = some_function()` will crash with `MatchError` if the
    function returns `{:error, reason}`. Always use `case` or `with` to handle
    both success and error tuples.

    Bad:
    ```elixir
    {:ok, user} = Accounts.get_user(id)
    ```

    Good:
    ```elixir
    case Accounts.get_user(id) do
      {:ok, user} -> user
      {:error, reason} -> handle_error(reason)
    end

    # or
    with {:ok, user} <- Accounts.get_user(id) do
      user
    end
    ```

    ### Always include error or catch-all clauses in case statements

    A `case` expression that only handles `{:ok, _}` without an `{:error, _}` or
    catch-all `_` clause will crash on unexpected results.

    Bad:
    ```elixir
    case Accounts.get_user(id) do
      {:ok, user} -> user
    end
    ```

    Good:
    ```elixir
    case Accounts.get_user(id) do
      {:ok, user} -> user
      {:error, reason} -> handle_error(reason)
    end
    ```

    ### Never swallow exceptions in try/rescue

    Every `rescue` clause must either log the exception or re-raise it.
    Silent rescue hides bugs and makes debugging impossible.

    Bad:
    ```elixir
    try do
      risky_operation()
    rescue
      _ -> :error
    end
    ```

    Good:
    ```elixir
    try do
      risky_operation()
    rescue
      e ->
        Logger.error("Operation failed", error: inspect(e))
        :error
    end
    ```
    """
  end

  defp database_and_performance_rules do
    """
    ## Database and Performance

    ### Never use `Repo.all()` followed by `Enum.filter/reject/find`

    Fetching all rows and filtering in Elixir wastes memory and CPU.
    Filter in the database using Ecto's `where/3`.

    Bad:
    ```elixir
    users = Repo.all(User)
    active_users = Enum.filter(users, & &1.active)
    ```

    Good:
    ```elixir
    import Ecto.Query
    active_users = User |> where([u], u.active == true) |> Repo.all()
    ```

    ### Never call Repo inside Enum.map/each/flat_map/reduce (N+1 query)

    Issuing a database query per element of a collection is an N+1 anti-pattern.
    Use `preload/2` to batch-load associations.

    Bad:
    ```elixir
    Enum.map(users, fn user ->
      Repo.get_by(Post, user_id: user.id)
    end)
    ```

    Good:
    ```elixir
    import Ecto.Query
    users = User |> preload(:posts) |> Repo.all()
    ```

    ### Always preload associations before accessing them

    When piping a query into `Repo.all()`, include `preload/2` for any
    associations that will be accessed later. Missing preloads cause
    lazy-loading N+1 queries at runtime.

    Bad:
    ```elixir
    users = User |> where([u], u.active) |> Repo.all()
    # later: user.posts triggers N+1
    ```

    Good:
    ```elixir
    users = User |> where([u], u.active) |> preload(:posts) |> Repo.all()
    ```
    """
  end

  defp liveview_and_concurrency_rules do
    """
    ## LiveView and Concurrency

    ### Use Task.Supervisor instead of bare Task.async/start

    Unmanaged tasks can leak memory if they crash or never complete.
    Always spawn tasks under a supervisor.

    Bad:
    ```elixir
    Task.async(fn -> do_work() end)
    Task.start(fn -> background_job() end)
    ```

    Good:
    ```elixir
    Task.Supervisor.async_nolink(MyApp.TaskSupervisor, fn -> do_work() end)
    Task.Supervisor.start_child(MyApp.TaskSupervisor, fn -> background_job() end)
    ```

    ### Never perform blocking I/O in LiveView/GenServer callbacks

    Calling `Repo`, HTTP clients, or `File` inside `handle_event`,
    `handle_call`, `handle_info`, `handle_cast`, or `handle_continue` blocks
    the process. Use `assign_async`, `start_async`, or background jobs.

    Bad:
    ```elixir
    def handle_event("save", params, socket) do
      user = Repo.get!(User, params["id"])
      {:noreply, assign(socket, :user, user)}
    end
    ```

    Good:
    ```elixir
    def handle_event("save", params, socket) do
      socket = assign_async(socket, :user, fn ->
        {:ok, %{user: Repo.get!(User, params["id"])}}
      end)
      {:noreply, socket}
    end
    ```

    ### Use `start_async`/`handle_async` for blocking work in handle_event

    When a LiveView `handle_event` needs to perform a blocking operation,
    delegate the work via `start_async` and handle the result in
    `handle_async`.

    Bad:
    ```elixir
    def handle_event("load", _params, socket) do
      data = Repo.all(Post)
      {:noreply, assign(socket, :posts, data)}
    end
    ```

    Good:
    ```elixir
    def handle_event("load", _params, socket) do
      {:noreply, start_async(socket, :posts, fn -> Repo.all(Post) end)}
    end

    def handle_async(:posts, {:ok, posts}, socket) do
      {:noreply, assign(socket, :posts, posts)}
    end
    ```

    ### Always add `phx-debounce` or `phx-throttle` to reactive form inputs

    Inputs with `phx-change`, `phx-keyup`, or `phx-input` fire on every
    keystroke. Add `phx-debounce` or `phx-throttle` to prevent excessive
    server events.

    Bad:
    ```html
    <input type="text" phx-change="search" />
    ```

    Good:
    ```html
    <input type="text" phx-change="search" phx-debounce="300" />
    ```

    ### Use `phx-*` bindings instead of inline JavaScript handlers

    Never use `onclick`, `onchange`, `onkeyup`, etc. in LiveView templates.
    Use Phoenix LiveView's `phx-click`, `phx-change`, and similar bindings.

    Bad:
    ```html
    <button onclick="alert('hi')">Click</button>
    ```

    Good:
    ```html
    <button phx-click="show_alert">Click</button>
    ```
    """
  end

  defp code_quality_rules do
    """
    ## Code Quality

    ### Use Ecto changesets instead of direct struct updates

    Direct struct updates (`%User{user | email: email}` or `Map.put(user, :email, email)`)
    bypass validation. Always go through changesets for data that will be persisted.

    Bad:
    ```elixir
    user = %User{user | email: new_email}
    Map.put(user, :email, new_email)
    ```

    Good:
    ```elixir
    user
    |> User.changeset(%{email: new_email})
    |> Repo.update()
    ```

    ### Flatten nested case statements with `with`

    More than 2 levels of nested `case` statements create callback hell.
    Use `with` for sequential ok/error chains.

    Bad:
    ```elixir
    case get_user(id) do
      {:ok, user} ->
        case get_account(user) do
          {:ok, account} ->
            case process(account) do
              {:ok, result} -> result
            end
        end
    end
    ```

    Good:
    ```elixir
    with {:ok, user} <- get_user(id),
         {:ok, account} <- get_account(user),
         {:ok, result} <- process(account) do
      result
    end
    ```

    ### Avoid blocking operations in Plug functions

    Expensive calls to `Repo`, HTTP clients, or `File` inside a plug
    function (any function receiving `conn` as first argument) slow down
    the entire request pipeline. Move heavy logic to the controller action
    or a background job.
    """
  end

  defp telemetry_rules do
    """
    ## Telemetry and Observability

    ### Instrument Oban worker `perform/1` with telemetry

    Every Oban worker's `perform/1` should emit `:telemetry` events
    (via `:telemetry.execute/3` or `:telemetry.span/3`) for monitoring
    job execution, duration, and success/failure rates.

    ### Instrument LiveView `mount/3` with telemetry

    LiveView `mount/3` callbacks should call `:telemetry.execute/3` or
    `:telemetry.span/3` so mounts are tracked in your observability stack.

    ### Instrument authentication/authorization plugs with telemetry

    Auth plugs (modules whose name contains "auth", "authenticate",
    "authorize", "require_user", "ensure_auth") should emit telemetry
    events in their `call/2` to track login attempts and latency.

    ### Instrument external HTTP calls with telemetry

    Wrap all calls to HTTP clients (Req, HTTPoison, Finch, Tesla, :httpc)
    with `:telemetry.span/3` so you can monitor external API latency and
    failure rates.

    ### Never emit telemetry inside recursive functions

    Telemetry emitted on every recursive call causes metric spam and
    performance degradation. Wrap the *entire* recursive operation with a
    single telemetry span instead.

    Bad:
    ```elixir
    defp process_list([head | tail]) do
      :telemetry.execute([:app, :process_item], %{})
      do_work(head)
      process_list(tail)
    end
    ```

    Good:
    ```elixir
    def process_list(items) do
      :telemetry.span([:app, :process_list], %{count: length(items)}, fn ->
        {do_process_list(items), %{}}
      end)
    end

    defp do_process_list([]), do: :ok
    defp do_process_list([head | tail]) do
      do_work(head)
      do_process_list(tail)
    end
    ```
    """
  end

  defp security_injection_rules do
    """
    ## Security -- Injection

    ### Never build SQL queries with string concatenation or interpolation

    Use parameterized queries or Ecto's query DSL. String-building SQL
    enables SQL injection (CWE-89).

    Bad:
    ```elixir
    Repo.query("SELECT * FROM users WHERE id = " <> id)
    ```

    Good:
    ```elixir
    Repo.query("SELECT * FROM users WHERE id = $1", [id])
    from(u in User, where: u.id == ^id)
    ```

    ### Never pass dynamic values as the command in System.cmd

    Always use a literal string for the executable name. Never use
    `System.shell/1` or `:os.cmd/1` -- they pass input through the OS
    shell and are vulnerable to OS command injection (CWE-78).

    Bad:
    ```elixir
    System.cmd(user_input, [])
    System.shell("ls " <> user_input)
    :os.cmd(String.to_charlist(params["cmd"]))
    ```

    Good:
    ```elixir
    System.cmd("ls", ["-la", safe_dir])
    ```

    ### Never use Code.eval_string/eval_quoted/eval_file

    Dynamic code evaluation is a code injection vector (CWE-94).
    Use pattern matching, safe parsers, or DSLs instead.

    ### Never use raw/1 or {:safe, ...} with user-controlled input

    `raw/1` and `{:safe, ...}` bypass Phoenix's HTML escaping and enable
    XSS (CWE-79). Let Phoenix auto-escape by default.

    Bad:
    ```elixir
    raw(user_input)
    {:safe, user_html}
    ```

    Good:
    ```elixir
    content_tag(:div, user_input)
    ```
    """
  end

  defp security_auth_rules do
    """
    ## Security -- Authentication and Authorization

    ### Protect controllers with authentication plugs

    Every controller with sensitive actions (index, show, create, update,
    edit, delete, destroy) must include an auth plug (CWE-306).

    Bad:
    ```elixir
    defmodule MyAppWeb.AdminController do
      use MyAppWeb, :controller
      def delete(conn, params), do: ...
    end
    ```

    Good:
    ```elixir
    defmodule MyAppWeb.AdminController do
      use MyAppWeb, :controller
      plug :require_authentication
      def delete(conn, params), do: ...
    end
    ```

    ### Always authorize before performing sensitive Repo operations

    Functions that call `Repo.delete/update/insert` must include an
    authorization check (`authorize!`, `can?`, `permit?`, `allowed?`,
    `policy`, `bodyguard`, or `current_user` reference) (CWE-862).

    ### Authorize BEFORE the sensitive operation, not after

    Authorization checks must precede the `Repo.delete!/update!/insert!`
    call in the function body. Checking *after* the operation has already
    been executed is useless (CWE-863).

    ### Always scope database lookups to the current user (prevent IDOR)

    When fetching resources by user-provided IDs with `Repo.get/get!/get_by`,
    verify ownership or authorization before returning the resource (CWE-639).

    Bad:
    ```elixir
    post = Repo.get!(Post, params["id"])
    ```

    Good:
    ```elixir
    post = Repo.get!(Post, params["id"])
    authorize!(current_user, :read, post)
    ```
    """
  end

  defp security_data_protection_rules do
    """
    ## Security -- Data Protection

    ### Never log sensitive data

    Do not pass passwords, tokens, API keys, credentials, SSNs, credit card
    numbers, JWTs, or similar fields to `Logger.*` or `IO.inspect`.
    Log only safe identifiers such as user IDs (CWE-200).

    Bad:
    ```elixir
    Logger.info("params: \#{inspect(params)}")
    IO.inspect(user.password_hash)
    ```

    Good:
    ```elixir
    Logger.info("user login", user_id: user.id)
    ```

    ### Never hardcode credentials in source code

    Passwords, API keys, tokens, and secrets must come from runtime
    configuration (`System.fetch_env!/1`, `Application.fetch_env!/2`),
    never from module attributes or variable assignments (CWE-798).

    Bad:
    ```elixir
    @api_key "sk_live_..."
    password = "super-secret"
    ```

    Good:
    ```elixir
    api_key = System.fetch_env!("API_KEY")
    ```

    ### Always pass `[:safe]` option to `:erlang.binary_to_term`

    Deserializing untrusted binaries without `:safe` can execute arbitrary
    code or construct dangerous atoms (CWE-502).

    Bad:
    ```elixir
    :erlang.binary_to_term(data)
    ```

    Good:
    ```elixir
    :erlang.binary_to_term(data, [:safe])
    ```
    """
  end

  defp security_input_file_rules do
    """
    ## Security -- Input and File Handling

    ### Always validate user input before sensitive operations

    Controller actions must validate/sanitize params through changesets or
    explicit validation before passing them to `Repo.insert/update/delete`
    (CWE-20).

    Bad:
    ```elixir
    def create(conn, %{"name" => name}) do
      Repo.insert!(%User{name: name})
    end
    ```

    Good:
    ```elixir
    def create(conn, params) do
      %User{}
      |> User.changeset(params)
      |> Repo.insert()
    end
    ```

    ### Never build file paths from user input without sanitization

    Use `Path.basename/1` to strip directory components before joining
    paths. Raw concatenation enables path traversal (CWE-22).

    Bad:
    ```elixir
    File.read!(params["file"])
    File.write!("/tmp/" <> filename, content)
    ```

    Good:
    ```elixir
    safe = Path.basename(filename)
    File.read!(Path.join("/safe/dir", safe))
    ```

    ### Validate file type before writing uploads

    Upload handlers must check `content_type`, file extension, or MIME type
    before writing to disk. Unrestricted upload of dangerous file types is
    CWE-434.

    Bad:
    ```elixir
    File.cp!(upload.path, "/uploads/\#{upload.filename}")
    ```

    Good:
    ```elixir
    ext = Path.extname(upload.filename) |> String.downcase()
    if ext in @allowed_extensions, do: ...
    ```
    """
  end

  defp security_web_rules do
    """
    ## Security -- Web

    ### Enable CSRF protection on all state-changing routes

    API pipelines that handle POST/PUT/PATCH/DELETE requests should include
    `:protect_from_forgery`. Never call `Plug.Conn.delete_csrf_token/1` or
    set `:plug_skip_csrf_protection` (CWE-352).

    ### Never make HTTP requests to user-controlled URLs (SSRF)

    Validate the host/domain of any URL received from user input against an
    allowlist before making outbound HTTP requests. Unvalidated URLs expose
    internal services and cloud metadata endpoints (CWE-918).

    Bad:
    ```elixir
    HTTPoison.get(params["url"])
    ```

    Good:
    ```elixir
    uri = URI.parse(url)
    if uri.host in @allowed_hosts, do: HTTPoison.get(url)
    ```
    """
  end

  defp security_race_condition_rules do
    """
    ## Security -- Race Conditions

    ### Never check `File.exists?` then operate on the file (TOCTOU)

    Between the check and the use, the file can be modified or deleted.
    Use the file operation directly and handle `{:error, :enoent}` (CWE-367).

    Bad:
    ```elixir
    if File.exists?(path) do
      {:ok, data} = File.read(path)
    end
    ```

    Good:
    ```elixir
    case File.read(path) do
      {:ok, data} -> process(data)
      {:error, :enoent} -> handle_missing()
    end
    ```
    """
  end

  defp standard_credo_rules do
    """
    ## Standard Credo Rules

    These additional rules come from the standard Credo checks enabled in
    the project.

    ### Use `match?/2` or pattern matching instead of `length/1` for emptiness checks

    `length/1` traverses the entire list and is O(n). To check whether a
    list is non-empty, use pattern matching or `match?/2`.

    Bad:
    ```elixir
    length(list) > 0
    length(list) == 0
    Enum.empty?(list)
    ```

    Good:
    ```elixir
    match?([_ | _], list)   # non-empty
    match?([], list)         # empty
    list == []               # empty (also fine)
    ```

    ### Prefer `Enum.count/2` over `Enum.filter |> length`

    Chaining `Enum.filter/2` into `length/1` creates an intermediate list.
    Use `Enum.count/2` instead.

    ### Prefer `Enum.into/3` over `Enum.map |> Enum.into`

    Fuse `Enum.map/2 |> Enum.into/2` into a single `Enum.into/3` call to
    avoid the intermediate list.

    ### Use `dbg` and `IO.inspect` only for debugging; remove before commit

    `dbg/1` and `IO.inspect/1` must not appear in committed code.

    ### Never use `IEx.pry` in committed code

    `IEx.pry` blocks the process and must be removed before committing.

    ### Do not read Application config in module attributes

    Module attributes are evaluated at compile time. Use
    `Application.compile_env/3` or move the call to runtime.

    ### Keep function arity low

    Functions with too many parameters are hard to use and test.
    Prefer passing a map, keyword list, or struct.

    ### Avoid deeply nested code

    Keep nesting at a maximum of 4 levels. Extract helper functions or
    use `with` to flatten deep nesting.

    ### Follow consistent naming conventions

    - Modules: `CamelCase`
    - Functions and variables: `snake_case`
    - Predicate functions: must start with `is_` or end with `?`
    - Exceptions: must end with `Error`

    ### Keep lines under 120 characters

    The configured maximum line length is 120. Break long lines at
    operators, pipes, or after opening brackets.

    ### Use `with` only when there are multiple clauses

    A `with` statement with a single clause is harder to read than a
    simple `case` or pattern match.
    """
  end

  defp footer do
    """
    ---

    *Auto-generated by `mix oeditus_assistant_rules` from OeditusCredo v#{OeditusCredo.version()}.*
    *Do not edit manually -- re-run the task to regenerate.*
    """
  end
end
