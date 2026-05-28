defmodule OeditusCredo.Check.Warning.TelemetryChecksTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Warning.{
    MissingTelemetryForExternalHttp,
    MissingTelemetryInAuthPlug,
    MissingTelemetryInObanWorker,
    TelemetryInRecursiveFunction
  }

  # MissingTelemetryInObanWorker tests

  test "MissingTelemetryInObanWorker: reports issue for worker without telemetry" do
    """
    defmodule MyApp.Worker do
      use Oban.Worker

      def perform(%Oban.Job{args: args}) do
        do_work(args)
        :ok
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInObanWorker)
    |> assert_issue()
  end

  test "MissingTelemetryInObanWorker: no issue when telemetry.span is used" do
    """
    defmodule MyApp.Worker do
      use Oban.Worker

      def perform(%Oban.Job{args: args}) do
        :telemetry.span([:oban, :job, :execute], %{worker: __MODULE__}, fn ->
          result = do_work(args)
          {result, %{}}
        end)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInObanWorker)
    |> refute_issues()
  end

  test "MissingTelemetryInObanWorker: no issue when telemetry.execute is used" do
    """
    defmodule MyApp.Worker do
      use Oban.Worker

      def perform(%Oban.Job{args: args}) do
        :telemetry.execute([:oban, :job], %{}, %{worker: __MODULE__})
        do_work(args)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInObanWorker)
    |> refute_issues()
  end

  # TelemetryInRecursiveFunction tests

  test "TelemetryInRecursiveFunction: reports issue for telemetry in recursive function" do
    """
    defmodule MyApp.Processor do
      defp process_list([head | tail]) do
        :telemetry.execute([:app, :process], %{})
        do_work(head)
        process_list(tail)
      end

      defp process_list([]), do: :ok
    end
    """
    |> to_source_file()
    |> run_check(TelemetryInRecursiveFunction)
    |> assert_issue()
  end

  test "TelemetryInRecursiveFunction: no issue for non-recursive function with telemetry" do
    """
    defmodule MyApp.Processor do
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
    end
    """
    |> to_source_file()
    |> run_check(TelemetryInRecursiveFunction)
    |> refute_issues()
  end

  test "TelemetryInRecursiveFunction: reports issue for recursive factorial with telemetry" do
    """
    defmodule Math do
      def factorial(0), do: 1
      def factorial(n) do
        :telemetry.execute([:math, :factorial], %{n: n})
        n * factorial(n - 1)
      end
    end
    """
    |> to_source_file()
    |> run_check(TelemetryInRecursiveFunction)
    |> assert_issue()
  end

  # MissingTelemetryInAuthPlug tests

  test "MissingTelemetryInAuthPlug: reports issue for auth plug without telemetry" do
    """
    defmodule MyAppWeb.Plugs.Authenticate do
      import Plug.Conn

      def call(conn, _opts) do
        case verify_token(conn) do
          {:ok, user} -> assign(conn, :current_user, user)
          {:error, _} -> halt(conn)
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInAuthPlug)
    |> assert_issue()
  end

  test "MissingTelemetryInAuthPlug: no issue when telemetry is present" do
    """
    defmodule MyAppWeb.Plugs.Authenticate do
      import Plug.Conn

      def call(conn, _opts) do
        :telemetry.execute([:auth, :verify], %{}, %{})
        case verify_token(conn) do
          {:ok, user} -> assign(conn, :current_user, user)
          {:error, _} -> halt(conn)
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInAuthPlug)
    |> refute_issues()
  end

  test "MissingTelemetryInAuthPlug: detects authorize plug" do
    """
    defmodule MyAppWeb.Plugs.EnsureAuthorized do
      def call(conn, _opts) do
        check_permissions(conn)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInAuthPlug)
    |> assert_issue()
  end

  test "MissingTelemetryInAuthPlug: ignores non-auth plugs" do
    """
    defmodule MyAppWeb.Plugs.Logger do
      def call(conn, _opts) do
        IO.inspect(conn)
        conn
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryInAuthPlug)
    |> refute_issues()
  end

  # MissingTelemetryForExternalHttp tests

  test "MissingTelemetryForExternalHttp: reports issue for Req.get without telemetry" do
    """
    defmodule MyApp.Client do
      def fetch_user(id) do
        Req.get!("https://api.example.com/users/\#{id}")
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryForExternalHttp)
    |> assert_issue()
  end

  test "MissingTelemetryForExternalHttp: no issue when telemetry wraps HTTP call" do
    """
    defmodule MyApp.Client do
      def fetch_user(id) do
        :telemetry.span([:http, :request], %{}, fn ->
          result = Req.get!("https://api.example.com/users/\#{id}")
          {result, %{}}
        end)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryForExternalHttp)
    |> refute_issues()
  end

  test "MissingTelemetryForExternalHttp: detects HTTPoison calls" do
    """
    defmodule MyApp.Client do
      def fetch_data do
        HTTPoison.get!("https://api.example.com/data")
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryForExternalHttp)
    |> assert_issue()
  end

  test "MissingTelemetryForExternalHttp: detects Finch calls" do
    """
    defmodule MyApp.Client do
      def fetch_data do
        Finch.request!(req, MyApp.Finch)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryForExternalHttp)
    |> assert_issue()
  end

  test "MissingTelemetryForExternalHttp: no issue for functions without HTTP calls" do
    """
    defmodule MyApp.Client do
      def process_data(data) do
        String.upcase(data)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingTelemetryForExternalHttp)
    |> refute_issues()
  end
end
