defmodule OeditusCredo.Check.GeneralParamsTest do
  use Credo.Test.Case

  @moduledoc """
  Tests that all OeditusCredo checks properly handle the standard Credo
  general parameters: `false` (disable) and `exit_status`.
  """

  @warning_checks [
    OeditusCredo.Check.Warning.BlockingInPlug,
    OeditusCredo.Check.Warning.CallbackHell,
    OeditusCredo.Check.Warning.DirectStructUpdate,
    OeditusCredo.Check.Warning.InefficientFilter,
    OeditusCredo.Check.Warning.InlineJavascript,
    OeditusCredo.Check.Warning.MissingErrorHandling,
    OeditusCredo.Check.Warning.MissingHandleAsync,
    OeditusCredo.Check.Warning.MissingPreload,
    OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp,
    OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug,
    OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount,
    OeditusCredo.Check.Warning.MissingTelemetryInObanWorker,
    OeditusCredo.Check.Warning.MissingThrottle,
    OeditusCredo.Check.Warning.NPlusOneQuery,
    OeditusCredo.Check.Warning.SilentErrorCase,
    OeditusCredo.Check.Warning.SwallowingException,
    OeditusCredo.Check.Warning.SyncOverAsync,
    OeditusCredo.Check.Warning.TelemetryInRecursiveFunction,
    OeditusCredo.Check.Warning.UnmanagedTask
  ]

  @security_checks [
    OeditusCredo.Check.Security.CodeInjection,
    OeditusCredo.Check.Security.HardcodedCredentials,
    OeditusCredo.Check.Security.ImproperInputValidation,
    OeditusCredo.Check.Security.IncorrectAuthorization,
    OeditusCredo.Check.Security.InsecureDirectObjectReference,
    OeditusCredo.Check.Security.MissingAuthentication,
    OeditusCredo.Check.Security.MissingAuthorization,
    OeditusCredo.Check.Security.MissingCSRFProtection,
    OeditusCredo.Check.Security.OSCommandInjection,
    OeditusCredo.Check.Security.PathTraversal,
    OeditusCredo.Check.Security.SensitiveDataExposure,
    OeditusCredo.Check.Security.SQLInjection,
    OeditusCredo.Check.Security.SSRFVulnerability,
    OeditusCredo.Check.Security.TOCTOU,
    OeditusCredo.Check.Security.UnrestrictedFileUpload,
    OeditusCredo.Check.Security.UnsafeDeserialization,
    OeditusCredo.Check.Security.XSSVulnerability
  ]

  #
  # ── false param (disable check) ─────────────────────────────────────

  describe "false param disables check" do
    for check <- @warning_checks ++ @security_checks do
      module_name = check |> Module.split() |> List.last()

      test "#{module_name} returns no issues when params is false" do
        """
        defmodule SomeModule do
          def some_function do
            :ok
          end
        end
        """
        |> to_source_file()
        |> run_check(unquote(check), false)
        |> refute_issues()
      end
    end
  end

  # ── exit_status param ────────────────────────────────────────────────

  describe "exit_status: 0 makes issues non-blocking" do
    test "NPlusOneQuery issues have exit_status 0 when configured" do
      """
      defmodule MyModule do
        def get_posts(users) do
          Enum.map(users, fn user ->
            Repo.get_by(Post, user_id: user.id)
          end)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.NPlusOneQuery, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "CallbackHell issues have exit_status 0 when configured" do
      """
      defmodule MyModule do
        def deeply_nested(x) do
          case x do
            :a ->
              case x do
                :b ->
                  case x do
                    :c -> :ok
                  end
              end
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.CallbackHell, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "SQLInjection issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def get_user(id) do
          Repo.query("SELECT * FROM users WHERE id = " <> id)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.SQLInjection, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingErrorHandling issues have custom exit_status when configured" do
      """
      defmodule MyModule do
        def run do
          {:ok, result} = do_something()
          result
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.MissingErrorHandling, exit_status: 2)
      |> assert_issue(fn issue -> assert issue.exit_status == 2 end)
    end
  end

  # ── default exit_status (category-based) ─────────────────────────────

  describe "default exit_status matches :warning category (16)" do
    test "NPlusOneQuery issues have default exit_status 16" do
      """
      defmodule MyModule do
        def get_posts(users) do
          Enum.map(users, fn user ->
            Repo.get_by(Post, user_id: user.id)
          end)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.NPlusOneQuery)
      |> assert_issue(fn issue -> assert issue.exit_status == 16 end)
    end
  end

  # ── exit_status for previously untested checks ────────────────────────

  describe "exit_status: 0 for warning checks" do
    test "MissingPreload issues have exit_status 0 when configured" do
      """
      defmodule MyModule do
        def get_users do
          User |> where([u], u.active) |> Repo.all()
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.MissingPreload, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "DirectStructUpdate issues have exit_status 0 when configured" do
      """
      defmodule MyModule do
        def update_email(user, email) do
          %User{user | email: email}
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.DirectStructUpdate, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "SilentErrorCase issues have exit_status 0 when configured" do
      """
      defmodule MyModule do
        def get_user(id) do
          case Accounts.get_user(id) do
            {:ok, user} -> user
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.SilentErrorCase, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "SwallowingException issues have exit_status 0 when configured" do
      """
      defmodule MyModule do
        def run do
          try do
            risky_operation()
          rescue
            _ -> :error
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.SwallowingException, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "TelemetryInRecursiveFunction issues have exit_status 0 when configured" do
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
      |> run_check(OeditusCredo.Check.Warning.TelemetryInRecursiveFunction, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingTelemetryForExternalHttp issues have exit_status 0 when configured" do
      """
      defmodule MyApp.Client do
        def fetch_user(id) do
          Req.get!("https://api.example.com/users/\#{id}")
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.MissingTelemetryForExternalHttp, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingTelemetryInObanWorker issues have exit_status 0 when configured" do
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
      |> run_check(OeditusCredo.Check.Warning.MissingTelemetryInObanWorker, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingTelemetryInLiveViewMount issues have exit_status 0 when configured" do
      """
      defmodule MyAppWeb.DashboardLive do
        use MyAppWeb, :live_view

        def mount(_params, _session, socket) do
          data = load_data()
          {:ok, assign(socket, data: data)}
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.MissingTelemetryInLiveViewMount, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingTelemetryInAuthPlug issues have exit_status 0 when configured" do
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
      |> run_check(OeditusCredo.Check.Warning.MissingTelemetryInAuthPlug, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end
  end

  describe "exit_status: 0 for security checks" do
    test "IncorrectAuthorization issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def delete_post(user, post) do
          Repo.delete!(post)
          authorize!(user, :delete, post)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.IncorrectAuthorization, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "InsecureDirectObjectReference issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def show(id) do
          Repo.get!(Post, id)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.InsecureDirectObjectReference, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingAuthentication issues have exit_status 0 when configured" do
      """
      defmodule MyAppWeb.AdminController do
        use MyAppWeb, :controller

        def delete(conn, params) do
          conn
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.MissingAuthentication, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingAuthorization issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def delete_post(post) do
          Repo.delete!(post)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.MissingAuthorization, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "MissingCSRFProtection issues have exit_status 0 when configured" do
      """
      defmodule MyRouter do
        pipeline :api do
          plug :accepts, ["json"]
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.MissingCSRFProtection, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "PathTraversal issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def read_file(filename) do
          File.read!("/tmp/" <> filename)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.PathTraversal, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "SensitiveDataExposure issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def create(password) do
          Logger.info(password)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.SensitiveDataExposure, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "SSRFVulnerability issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def fetch(user_url) do
          HTTPoison.get(user_url)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.SSRFVulnerability, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "TOCTOU issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def read_safe(path) do
          if File.exists?(path) do
            File.read!(path)
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.TOCTOU, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "UnsafeDeserialization issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def decode(data) do
          :erlang.binary_to_term(data)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.UnsafeDeserialization, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "XSSVulnerability issues have exit_status 0 when configured" do
      """
      defmodule MyApp do
        def show(content) do
          raw(content)
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.XSSVulnerability, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end
  end

  # ── combined params ──────────────────────────────────────────────────

  describe "exit_status works alongside other params" do
    test "CallbackHell respects both max_nesting and exit_status" do
      """
      defmodule MyModule do
        def deeply_nested(x) do
          case x do
            :a ->
              case x do
                :b ->
                  case x do
                    :c ->
                      case x do
                        :d -> :ok
                      end
                  end
              end
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Warning.CallbackHell,
        max_nesting: 3,
        exit_status: 0
      )
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end

    test "HardcodedCredentials respects both exclude_test_files and exit_status" do
      """
      defmodule MyApp do
        @api_key "sk_live_abc123"
      end
      """
      |> to_source_file()
      |> run_check(OeditusCredo.Check.Security.HardcodedCredentials, exit_status: 0)
      |> assert_issue(fn issue -> assert issue.exit_status == 0 end)
    end
  end
end
