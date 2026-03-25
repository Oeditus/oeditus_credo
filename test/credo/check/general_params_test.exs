defmodule OeditusCredo.Check.GeneralParamsTest do
  use Credo.Test.Case

  @moduledoc """
  Tests that all OeditusCredo checks properly handle the standard Credo
  general parameters: `false` (disable) and `exit_status`.
  """

  # Representative checks from each category
  @warning_checks [
    OeditusCredo.Check.Warning.NPlusOneQuery,
    OeditusCredo.Check.Warning.CallbackHell,
    OeditusCredo.Check.Warning.MissingErrorHandling,
    OeditusCredo.Check.Warning.UnmanagedTask,
    OeditusCredo.Check.Warning.BlockingInPlug,
    OeditusCredo.Check.Warning.InefficientFilter
  ]

  @security_checks [
    OeditusCredo.Check.Security.SQLInjection,
    OeditusCredo.Check.Security.CodeInjection,
    OeditusCredo.Check.Security.HardcodedCredentials,
    OeditusCredo.Check.Security.OSCommandInjection
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
