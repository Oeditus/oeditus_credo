defmodule OeditusCredo.Check.Refactoring.SuggestFSMTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Refactoring.SuggestFSM

  describe "SuggestFSM" do
    test "detects module with Ecto.Enum status field + case branching" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :paid, :shipped]
        end

        def process(order) do
          case order.status do
            :draft -> {:error, :not_ready}
            :pending -> :process
            :paid -> :ship
            :shipped -> {:error, :already_shipped}
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue(fn issue ->
        assert issue.message =~ "status values"
        assert issue.message =~ "Finitomata"
        assert issue.trigger == "defmodule"
      end)
    end

    test "detects module with Ecto.Enum status field + put_change transitions" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def submit(order) do
          put_change(order, :status, :pending)
        end

        def activate(order) do
          put_change(order, :status, :active)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects module with Ecto.Enum status field + verb functions" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def activate(order), do: do_activate(order)
        def deactivate(order), do: do_deactivate(order)
        defp do_activate(order), do: order
        defp do_deactivate(order), do: order
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects branching + transitions even without schema" do
      """
      defmodule MyApp.Workflow do
        def process(record) do
          case record.status do
            :new -> handle_new(record)
            :in_progress -> handle_progress(record)
            :done -> handle_done(record)
          end
        end

        def advance(record) do
          put_change(record, :status, :in_progress)
        end

        def finish(record) do
          put_change(record, :status, :done)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "ignores module with only 2 states (below threshold)" do
      """
      defmodule MyApp.Toggle do
        use Ecto.Schema

        schema "toggles" do
          field :status, Ecto.Enum, values: [:on, :off]
        end

        def toggle(t) do
          case t.status do
            :on -> put_change(t, :status, :off)
            :off -> put_change(t, :status, :on)
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> refute_issues()
    end

    test "ignores module with schema but no branching or transitions" do
      """
      defmodule MyApp.User do
        use Ecto.Schema

        schema "users" do
          field :status, Ecto.Enum, values: [:active, :inactive, :banned]
          field :name, :string
        end

        def full_name(user), do: user.name
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> refute_issues()
    end

    test "ignores module without status fields" do
      """
      defmodule MyApp.Calculator do
        def add(a, b), do: a + b
        def subtract(a, b), do: a - b
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> refute_issues()
    end

    test "skips test files when exclude_test_files is true" do
      """
      defmodule MyApp.OrderTest do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :paid]
        end

        def process(order) do
          case order.status do
            :draft -> :ok
            :pending -> :ok
            :paid -> :ok
          end
        end
      end
      """
      |> to_source_file("test/my_app/order_test.exs")
      |> run_check(SuggestFSM, exclude_test_files: true)
      |> refute_issues()
    end

    test "respects custom min_states parameter" do
      """
      defmodule MyApp.Toggle do
        use Ecto.Schema

        schema "toggles" do
          field :status, Ecto.Enum, values: [:on, :off]
        end

        def toggle(t) do
          case t.status do
            :on -> put_change(t, :status, :off)
            :off -> put_change(t, :status, :on)
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM, min_states: 2)
      |> assert_issue()
    end

    test "detects struct update syntax for status transitions" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def submit(order), do: %{order | status: :pending}
        def activate(order), do: %{order | status: :active}
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "disabled when params is false" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema
        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :paid]
        end
        def pay(o), do: put_change(o, :status, :paid)
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM, false)
      |> refute_issues()
    end
  end
end
