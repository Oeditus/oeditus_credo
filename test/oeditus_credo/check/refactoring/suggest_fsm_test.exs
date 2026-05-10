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

  describe "module attribute resolution" do
    test "detects status values from @attr with ~W sigil" do
      """
      defmodule MyApp.Experiment do
        use Ecto.Schema

        @statuses ~W(draft pending live complete cancelled)a

        schema "experiments" do
          field :status, Ecto.Enum, values: @statuses, default: :draft
        end

        def register(exp) do
          exp
          |> cast(%{}, [])
          |> put_change(:status, :pending)
        end

        def go_live(exp) do
          exp
          |> cast(%{}, [])
          |> put_change(:status, :live)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue(fn issue ->
        assert issue.message =~ "status values"
        assert issue.message =~ "Finitomata"
      end)
    end

    test "detects status values from @attr with literal list" do
      """
      defmodule MyApp.Batch do
        use Ecto.Schema

        @status_values [:current, :historic, :archived, :excluded, :pending]

        schema "batches" do
          field :status, Ecto.Enum, values: @status_values, default: :current
        end

        def archive(batch) do
          batch
          |> cast(%{}, [])
          |> put_change(:status, :archived)
        end

        def exclude(batch) do
          batch
          |> cast(%{}, [])
          |> put_change(:status, :excluded)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "ignores module attributes with fewer states than threshold" do
      """
      defmodule MyApp.Toggle do
        use Ecto.Schema

        @statuses ~W(on off)a

        schema "toggles" do
          field :status, Ecto.Enum, values: @statuses
        end

        def toggle(t) do
          case t.status do
            :on -> :off
            :off -> :on
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> refute_issues()
    end
  end

  describe "piped function calls" do
    test "detects piped put_change transitions" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :submitted, :pending, :completed]
        end

        def submit(order) do
          order
          |> cast(%{}, [])
          |> put_change(:status, :submitted)
        end

        def complete(order) do
          order
          |> cast(%{}, [])
          |> put_change(:status, :completed)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects piped change with keyword list" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def submit(order) do
          order
          |> change(status: :pending)
        end

        def activate(order) do
          order
          |> change(status: :active)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects piped force_change transitions" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def submit(order) do
          order
          |> cast(%{}, [])
          |> force_change(:status, :pending)
        end

        def activate(order) do
          order
          |> cast(%{}, [])
          |> force_change(:status, :active)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects mixed piped and non-piped put_change + branching" do
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
          record
          |> cast(%{}, [])
          |> put_change(:status, :in_progress)
        end

        def finish(record) do
          record
          |> cast(%{}, [])
          |> put_change(:status, :done)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end
  end

  describe "changeset accessor branching" do
    test "detects case get_field(changeset, :status) branching" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :live, :complete]
        end

        def validate_status(changeset) do
          case get_field(changeset, :status) do
            :draft -> changeset
            :pending -> validate_required(changeset, [:submitted_at])
            :live -> validate_required(changeset, [:live_at])
            :complete -> validate_required(changeset, [:completed_at])
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects case get_change(changeset, :status) branching" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def validate_transition(changeset) do
          case get_change(changeset, :status) do
            :draft -> changeset
            :pending -> validate_required(changeset, [:submitted_at])
            :active -> validate_required(changeset, [:activated_at])
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end

    test "detects case fetch_field!(changeset, :status) branching" do
      """
      defmodule MyApp.Order do
        use Ecto.Schema

        schema "orders" do
          field :status, Ecto.Enum, values: [:draft, :pending, :active]
        end

        def validate_transition(changeset) do
          case fetch_field!(changeset, :status) do
            :draft -> changeset
            :pending -> validate_required(changeset, [:submitted_at])
            :active -> validate_required(changeset, [:activated_at])
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end
  end

  describe "real-world patterns" do
    test "detects module attr + piped put_change (galileo ContentExperiment pattern)" do
      """
      defmodule MyApp.ContentExperiment do
        use Ecto.Schema
        import Ecto.Changeset

        @statuses ~W(draft pending live complete cancelled)a

        schema "content_experiments" do
          field :status, Ecto.Enum, values: @statuses, default: :draft
        end

        def draft_changeset(experiment, attrs) do
          experiment
          |> cast(attrs, [:name])
          |> put_change(:status, :draft)
        end

        def register_changeset(experiment, attrs) do
          experiment
          |> cast(attrs, [:name])
          |> put_change(:status, :pending)
        end

        def complete_changeset(experiment) do
          experiment
          |> cast(%{}, [])
          |> put_change(:status, :complete)
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue(fn issue ->
        assert issue.message =~ "status values"
      end)
    end

    test "detects module attr + piped put_change + get_field branching" do
      """
      defmodule MyApp.ScenarioRequest do
        use Ecto.Schema
        import Ecto.Changeset

        @statuses ~W(draft submitted pending completed failed applied expired)a

        schema "scenario_requests" do
          field :status, Ecto.Enum, values: @statuses, default: :draft
        end

        def create_draft(attrs) do
          %__MODULE__{}
          |> cast(attrs, [:name])
          |> put_change(:status, :draft)
        end

        defp validate_draft_status(changeset) do
          case get_field(changeset, :status) do
            :draft -> changeset
            _ -> add_error(changeset, :status, "must be draft")
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(SuggestFSM)
      |> assert_issue()
    end
  end
end
