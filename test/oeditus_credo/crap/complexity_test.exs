defmodule OeditusCredo.Crap.ComplexityTest do
  use ExUnit.Case, async: true

  alias OeditusCredo.Crap.Complexity

  describe "from_string/1" do
    test "returns base complexity for a discovered function" do
      source = """
      defmodule Example do
        def greet(name) do
          "hello " <> name
        end
      end
      """

      assert {:ok, [%{module: Example, function: :greet, arity: 1, line: 2, complexity: 1}]} =
               Complexity.from_string(source)
    end

    test "returns invalid_source for syntactically invalid source" do
      assert Complexity.from_string("defmodule") == {:error, :invalid_source}
    end

    test "returns invalid_source for non-string source" do
      assert Complexity.from_string(nil) == {:error, :invalid_source}
    end

    test "counts if, unless, and boolean operators as decision points" do
      source = """
      defmodule Example do
        def visible?(user) do
          if user.active and user.confirmed do
            true
          else
            unless user.suspended or user.deleted do
              true
            end
          end
        end
      end
      """

      assert {:ok, [%{complexity: 5}]} = Complexity.from_string(source)
    end

    test "counts symbolic boolean operators as decision points" do
      source = """
      defmodule Example do
        def allowed?(user) do
          user.active? && user.confirmed? || user.admin?
        end
      end
      """

      assert {:ok, [%{complexity: 3}]} = Complexity.from_string(source)
    end

    test "counts guard boolean operators as decision points" do
      source = """
      defmodule Example do
        def valid?(value) when is_binary(value) and byte_size(value) > 0 do
          true
        end
      end
      """

      assert {:ok, [%{complexity: 2}]} = Complexity.from_string(source)
    end

    test "counts each case branch and cond clause as a decision point" do
      source = """
      defmodule Example do
        def classify(value) do
          case value do
            0 -> :zero
            1 -> :one
            _ -> :many
          end

          cond do
            value < 0 -> :negative
            value > 0 -> :positive
            true -> :zero
          end
        end
      end
      """

      assert {:ok, [%{complexity: 7}]} = Complexity.from_string(source)
    end

    test "counts with else clauses as decision points" do
      source = """
      defmodule Example do
        def load(params) do
          with {:ok, id} <- Map.fetch(params, :id),
               {:ok, user} <- fetch_user(id) do
            {:ok, user}
          else
            :error -> {:error, :missing_id}
            {:error, reason} -> {:error, reason}
          end
        end
      end
      """

      assert {:ok, [%{complexity: 5}]} = Complexity.from_string(source)
    end

    test "counts try rescue and catch as decision points" do
      source = """
      defmodule Example do
        def safe(fun) do
          try do
            fun.()
          rescue
            ArgumentError -> :bad_argument
            RuntimeError -> :runtime
          catch
            :exit, _reason -> :exit
          after
            :ok
          end
        end
      end
      """

      assert {:ok, [%{complexity: 5}]} = Complexity.from_string(source)
    end

    test "aggregates multiple clauses of the same function by summing complexity" do
      source = """
      defmodule Example do
        def f(0), do: :zero
        def f(n) when n > 0, do: :pos
        def f(_), do: :neg
      end
      """

      assert {:ok, [%{module: Example, function: :f, arity: 1, complexity: 3}]} =
               Complexity.from_string(source)
    end
  end
end
