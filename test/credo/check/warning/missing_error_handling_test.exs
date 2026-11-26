defmodule OeditusCredo.Check.Warning.MissingErrorHandlingTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Warning.MissingErrorHandling

  test "it should NOT report issue for case with error handling" do
    """
    defmodule MyModule do
      def example do
        case Accounts.get_user(1) do
          {:ok, user} -> user
          {:error, _} -> nil
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for with statement" do
    """
    defmodule MyModule do
      def example do
        with {:ok, user} <- Accounts.get_user(1) do
          user
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should report issue for direct pattern match on :ok tuple" do
    """
    defmodule MyModule do
      def example do
        {:ok, user} = Accounts.get_user(1)
        user
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> assert_issue()
  end

  test "it should report issue for two-element :ok tuple pattern match" do
    """
    defmodule MyModule do
      def example(id) do
        {:ok, result} = fetch_data(id)
        result
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> assert_issue()
  end

  test "it should NOT report issue for pattern match in function head" do
    """
    defmodule MyModule do
      def example({:ok, value}) do
        value
      end

      def example({:error, _reason}) do
        nil
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for non-ok tuple pattern match" do
    """
    defmodule MyModule do
      def example do
        {:some, :tuple} = get_data()
        :tuple
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in case clause pattern with an error clause" do
    """
    defmodule MyModule do
      def example do
        case start_link(opts) do
          {:ok, _} = resp ->
            init()
            resp

          error ->
            error
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in fn clause pattern" do
    """
    defmodule MyModule do
      def example do
        receive do
          {:ok, value} = msg -> value
          {:error, _} = err -> err
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in def clause pattern" do
    """
    defmodule MyModule do
      def example({:ok, value} = result) do
        value
      end

      def example({:error, _reason} = error) do
        error
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in with <- pattern" do
    """
    defmodule MyModule do
      def example do
        with {:ok, _} = resp <- start_call() do
          resp
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in with else clause pattern" do
    """
    defmodule MyModule do
      def example do
        with {:ok, value} <- fetch(1) do
          value
        else
          {:error, reason} = err -> err
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in for generator pattern" do
    """
    defmodule MyModule do
      def example(list) do
        for {:ok, value} = item <- list do
          value
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should STILL report issue for bad match inside a clause body" do
    """
    defmodule MyModule do
      def example do
        case fetch(1) do
          {:ok, value} ->
            {:ok, result} = transform(value)
            result

          {:error, _} ->
            nil
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> assert_issue()
  end

  test "it should NOT report issue for match in defmacro head" do
    """
    defmodule MyModule do
      defmacro example({:ok, value} = result) do
        value
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in defmacrop head" do
    """
    defmodule MyModule do
      defmacrop example({:ok, value} = result) do
        value
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in defguard head" do
    """
    defmodule MyModule do
      defguard is_ok({:ok, value} = result) when is_integer(value)
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in defguardp head" do
    """
    defmodule MyModule do
      defguardp is_ok({:ok, value} = result) when is_integer(value)
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in defdelegate head" do
    """
    defmodule MyModule do
      defdelegate example({:ok, value} = result), to: Other
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should NOT report issue for match in guarded def head" do
    """
    defmodule MyModule do
      def example({:ok, value} = result) when is_integer(value) do
        value
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> refute_issues()
  end

  test "it should STILL report issue for bad match in a guarded def body" do
    """
    defmodule MyModule do
      def example(value) when is_integer(value) do
        {:ok, result} = transform(value)
        result
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> assert_issue()
  end

  test "it should STILL report issue for bad match in a defmacro body" do
    """
    defmodule MyModule do
      defmacro example(ast) do
        {:ok, result} = transform(ast)
        result
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingErrorHandling)
    |> assert_issue()
  end
end
