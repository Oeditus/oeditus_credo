defmodule OeditusCredo.Check.Refactoring.IdiomaticSmellsTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Refactoring.{
    PreferCasePatternMatching,
    PreferMultiHeadFunction,
    PreferPipelineOperator,
    PreferInplaceMapMatching,
    PreferInplaceListMatching,
    PreferInplaceBinaryMatching
  }

  describe "PreferCasePatternMatching" do
    test "reports if checking pattern equality" do
      """
      defmodule Test do
        def check(res) do
          if res == {:ok, :active} do
            :ok
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferCasePatternMatching)
      |> assert_issue()
    end

    test "reports if condition checking atom literal" do
      """
      defmodule Test do
        def check(mode) do
          if mode == :fast do
            :ok
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferCasePatternMatching)
      |> assert_issue()
    end

    test "reports tuple elem check" do
      """
      defmodule Test do
        def check(tuple) do
          if elem(tuple, 0) == :ok do
            :ok
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferCasePatternMatching)
      |> assert_issue()
    end

    test "reports cond repeatedly checking equality on same variable" do
      """
      defmodule Test do
        def check(status) do
          cond do
            status == :pending -> :wait
            status == :active -> :go
            true -> :stop
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferCasePatternMatching)
      |> assert_issue()
    end

    test "does not report case pattern matching" do
      """
      defmodule Test do
        def check(res) do
          case res do
            {:ok, :active} -> :ok
            _ -> :error
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferCasePatternMatching)
      |> refute_issues()
    end

    test "does not report general numeric comparisons in if" do
      """
      defmodule Test do
        def check(count) do
          if count > 10 do
            :many
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferCasePatternMatching)
      |> refute_issues()
    end
  end

  describe "PreferMultiHeadFunction" do
    test "reports if inside function body checking arg" do
      """
      defmodule Test do
        def process(mode) do
          if mode == :fast do
            :fast
          else
            :slow
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferMultiHeadFunction)
      |> assert_issue()
    end

    test "reports cond inside function body dispatching on arg" do
      """
      defmodule Test do
        def process(type) do
          cond do
            type == :a -> 1
            type == :b -> 2
            true -> 0
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferMultiHeadFunction)
      |> assert_issue()
    end

    test "does not report multi-head function definitions" do
      """
      defmodule Test do
        def process(:fast), do: :fast
        def process(:slow), do: :slow
      end
      """
      |> to_source_file()
      |> run_check(PreferMultiHeadFunction)
      |> refute_issues()
    end

    test "does not report if checking local non-parameter variable" do
      """
      defmodule Test do
        def process(opts) do
          count = Enum.count(opts)
          if count > 5 do
            :large
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferMultiHeadFunction)
      |> refute_issues()
    end
  end

  describe "PreferPipelineOperator" do
    test "reports sequential assignments passing prev var" do
      """
      defmodule Test do
        def run(input) do
          a = String.trim(input)
          b = String.downcase(a)
          c = String.reverse(b)
          c
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferPipelineOperator)
      |> assert_issue()
    end

    test "reports sequential module function assignments" do
      """
      defmodule Test do
        def run(data) do
          x = MyApp.clean(data)
          y = MyApp.format(x)
          y
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferPipelineOperator)
      |> assert_issue()
    end

    test "does not report pipeline operator usage" do
      """
      defmodule Test do
        def run(input) do
          input
          |> String.trim()
          |> String.downcase()
          |> String.reverse()
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferPipelineOperator)
      |> refute_issues()
    end

    test "does not report unrelated assignments" do
      """
      defmodule Test do
        def run(input, other) do
          a = String.trim(input)
          b = String.downcase(other)
          {a, b}
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferPipelineOperator)
      |> refute_issues()
    end
  end

  describe "PreferInplaceMapMatching" do
    test "reports is_map guard" do
      """
      defmodule Test do
        def handle(opts) when is_map(opts) do
          opts
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceMapMatching)
      |> assert_issue()
    end

    test "reports is_map in compound guard" do
      """
      defmodule Test do
        def handle(opts, user) when is_binary(user) and is_map(opts) do
          {opts, user}
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceMapMatching)
      |> assert_issue()
    end

    test "does not report map pattern matching in parameter list" do
      """
      defmodule Test do
        def handle(%{} = opts) do
          opts
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceMapMatching)
      |> refute_issues()
    end

    test "does not report other guards" do
      """
      defmodule Test do
        def handle(opts) when is_list(opts) do
          opts
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceMapMatching)
      |> refute_issues()
    end
  end

  describe "PreferInplaceListMatching" do
    test "reports length(list) > 0 in guard" do
      """
      defmodule Test do
        def handle(items) when length(items) > 0 do
          items
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceListMatching)
      |> assert_issue()
    end

    test "reports length(list) == 0 in guard" do
      """
      defmodule Test do
        def handle(items) when length(items) == 0 do
          items
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceListMatching)
      |> assert_issue()
    end

    test "reports 0 < length(list) in guard" do
      """
      defmodule Test do
        def handle(items) when 0 < length(items) do
          items
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceListMatching)
      |> assert_issue()
    end

    test "reports length(list) != 0 in guard" do
      """
      defmodule Test do
        def handle(items) when length(items) != 0 do
          items
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceListMatching)
      |> assert_issue()
    end

    test "does not report list pattern matching" do
      """
      defmodule Test do
        def handle([_ | _] = items) do
          items
        end

        def handle([]) do
          :empty
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceListMatching)
      |> refute_issues()
    end

    test "reports length check for specific count" do
      """
      defmodule Test do
        def handle(items) when length(items) == 3 do
          items
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceListMatching)
      |> assert_issue()
    end
  end

  describe "PreferInplaceBinaryMatching" do
    test "reports is_binary and non-empty guard" do
      """
      defmodule Test do
        def handle(str) when is_binary(str) and str != "" do
          str
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceBinaryMatching)
      |> assert_issue()
    end

    test "reports is_binary and byte_size > 0 guard" do
      """
      defmodule Test do
        def handle(str) when is_binary(str) and byte_size(str) > 0 do
          str
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceBinaryMatching)
      |> assert_issue()
    end

    test "reports byte_size > 0 and is_binary guard" do
      """
      defmodule Test do
        def handle(str) when byte_size(str) > 0 and is_binary(str) do
          str
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceBinaryMatching)
      |> assert_issue()
    end

    test "reports non-empty and is_binary guard" do
      """
      defmodule Test do
        def handle(str) when "" != str and is_binary(str) do
          str
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceBinaryMatching)
      |> assert_issue()
    end

    test "does not report binary pattern matching in parameter list" do
      """
      defmodule Test do
        def handle(<<_::utf8, _::binary>> = str) do
          str
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceBinaryMatching)
      |> refute_issues()
    end

    test "does not report is_binary guard alone without non-empty check" do
      """
      defmodule Test do
        def handle(str) when is_binary(str) do
          str
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferInplaceBinaryMatching)
      |> refute_issues()
    end
  end
end

