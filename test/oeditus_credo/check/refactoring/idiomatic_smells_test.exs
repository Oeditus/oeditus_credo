defmodule OeditusCredo.Check.Refactoring.IdiomaticSmellsTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Refactoring.{
    PreferCasePatternMatching,
    PreferMultiHeadFunction,
    PreferPipelineOperator,
    PreferInplaceMapMatching,
    PreferInplaceListMatching,
    PreferInplaceBinaryMatching,
    PreferDestructuring,
    PreferMultiHeadForNil,
    PreferWithClause,
    PreferTaggedTuplesForErrors,
    PreferForComprehensionOverFilterMap,
    PreferListPrepend,
    PreferPatternMatchingForEmptiness,
    AvoidSinglePipe,
    PreferDotAccessForStructs
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
  end

  describe "PreferInplaceListMatching" do
    test "reports length(list) in guard" do
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
  end

  describe "PreferDestructuring" do
    test "reports elem call" do
      """
      defmodule Test do
        def run(tuple) do
          elem(tuple, 0)
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferDestructuring)
      |> assert_issue()
    end
  end

  describe "PreferMultiHeadForNil" do
    test "reports is_nil in guard" do
      """
      defmodule Test do
        def process(arg) when not is_nil(arg) do
          arg
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferMultiHeadForNil)
      |> assert_issue()
    end
  end

  describe "PreferWithClause" do
    test "reports nested case statements" do
      """
      defmodule Test do
        def run do
          case f1() do
            {:ok, a} ->
              case f2(a) do
                {:ok, b} -> b
              end
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferWithClause)
      |> assert_issue()
    end
  end

  describe "PreferTaggedTuplesForErrors" do
    test "reports try rescue block" do
      """
      defmodule Test do
        def run(str) do
          try do
            String.to_integer(str)
          rescue
            ArgumentError -> :err
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferTaggedTuplesForErrors)
      |> assert_issue()
    end
  end

  describe "PreferForComprehensionOverFilterMap" do
    test "reports filter piped to map" do
      """
      defmodule Test do
        def run(list) do
          list |> Enum.filter(& &1) |> Enum.map(& &1)
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferForComprehensionOverFilterMap)
      |> assert_issue()
    end
  end

  describe "PreferListPrepend" do
    test "reports appending to list with ++" do
      """
      defmodule Test do
        def run(acc, item) do
          acc ++ [item]
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferListPrepend)
      |> assert_issue()
    end
  end

  describe "PreferPatternMatchingForEmptiness" do
    test "reports Enum.count > 0 check" do
      """
      defmodule Test do
        def run(list) do
          if Enum.count(list) > 0 do
            :ok
          end
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferPatternMatchingForEmptiness)
      |> assert_issue()
    end
  end

  describe "AvoidSinglePipe" do
    test "reports single stage pipe" do
      """
      defmodule Test do
        def run(data) do
          data |> String.trim()
        end
      end
      """
      |> to_source_file()
      |> run_check(AvoidSinglePipe)
      |> assert_issue()
    end
  end

  describe "PreferDotAccessForStructs" do
    test "reports bracket access syntax" do
      """
      defmodule Test do
        def run(user) do
          user[:name]
        end
      end
      """
      |> to_source_file()
      |> run_check(PreferDotAccessForStructs)
      |> assert_issue()
    end
  end
end
