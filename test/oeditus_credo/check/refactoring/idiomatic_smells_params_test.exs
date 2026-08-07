defmodule OeditusCredo.Check.Refactoring.IdiomaticSmellsParamsTest do
  use Credo.Test.Case

  @moduledoc """
  Verifies that every idiomatic refactoring check honours the common
  `exclude_test_files` parameter documented in the README.
  """

  alias OeditusCredo.Check.Refactoring.{
    AvoidSinglePipe,
    AvoidUnawaitedTaskAsync,
    PreferCasePatternMatching,
    PreferDestructuring,
    PreferDotAccessForStructs,
    PreferForComprehensionOverFilterMap,
    PreferFunctionCapture,
    PreferInplaceBinaryMatching,
    PreferInplaceListMatching,
    PreferInplaceMapMatching,
    PreferListPrepend,
    PreferMapMerge,
    PreferMultiHeadForNil,
    PreferMultiHeadFunction,
    PreferPatternMatchingForEmptiness,
    PreferPipelineOperator,
    PreferShortFieldAccessCapture,
    PreferStringBoundariesOverRegex,
    PreferTaggedTuplesForErrors,
    PreferWithClause
  }

  @offending_sources [
    {AvoidSinglePipe,
     """
     defmodule Test do
       def run(data) do
         data |> String.trim()
       end
     end
     """},
    {AvoidUnawaitedTaskAsync,
     """
     defmodule Test do
       def run(user) do
         Task.async(fn -> user end)
         :ok
       end
     end
     """},
    {PreferCasePatternMatching,
     """
     defmodule Test do
       def check(res) do
         if res == {:ok, :active} do
           :ok
         end
       end
     end
     """},
    {PreferDestructuring,
     """
     defmodule Test do
       def run(tuple) do
         elem(tuple, 0)
       end
     end
     """},
    {PreferDotAccessForStructs,
     """
     defmodule Test do
       def run(user) do
         user[:name]
       end
     end
     """},
    {PreferForComprehensionOverFilterMap,
     """
     defmodule Test do
       def run(list) do
         list |> Enum.filter(& &1) |> Enum.map(& &1)
       end
     end
     """},
    {PreferFunctionCapture,
     """
     defmodule Test do
       def run(list) do
         Enum.map(list, fn s -> String.trim(s) end)
       end
     end
     """},
    {PreferInplaceBinaryMatching,
     """
     defmodule Test do
       def handle(str) when is_binary(str) and str != "" do
         str
       end
     end
     """},
    {PreferInplaceListMatching,
     """
     defmodule Test do
       def handle(items) when length(items) > 0 do
         items
       end
     end
     """},
    {PreferInplaceMapMatching,
     """
     defmodule Test do
       def handle(opts) when is_map(opts) do
         opts
       end
     end
     """},
    {PreferListPrepend,
     """
     defmodule Test do
       def run(acc, item) do
         acc ++ [item]
       end
     end
     """},
    {PreferMapMerge,
     """
     defmodule Test do
       def run(map) do
         map |> Map.put(:a, 1) |> Map.put(:b, 2)
       end
     end
     """},
    {PreferMultiHeadForNil,
     """
     defmodule Test do
       def process(arg) when not is_nil(arg) do
         arg
       end
     end
     """},
    {PreferMultiHeadFunction,
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
     """},
    {PreferPatternMatchingForEmptiness,
     """
     defmodule Test do
       def run(list) do
         if Enum.count(list) > 0 do
           :ok
         end
       end
     end
     """},
    {PreferPipelineOperator,
     """
     defmodule Test do
       def run(input) do
         a = String.trim(input)
         b = String.downcase(a)
         b
       end
     end
     """},
    {PreferShortFieldAccessCapture,
     """
     defmodule Test do
       def run(users) do
         Enum.map(users, fn u -> u.id end)
       end
     end
     """},
    {PreferStringBoundariesOverRegex,
     """
     defmodule Test do
       def run(url) do
         Regex.match?(~r/^https:/, url)
       end
     end
     """},
    {PreferTaggedTuplesForErrors,
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
     """},
    {PreferWithClause,
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
     """}
  ]

  describe "exclude_test_files" do
    for {check, source} <- @offending_sources do
      module_name = check |> Module.split() |> List.last()

      test "#{module_name} reports issues in test files by default" do
        unquote(source)
        |> to_source_file("test/my_app/some_test.exs")
        |> run_check(unquote(check))
        |> assert_issue()
      end

      test "#{module_name} skips test files when exclude_test_files is true" do
        unquote(source)
        |> to_source_file("test/my_app/some_test.exs")
        |> run_check(unquote(check), exclude_test_files: true)
        |> refute_issues()
      end

      test "#{module_name} still reports lib files when exclude_test_files is true" do
        unquote(source)
        |> to_source_file("lib/my_app/some_module.ex")
        |> run_check(unquote(check), exclude_test_files: true)
        |> assert_issue()
      end
    end
  end
end
