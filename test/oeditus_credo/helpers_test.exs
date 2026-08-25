defmodule OeditusCredo.HelpersTest do
  use ExUnit.Case, async: true

  alias OeditusCredo.Helpers

  describe "test_file?/1" do
    test "matches files ending with _test.exs" do
      assert Helpers.test_file?("lib/my_app_test.exs")
      assert Helpers.test_file?("some/path/foo_test.exs")
    end

    test "matches files in /test/ directory (umbrella apps)" do
      assert Helpers.test_file?("apps/my_app/test/support/factory.ex")
      assert Helpers.test_file?("apps/my_app/test/test_helper.exs")
    end

    test "matches files starting with test/ (regular apps)" do
      assert Helpers.test_file?("test/test_helper.exs")
      assert Helpers.test_file?("test/my_app/some_test.exs")
      assert Helpers.test_file?("test/support/factory.ex")
    end

    test "does not match regular lib files" do
      refute Helpers.test_file?("lib/my_app/context.ex")
      refute Helpers.test_file?("lib/my_app_web/router.ex")
    end

    test "does not match files with 'test' in the name but not in test dir" do
      refute Helpers.test_file?("lib/my_app/test_utils.ex")
      refute Helpers.test_file?("lib/contest/module.ex")
    end
  end

  describe "alias_to_string/1" do
    test "converts atom list to string" do
      assert Helpers.alias_to_string([:Repo, :User]) == "Repo.User"
    end

    test "handles {:__MODULE__, _, nil} in alias parts" do
      ast_parts = [{:__MODULE__, [line: 4], nil}, :Pigeon]
      assert Helpers.alias_to_string(ast_parts) == "__MODULE__.Pigeon"
    end

    test "handles module attributes and other AST nodes in parts" do
      attr_parts = [{:@, [], [{:sub_mod, [], nil}]}, :Worker]
      assert Helpers.alias_to_string(attr_parts) == "@sub_mod.Worker"
    end

    test "handles {:__aliases__, _, parts} AST" do
      aliases_ast = {:__aliases__, [], [{:__MODULE__, [], nil}, :Sub]}
      assert Helpers.alias_to_string(aliases_ast) == "__MODULE__.Sub"
    end

    test "handles single atom" do
      assert Helpers.alias_to_string(:Repo) == "Repo"
    end
  end
end
