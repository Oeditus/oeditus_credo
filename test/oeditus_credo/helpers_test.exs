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
end
