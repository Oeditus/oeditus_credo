defmodule OeditusCredo.Check.Warning.UnsafeMapAccessTest do
  use Credo.Test.Case

  alias OeditusCredo.Check.Warning.UnsafeMapAccess

  # These tests require real files on disk so Typle can infer types.
  # We use ExUnit's @tag :tmp_dir to get a per-test temp directory.

  @tag :tmp_dir
  test "it should report issue for bracket access on a map literal", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example do
        config = %{timeout: 5000}
        config[:timeout]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> assert_issue()
  end

  @tag :tmp_dir
  test "it should report issue for bracket access on a struct literal", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      defstruct [:name, :age]

      def example do
        user = %MyModule{name: "Alice", age: 30}
        user[:name]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> assert_issue()
  end

  @tag :tmp_dir
  test "it should report multiple issues for chained bracket access on maps",
       %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example do
        outer = %{inner: %{key: 1}}
        outer[:inner][:key]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> assert_issue()
  end

  @tag :tmp_dir
  test "it should NOT report issue for bracket access with string key", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example do
        map = %{"key" => 1}
        map["key"]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> refute_issues()
  end

  @tag :tmp_dir
  test "it should NOT report issue for bracket access with variable key", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example(key) do
        map = %{foo: 1}
        map[key]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> refute_issues()
  end

  @tag :tmp_dir
  test "it should NOT report issue for bracket access with integer key", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example do
        list = [10, 20, 30]
        list[0]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> refute_issues()
  end

  @tag :tmp_dir
  test "it should NOT report issue for keyword list bracket access", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example do
        opts = [timeout: 5000, retries: 3]
        opts[:timeout]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> refute_issues()
  end

  @tag :tmp_dir
  test "it should NOT report issue for dynamic variable bracket access", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModule do
      def example(data) do
        data[:key]
      end
    end
    """

    source
    |> to_source_file_on_disk(tmp_dir)
    |> run_check(UnsafeMapAccess)
    |> refute_issues()
  end

  test "it should NOT report issue when source file has no on-disk path" do
    """
    defmodule MyModule do
      def example do
        map = %{key: 1}
        map[:key]
      end
    end
    """
    |> to_source_file()
    |> run_check(UnsafeMapAccess)
    |> refute_issues()
  end

  @tag :tmp_dir
  test "it should skip test files when exclude_test_files is true", %{tmp_dir: tmp_dir} do
    source = """
    defmodule MyModuleTest do
      def example do
        config = %{timeout: 5000}
        config[:timeout]
      end
    end
    """

    path = Path.join(tmp_dir, "my_module_test.exs")
    File.write!(path, source)

    source
    |> to_source_file(path)
    |> run_check(UnsafeMapAccess, exclude_test_files: true)
    |> refute_issues()
  end

  # -- Helper ------------------------------------------------------------------

  defp to_source_file_on_disk(source, tmp_dir) do
    path = Path.join(tmp_dir, "test_#{:erlang.unique_integer([:positive])}.ex")
    File.write!(path, source)
    to_source_file(source, path)
  end
end
