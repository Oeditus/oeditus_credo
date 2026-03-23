defmodule OeditusCredo.Helpers do
  @moduledoc """
  Shared helper functions for OeditusCredo checks.
  """

  @doc """
  Returns `true` if the given `filename` belongs to the test directory.

  Matches files ending with `_test.exs` as well as any path containing
  a `test/` segment (both `/test/` for umbrella apps and a leading `test/`
  for regular applications).

  ## Examples

      iex> OeditusCredo.Helpers.test_file?("test/test_helper.exs")
      true

      iex> OeditusCredo.Helpers.test_file?("test/my_app_test.exs")
      true

      iex> OeditusCredo.Helpers.test_file?("apps/my_app/test/support/factory.ex")
      true

      iex> OeditusCredo.Helpers.test_file?("lib/my_app/test_utils.ex")
      false

  """
  @spec test_file?(String.t()) :: boolean()
  def test_file?(filename) do
    String.ends_with?(filename, "_test.exs") or
      String.contains?(filename, "/test/") or
      String.starts_with?(filename, "test/")
  end
end
