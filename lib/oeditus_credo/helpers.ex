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

  @doc """
  Safely converts module alias parts (or an alias AST / atom / tuple) to a string representation.

  Handles simple atoms (e.g. `:Repo` -> `"Repo"`), AST nodes (e.g. `{:__MODULE__, _, nil}` -> `"__MODULE__"`),
  and lists of parts (e.g. `[{:__MODULE__, _, nil}, :Pigeon]` -> `"__MODULE__.Pigeon"`).
  """
  @spec alias_to_string(term()) :: String.t()
  def alias_to_string(parts) when is_list(parts) do
    Enum.map_join(parts, ".", &format_alias_part/1)
  end

  def alias_to_string({:__aliases__, _, parts}), do: alias_to_string(parts)
  def alias_to_string(part) when is_atom(part), do: Atom.to_string(part)
  def alias_to_string(part), do: format_alias_part(part)

  defp format_alias_part(part) when is_atom(part), do: Atom.to_string(part)
  defp format_alias_part({:__MODULE__, _, _}), do: "__MODULE__"

  defp format_alias_part(part) do
    Macro.to_string(part)
  rescue
    _ -> ""
  end
end
