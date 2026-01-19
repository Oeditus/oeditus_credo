defmodule OeditusCredo.Escript do
  @moduledoc """
  Entry point for the oeditus_credo escript.

  This module provides a standalone executable that runs Credo with all
  OeditusCredo checks enabled.
  """

  @doc """
  Main entry point for the escript.
  """
  @spec main([String.t()]) :: no_return()
  def main(args) do
    # Ensure Credo and dependencies are loaded
    Application.ensure_all_started(:credo)

    # Generate temporary config
    config_content = OeditusCredo.CLI.default_config()

    temp_config_path =
      Path.join(
        System.tmp_dir!(),
        "oeditus_credo_#{System.unique_integer([:positive])}.exs"
      )

    File.write!(temp_config_path, config_content)

    try do
      # Parse and run Credo with our configuration
      args_with_config = ["--config-file", temp_config_path | args]

      # Run Credo CLI
      exit_status = run_credo(args_with_config)

      # Exit with appropriate status
      System.halt(exit_status)
    catch
      kind, reason ->
        IO.puts(:stderr, "Error running oeditus_credo: #{inspect(kind)} - #{inspect(reason)}")
        System.halt(1)
    after
      File.rm(temp_config_path)
    end
  end

  defp run_credo(args) do
    # Use Credo's CLI module directly
    case Credo.CLI.main(args) do
      _ -> 0
    end
  rescue
    _ -> 1
  end
end
