defmodule OeditusCredo.Crap.Coverage do
  @moduledoc false

  # Ported from ExCrap (https://github.com/germsvel/ex_crap), MIT License,
  # Copyright (c) 2026 The Software League. See NOTICE.md for the full notice.
  #
  # Imports Erlang/Mix coverdata and normalizes function coverage percentages by MFA.

  @doc """
  Imports a persisted Erlang/Mix coverdata file and returns a map of
  `{module, function, arity} => coverage_percent`.

  The coverdata file is produced by `mix test --cover --export-coverage default`.
  Returns `{:ok, coverage_map}` or `{:error, reason}`.
  """
  @spec from_coverdata(binary()) :: {:ok, %{optional(tuple()) => float()}} | {:error, term()}
  def from_coverdata(path) when is_binary(path) do
    if File.regular?(path) do
      with :ok <- ensure_cover_started(),
           :ok <- :cover.import(String.to_charlist(path)),
           modules when is_list(modules) <- :cover.imported_modules() do
        {:ok, coverage_for_modules(modules)}
      end
    else
      {:error, {:coverdata_unreadable, path}}
    end
  end

  @doc false
  def from_function_rows(rows) when is_list(rows) do
    Map.new(rows, fn {{module, function, arity}, {covered, not_covered}} ->
      total = covered + not_covered
      percent = if total == 0, do: 0.0, else: covered / total * 100
      {normalize_key(module, function, arity), percent}
    end)
  end

  defp normalize_key(module, function, arity) do
    case Atom.to_string(function) do
      "MACRO-" <> name -> normalize_macro_key(module, function, name, arity)
      _other -> {module, function, arity}
    end
  end

  defp normalize_macro_key(module, function, name, arity) do
    {module, String.to_existing_atom(name), arity - 1}
  rescue
    ArgumentError -> {module, function, arity}
  end

  defp ensure_cover_started do
    case :cover.start() do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp coverage_for_modules(modules) do
    without_cover_output(fn ->
      Enum.flat_map(modules, &coverage_rows_for_module/1)
    end)
    |> from_function_rows()
  end

  defp coverage_rows_for_module(module) do
    case :cover.analyse(module, :coverage, :function) do
      {:ok, rows} -> rows
      {:error, _reason} -> []
    end
  end

  defp without_cover_output(fun) do
    group_leader = Process.group_leader()
    cover_pid = cover_pid()
    cover_group_leader = if cover_pid, do: Process.info(cover_pid, :group_leader) |> elem(1)
    {:ok, io} = StringIO.open("")

    try do
      Process.group_leader(self(), io)
      if cover_pid, do: Process.group_leader(cover_pid, io)
      fun.()
    after
      Process.group_leader(self(), group_leader)
      if cover_pid, do: Process.group_leader(cover_pid, cover_group_leader)
    end
  end

  defp cover_pid do
    case :cover.start() do
      {:error, {:already_started, pid}} -> pid
      {:ok, pid} -> pid
      _other -> nil
    end
  end
end
