exclude =
  if Version.match?(System.version(), ">= 1.20.0-dev") do
    []
  else
    [:elixir_1_20]
  end

ExUnit.start(exclude: exclude)
