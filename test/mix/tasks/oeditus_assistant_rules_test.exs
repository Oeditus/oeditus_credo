defmodule Mix.Tasks.OeditusAssistantRulesTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.OeditusAssistantRules

  describe "generate/0" do
    test "generates rules content matching the .aiassistant/rules/oeditus.md file" do
      generated = OeditusAssistantRules.generate()
      file_path = ".aiassistant/rules/oeditus.md"

      assert File.exists?(file_path), "Expected #{file_path} to exist"
      assert File.read!(file_path) == generated,
             "Expected #{file_path} to be up-to-date with `mix oeditus_assistant_rules`"
    end

    test "includes footer with current version of OeditusCredo" do
      generated = OeditusAssistantRules.generate()
      version = OeditusCredo.version()

      assert generated =~ "OeditusCredo v#{version}"
    end
  end

  describe "run/1" do
    test "creates custom output file when -o or --output option is provided" do
      tmp_path = Path.join(System.tmp_dir!(), "test_rules_#{System.unique_integer([:positive])}.md")

      on_exit(fn -> File.rm(tmp_path) end)

      OeditusAssistantRules.run(["-o", tmp_path])

      assert File.exists?(tmp_path)
      assert File.read!(tmp_path) == OeditusAssistantRules.generate()
    end
  end
end
