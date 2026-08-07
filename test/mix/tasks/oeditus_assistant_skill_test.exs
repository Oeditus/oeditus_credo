defmodule Mix.Tasks.OeditusAssistantSkillTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.OeditusAssistantSkill

  describe "generate/1" do
    test "generates skill content for target assistant with frontmatter and title" do
      for target <- ["claude", "openai", "gemini"] do
        content = OeditusAssistantSkill.generate(target)

        assert content =~ "name: oeditus"
        assert content =~ "OeditusCredo v#{OeditusCredo.version()}"
        assert content =~ "### 🚨 Error Handling"
        assert content =~ "### 🛡️ Security Rules"
        refute content =~ "ChangeRiskAntiPatterns" # skipped as non-pure LLM check
      end

      assert OeditusAssistantSkill.generate("claude") =~ "Claude Code"
      assert OeditusAssistantSkill.generate("openai") =~ "OpenAI / Codex / ChatGPT"
      assert OeditusAssistantSkill.generate("gemini") =~ "Google Antigravity / Gemini"
    end
  end

  describe "run/1" do
    test "writes to default directory for valid target assistant" do
      for {target, expected_file} <- [
            {"claude", ".claude/skills/oeditus/SKILL.md"},
            {"openai", ".openai/skills/oeditus/SKILL.md"},
            {"gemini", ".gemini/skills/oeditus/SKILL.md"}
          ] do
        OeditusAssistantSkill.run([target])
        assert File.exists?(expected_file)
        assert File.read!(expected_file) == OeditusAssistantSkill.generate(target)
      end
    end

    test "creates custom output file when -o option is passed" do
      tmp_path = Path.join(System.tmp_dir!(), "skill_#{System.unique_integer([:positive])}.md")
      on_exit(fn -> File.rm(tmp_path) end)

      OeditusAssistantSkill.run(["claude", "-o", tmp_path])

      assert File.exists?(tmp_path)
      assert File.read!(tmp_path) == OeditusAssistantSkill.generate("claude")
    end

    test "raises error when target assistant is missing or invalid" do
      assert_raise Mix.Error, ~r/Missing target assistant/, fn ->
        OeditusAssistantSkill.run([])
      end

      assert_raise Mix.Error, ~r/Invalid target assistant/, fn ->
        OeditusAssistantSkill.run(["unknown_assistant"])
      end
    end
  end
end
