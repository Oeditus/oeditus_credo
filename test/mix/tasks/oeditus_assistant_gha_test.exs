defmodule Mix.Tasks.OeditusAssistantGhaTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.OeditusAssistantGha

  describe "content functions" do
    test "action_yml_content returns action.yml content" do
      content = OeditusAssistantGha.action_yml_content()
      assert content =~ "name: \"Oeditus - Elixir PR AI Code Reviewer\""
      assert content =~ "python3 ${{ github.action_path }}/review_pr.py"
    end

    test "workflow_yml_content returns workflow.yml content" do
      content = OeditusAssistantGha.workflow_yml_content()
      assert content =~ "name: \"Oeditus AI PR Reviewer\""
      assert content =~ "uses: ./.github/actions/oeditus"
    end

    test "review_py_content returns valid Python script content" do
      content = OeditusAssistantGha.review_py_content()
      assert content =~ "#!/usr/bin/env python3"
      assert content =~ "call_claude_api"
      assert content =~ "call_openai_api"
      assert content =~ "post_github_pr_review"
    end
  end

  describe "run/1" do
    test "creates workflow and action files in target directory" do
      tmp_dir = Path.join(System.tmp_dir!(), "gha_test_#{System.unique_integer([:positive])}")
      on_exit(fn -> File.rm_rf(tmp_dir) end)

      OeditusAssistantGha.run(["-o", tmp_dir])

      action_path = Path.join(tmp_dir, ".github/actions/oeditus/action.yml")
      review_path = Path.join(tmp_dir, ".github/actions/oeditus/review_pr.py")
      workflow_path = Path.join(tmp_dir, ".github/workflows/oeditus.yml")

      assert File.exists?(action_path)
      assert File.exists?(review_path)
      assert File.exists?(workflow_path)

      assert File.read!(action_path) == OeditusAssistantGha.action_yml_content()
      assert File.read!(workflow_path) == OeditusAssistantGha.workflow_yml_content()
      assert File.read!(review_path) == OeditusAssistantGha.review_py_content()
    end
  end
end
