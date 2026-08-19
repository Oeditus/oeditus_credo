defmodule Mix.Tasks.OeditusAssistantGha do
  @moduledoc """
  Generates GitHub Action workflow and composite action files for running automated AI PR reviews using OeditusCredo rules.

  ## Generated Files

  - `.github/actions/oeditus/action.yml`
  - `.github/actions/oeditus/review_pr.py`
  - `.github/workflows/oeditus.yml`

  ## Usage

      mix oeditus_assistant_gha            # writes action and workflow files
      mix oeditus_assistant_gha --stdout   # prints files to stdout
      mix oeditus_assistant_gha -o DIR     # writes to a custom target base directory
  """

  use Mix.Task

  @shortdoc "Generates GitHub Action workflow for Oeditus AI PR review"

  @impl Mix.Task
  def run(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [stdout: :boolean, output: :string, target_dir: :string],
        aliases: [o: :output]
      )

    base_dir = opts[:output] || opts[:target_dir] || "."

    action_yml_path = Path.join(base_dir, ".github/actions/oeditus/action.yml")
    review_py_path = Path.join(base_dir, ".github/actions/oeditus/review_pr.py")
    workflow_yml_path = Path.join(base_dir, ".github/workflows/oeditus.yml")

    if opts[:stdout] do
      IO.puts("=== #{action_yml_path} ===")
      IO.puts(action_yml_content())
      IO.puts("\n=== #{review_py_path} ===")
      IO.puts(review_py_content())
      IO.puts("\n=== #{workflow_yml_path} ===")
      IO.puts(workflow_yml_content())
    else
      write_file(action_yml_path, action_yml_content())
      write_file(review_py_path, review_py_content())
      File.chmod!(review_py_path, 0o755)
      write_file(workflow_yml_path, workflow_yml_content())

      Mix.shell().info("Generated Oeditus GitHub Action workflow files:")
      Mix.shell().info("  - #{action_yml_path}")
      Mix.shell().info("  - #{review_py_path}")
      Mix.shell().info("  - #{workflow_yml_path}")
    end
  end

  defp write_file(path, content) do
    path |> Path.dirname() |> File.mkdir_p!()
    File.write!(path, content)
  end

  @doc "Returns the content of .github/actions/oeditus/action.yml"
  def action_yml_content do
    """
    name: "Oeditus - Elixir PR AI Code Reviewer"
    description: "Evaluates Elixir PR diffs against OeditusCredo rules using Claude or OpenAI API and posts inline review comments to the PR."
    inputs:
      openai_api_key:
        description: "OpenAI API Key to run review with OpenAI models (gpt-4o, o3-mini, etc.)"
        required: false
      anthropic_api_key:
        description: "Anthropic API Key to run review with Claude models (claude-3-5-sonnet-latest, etc.)"
        required: false
      github_token:
        description: "GitHub Token (secrets.GITHUB_TOKEN)"
        required: true
        default: ${{ github.token }}
      model:
        description: "AI Model to use for review (e.g. claude-3-5-sonnet-latest, gpt-4o)"
        required: false
        default: "claude-3-5-sonnet-latest"

    runs:
      using: "composite"
      steps:
        - name: Set up Python
          uses: actions/setup-python@v4
          with:
            python-version: "3.x"

        - name: Run Oeditus Elixir PR Review Script
          shell: bash
          env:
            OPENAI_API_KEY: ${{ inputs.openai_api_key }}
            ANTHROPIC_API_KEY: ${{ inputs.anthropic_api_key }}
            GITHUB_TOKEN: ${{ inputs.github_token }}
            MODEL: ${{ inputs.model }}
            GITHUB_BASE_REF: ${{ github.base_ref }}
            GITHUB_EVENT_PATH: ${{ env.GITHUB_EVENT_PATH }}
            GITHUB_REPOSITORY: ${{ github.repository }}
          run: |
            python3 ${{ github.action_path }}/review_pr.py
    """
  end

  @doc "Returns the content of .github/workflows/oeditus.yml"
  def workflow_yml_content do
    """
    name: "Oeditus AI PR Reviewer"

    on:
      pull_request:
        types: [opened, synchronize]
        paths:
          - "**/*.ex"
          - "**/*.exs"

    jobs:
      ai-code-review:
        name: "Oeditus Code Review"
        runs-on: ubuntu-latest
        permissions:
          contents: read
          pull-requests: write

        steps:
          - name: Checkout repository
            uses: actions/checkout@v3
            with:
              fetch-depth: 0

          - name: Run Oeditus AI PR Reviewer
            uses: ./.github/actions/oeditus
            with:
              anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
              model: "claude-3-5-sonnet-latest"
              github_token: ${{ secrets.GITHUB_TOKEN }}
    """
  end

  @doc "Returns the content of .github/actions/oeditus/review_pr.py"
  def review_py_content do
    """
    #!/usr/bin/env python3
    import json
    import os
    import re
    import subprocess
    import sys
    import urllib.request
    import urllib.error

    def get_git_diff():
        \"\"\"Fetches git diff for Elixir files in the current PR.\"\"\"
        base_ref = os.environ.get("GITHUB_BASE_REF", "main")
        try:
            subprocess.run(["git", "fetch", "origin", base_ref, "--depth=100"], check=False)
            diff_cmd = ["git", "diff", f"origin/{base_ref}...HEAD", "--", "*.ex", "*.exs"]
            res = subprocess.run(diff_cmd, capture_output=True, text=True, check=True)
            return res.stdout
        except Exception:
            try:
                res = subprocess.run(["git", "diff", "HEAD^1", "--", "*.ex", "*.exs"], capture_output=True, text=True, check=True)
                return res.stdout
            except Exception:
                return ""

    def load_skill_prompt():
        \"\"\"Reads the Oeditus review rules from rule/skill files.\"\"\"
        paths = [
            os.path.join(".aiassistant", "rules", "oeditus.md"),
            os.path.join(".claude", "skills", "oeditus", "SKILL.md"),
            os.path.join(".openai", "skills", "oeditus", "SKILL.md"),
            os.path.join(".gemini", "skills", "oeditus", "SKILL.md"),
            os.path.join("skills", "oeditus", "SKILL.md")
        ]
        for skill_path in paths:
            if os.path.exists(skill_path):
                with open(skill_path, "r", encoding="utf-8") as f:
                    return f.read()
        return (
            "Evaluate Elixir PR diffs against OeditusCredo rules:\\n"
            "- Error Handling: match {:ok, _} with handling, case error branches, try/rescue re-raising\\n"
            "- DB/Perf: avoid N+1 queries in Enum loops, Repo.all |> Enum.filter, missing preloads\\n"
            "- LiveView/Concurrency: Task.Supervisor for async tasks, avoid unawaited Task.async, no blocking in GenServer/LiveView/Plug, start_async/handle_async in handle_event, phx-debounce/throttle, phx-* over inline JS\\n"
            "- Code Quality & Struct/Map Access: Ecto changesets over direct struct updates, dot access map.key/struct.key over bracket access, with over nested case\\n"
            "- Refactoring: case over if/cond, multi-head over parameter if, pipe operator, %{} map match, [_|_] list match, binary match, destructuring, tagged tuples over try/rescue, for comprehensions, Map.merge, string boundaries over regex, capture syntax\\n"
            "- Security (CWE Top 25): SQL injection, OS command injection, code injection, XSS raw/1, missing auth/authorization, auth order before Repo, no negated role checks, IDOR, sensitive logging, credentials, unsafe binary_to_term, path traversal, file upload validation, CSRF, SSRF, TOCTOU."
        )

    def call_openai_api(api_key, model, prompt, diff):
        \"\"\"Sends PR diff and review rules to OpenAI API.\"\"\"
        system_prompt = (
            "You are an expert Elixir Code Reviewer AI. Analyze the provided git diff against the Oeditus rules in SKILL.md.\\n"
            "Identify code smells, security vulnerabilities, and anti-patterns strictly within the added/modified lines of the PR diff.\\n"
            "For each detected issue, provide a concise explanation and an exact replacement snippet for the GitHub ```suggestion block.\\n\\n"
            "You MUST respond ONLY with valid JSON matching this exact structure:\\n"
            "{\\n"
            '  "summary": "Short overall review summary string",\\n'
            '  "comments": [\\n'
            "    {\\n"
            '      "path": "path/to/file.ex",\\n'
            '      "line": 15,\\n'
            '      "rule_id": "OEDITUS_RULE",\\n'
            '      "title": "Short title",\\n'
            '      "body": "Explanation of the issue and why it is unidiomatic or insecure.",\\n'
            '      "suggestion": "exact single line or multiline string replacement code for GitHub ```suggestion block"\\n'
            "    }\\n"
            "  ]\\n"
            "}\\n\\n"
            "If no issues are found, return {\\\"summary\\\": \\\"No Elixir code issues detected.\\\", \\\"comments\\\": []}."
        )

        user_message = (
            f"### OEDITUS RULES:\\n{prompt}\\n\\n"
            f"### PR GIT DIFF TO REVIEW:\\n{diff}"
        )

        payload = {
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        }

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_content = data["choices"][0]["message"]["content"].strip()
                raw_content = re.sub(r"^```json\\s*", "", raw_content)
                raw_content = re.sub(r"\\s*```$", "", raw_content)
                return json.loads(raw_content)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            print(f"OpenAI API HTTP Error {e.code}: {err_body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error calling OpenAI API: {e}", file=sys.stderr)
            sys.exit(1)

    def call_claude_api(api_key, model, prompt, diff):
        \"\"\"Sends PR diff and review rules to Anthropic Claude API.\"\"\"
        system_prompt = (
            "You are an expert Elixir Code Reviewer AI. Analyze the provided git diff against the Oeditus rules in SKILL.md.\\n"
            "Identify code smells, security vulnerabilities, and anti-patterns strictly within the added/modified lines of the PR diff.\\n"
            "For each detected issue, provide a concise explanation and an exact replacement snippet for the GitHub ```suggestion block.\\n\\n"
            "You MUST respond ONLY with valid JSON matching this exact structure:\\n"
            "{\\n"
            '  "summary": "Short overall review summary string",\\n'
            '  "comments": [\\n'
            "    {\\n"
            '      "path": "path/to/file.ex",\\n'
            '      "line": 15,\\n'
            '      "rule_id": "OEDITUS_RULE",\\n'
            '      "title": "Short title",\\n'
            '      "body": "Explanation of the issue and why it is unidiomatic or insecure.",\\n'
            '      "suggestion": "exact single line or multiline string replacement code for GitHub ```suggestion block"\\n'
            "    }\\n"
            "  ]\\n"
            "}\\n\\n"
            "If no issues are found, return {\\\"summary\\\": \\\"No Elixir code issues detected.\\\", \\\"comments\\\": []}.\\n"
            "Do NOT wrap the output in markdown code blocks like ```json."
        )

        user_message = (
            f"### OEDITUS RULES:\\n{prompt}\\n\\n"
            f"### PR GIT DIFF TO REVIEW:\\n{diff}"
        )

        payload = {
            "model": model,
            "max_tokens": 4096,
            "temperature": 0.1,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message}
            ]
        }

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_content = data["content"][0]["text"].strip()
                raw_content = re.sub(r"^```json\\s*", "", raw_content)
                raw_content = re.sub(r"\\s*```$", "", raw_content)
                return json.loads(raw_content)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            print(f"Claude API HTTP Error {e.code}: {err_body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error calling Claude API: {e}", file=sys.stderr)
            sys.exit(1)

    def post_github_pr_review(github_token, repo, pr_number, commit_sha, review_data):
        \"\"\"Posts review comments directly to the GitHub PR using GitHub REST API.\"\"\"
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"

        comments = []
        for item in review_data.get("comments", []):
            path = item.get("path")
            line = item.get("line")
            rule_id = item.get("rule_id", "OEDITUS")
            title = item.get("title", "Code Smell Detected")
            body_text = item.get("body", "")
            suggestion = item.get("suggestion", "")

            comment_markdown = f"### 💡 **[{rule_id}] {title}**\\n\\n{body_text}\\n"
            if suggestion:
                comment_markdown += f"\\n```suggestion\\n{suggestion}\\n```"

            if path and line:
                comments.append({
                    "path": path,
                    "line": int(line),
                    "side": "RIGHT",
                    "body": comment_markdown
                })

        summary = review_data.get("summary", "Oeditus Code Review Completed.")
        event_type = "COMMENT" if comments else "APPROVE"

        payload = {
            "commit_id": commit_sha,
            "event": event_type,
            "body": f"## 🔍 Oeditus AI PR Code Reviewer\\n\\n{summary}\\n\\nFound **{len(comments)}** suggestion(s).",
            "comments": comments
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"token {github_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req) as resp:
                print(f"Successfully posted PR review to \#{pr_number} with {len(comments)} comment(s).")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            print(f"GitHub API Error {e.code}: {err_body}", file=sys.stderr)
            sys.exit(1)

    def main():
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")
        github_token = os.environ.get("GITHUB_TOKEN")
        model = os.environ.get("MODEL") or os.environ.get("CLAUDE_MODEL", "claude-3-5-sonnet-latest")

        diff = get_git_diff()
        if not diff.strip():
            print("No Elixir changes detected in PR diff.")
            sys.exit(0)

        print("Extracting Elixir diff and loading Oeditus rules...")
        skill_prompt = load_skill_prompt()

        is_openai = bool(openai_key) or model.startswith(("gpt-", "o1-", "o3-"))

        if is_openai:
            if not openai_key:
                print("Error: OPENAI_API_KEY is required to run review with OpenAI models.", file=sys.stderr)
                sys.exit(1)
            if model == "claude-3-5-sonnet-latest":
                model = "gpt-4o"
            print(f"Evaluating PR diff against Oeditus rules with OpenAI API ({model})...")
            review_data = call_openai_api(openai_key, model, skill_prompt, diff)
        else:
            if not anthropic_key:
                print("Error: ANTHROPIC_API_KEY or OPENAI_API_KEY is required to run the AI PR Reviewer Action.", file=sys.stderr)
                sys.exit(1)
            print(f"Evaluating PR diff against Oeditus rules with Claude API ({model})...")
            review_data = call_claude_api(anthropic_key, model, skill_prompt, diff)

        print("Review Results:")
        print(json.dumps(review_data, indent=2))

        event_path = os.environ.get("GITHUB_EVENT_PATH")
        repo = os.environ.get("GITHUB_REPOSITORY")

        if event_path and os.path.exists(event_path) and repo and github_token:
            with open(event_path, "r", encoding="utf-8") as f:
                event_data = json.load(f)

            pr_number = event_data.get("pull_request", {}).get("number")
            commit_sha = event_data.get("pull_request", {}).get("head", {}).get("sha")

            if pr_number and commit_sha:
                print(f"Posting review to GitHub PR \#{pr_number}...")
                post_github_pr_review(github_token, repo, pr_number, commit_sha, review_data)
            else:
                print("Not running inside a Pull Request event. Skipping GitHub PR inline comment posting.")
        else:
            print("GITHUB_TOKEN or GITHUB_EVENT_PATH not set. Printed review results to logs.")

    if __name__ == "__main__":
        main()
    """
  end
end
