defmodule OeditusCredo.Check.Security.SecurityChecksTest do
  use Credo.Test.Case

  # ── CWE-89: SQL Injection ────────────────────────────────────────────

  alias OeditusCredo.Check.Security.SQLInjection

  test "CWE-89: reports Repo.query with <> concatenation" do
    """
    defmodule MyApp do
      def get_user(id) do
        Repo.query("SELECT * FROM users WHERE id = " <> id)
      end
    end
    """
    |> to_source_file()
    |> run_check(SQLInjection)
    |> assert_issue()
  end

  test "CWE-89: no issue for parameterized query" do
    """
    defmodule MyApp do
      def get_user(id) do
        Repo.query("SELECT * FROM users WHERE id = $1", [id])
      end
    end
    """
    |> to_source_file()
    |> run_check(SQLInjection)
    |> refute_issues()
  end

  # ── CWE-78: OS Command Injection ────────────────────────────────────

  alias OeditusCredo.Check.Security.OSCommandInjection

  test "CWE-78: reports System.shell usage" do
    """
    defmodule MyApp do
      def run(cmd) do
        System.shell(cmd)
      end
    end
    """
    |> to_source_file()
    |> run_check(OSCommandInjection)
    |> assert_issue()
  end

  test "CWE-78: reports System.cmd with non-literal command" do
    """
    defmodule MyApp do
      def run(cmd) do
        System.cmd(cmd, [])
      end
    end
    """
    |> to_source_file()
    |> run_check(OSCommandInjection)
    |> assert_issue()
  end

  test "CWE-78: no issue for literal System.cmd" do
    """
    defmodule MyApp do
      def run do
        System.cmd("ls", ["-la"])
      end
    end
    """
    |> to_source_file()
    |> run_check(OSCommandInjection)
    |> refute_issues()
  end

  test "CWE-78: reports :os.cmd usage" do
    """
    defmodule MyApp do
      def run(cmd) do
        :os.cmd(cmd)
      end
    end
    """
    |> to_source_file()
    |> run_check(OSCommandInjection)
    |> assert_issue()
  end

  # ── CWE-94: Code Injection ──────────────────────────────────────────

  alias OeditusCredo.Check.Security.CodeInjection

  test "CWE-94: reports Code.eval_string" do
    """
    defmodule MyApp do
      def eval(input) do
        Code.eval_string(input)
      end
    end
    """
    |> to_source_file()
    |> run_check(CodeInjection)
    |> assert_issue()
  end

  test "CWE-94: reports Code.eval_file" do
    """
    defmodule MyApp do
      def eval(path) do
        Code.eval_file(path)
      end
    end
    """
    |> to_source_file()
    |> run_check(CodeInjection)
    |> assert_issue()
  end

  # ── CWE-79: XSS ────────────────────────────────────────────────────

  alias OeditusCredo.Check.Security.XSSVulnerability

  test "CWE-79: reports raw/1 call" do
    """
    defmodule MyApp do
      def show(content) do
        raw(content)
      end
    end
    """
    |> to_source_file()
    |> run_check(XSSVulnerability)
    |> assert_issue()
  end

  test "CWE-79: no issue for regular functions" do
    """
    defmodule MyApp do
      def show(content) do
        content_tag(:div, content)
      end
    end
    """
    |> to_source_file()
    |> run_check(XSSVulnerability)
    |> refute_issues()
  end

  # ── CWE-306: Missing Authentication ─────────────────────────────────

  alias OeditusCredo.Check.Security.MissingAuthentication

  test "CWE-306: reports controller without auth plug" do
    """
    defmodule MyAppWeb.AdminController do
      use MyAppWeb, :controller

      def delete(conn, params) do
        conn
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingAuthentication)
    |> assert_issue()
  end

  test "CWE-306: no issue when auth plug is present" do
    """
    defmodule MyAppWeb.AdminController do
      use MyAppWeb, :controller
      plug :require_authentication

      def delete(conn, params) do
        conn
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingAuthentication)
    |> refute_issues()
  end

  # ── CWE-862: Missing Authorization ──────────────────────────────────

  alias OeditusCredo.Check.Security.MissingAuthorization

  test "CWE-862: reports Repo.delete without authorization" do
    """
    defmodule MyApp do
      def delete_post(post) do
        Repo.delete!(post)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingAuthorization)
    |> assert_issue()
  end

  test "CWE-862: no issue when authorize! is called" do
    """
    defmodule MyApp do
      def delete_post(user, post) do
        authorize!(user, :delete, post)
        Repo.delete!(post)
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingAuthorization)
    |> refute_issues()
  end

  # ── CWE-863: Incorrect Authorization ────────────────────────────────

  alias OeditusCredo.Check.Security.IncorrectAuthorization

  test "CWE-863: reports auth after sensitive operation" do
    """
    defmodule MyApp do
      def delete_post(user, post) do
        Repo.delete!(post)
        authorize!(user, :delete, post)
      end
    end
    """
    |> to_source_file()
    |> run_check(IncorrectAuthorization)
    |> assert_issue()
  end

  test "CWE-863: no issue when auth before operation" do
    """
    defmodule MyApp do
      def delete_post(user, post) do
        authorize!(user, :delete, post)
        Repo.delete!(post)
      end
    end
    """
    |> to_source_file()
    |> run_check(IncorrectAuthorization)
    |> refute_issues()
  end

  # ── CWE-639: IDOR ──────────────────────────────────────────────────

  alias OeditusCredo.Check.Security.InsecureDirectObjectReference

  test "CWE-639: reports Repo.get! with id without ownership check" do
    """
    defmodule MyApp do
      def show(id) do
        Repo.get!(Post, id)
      end
    end
    """
    |> to_source_file()
    |> run_check(InsecureDirectObjectReference)
    |> assert_issue()
  end

  test "CWE-639: no issue when current_user check present" do
    """
    defmodule MyApp do
      def show(user, id) do
        post = Repo.get!(Post, id)
        authorize!(user, :read, post)
        post
      end
    end
    """
    |> to_source_file()
    |> run_check(InsecureDirectObjectReference)
    |> refute_issues()
  end

  # ── CWE-200: Sensitive Data Exposure ────────────────────────────────

  alias OeditusCredo.Check.Security.SensitiveDataExposure

  test "CWE-200: reports Logger call with password variable" do
    """
    defmodule MyApp do
      def create(password) do
        Logger.info(password)
      end
    end
    """
    |> to_source_file()
    |> run_check(SensitiveDataExposure)
    |> assert_issue()
  end

  test "CWE-200: no issue for non-sensitive variables" do
    """
    defmodule MyApp do
      def create(name) do
        Logger.info(name)
      end
    end
    """
    |> to_source_file()
    |> run_check(SensitiveDataExposure)
    |> refute_issues()
  end

  # ── CWE-798: Hardcoded Credentials ──────────────────────────────────

  alias OeditusCredo.Check.Security.HardcodedCredentials

  test "CWE-798: reports hardcoded password assignment" do
    """
    defmodule MyApp do
      def connect do
        password = "super-secret"
        password
      end
    end
    """
    |> to_source_file()
    |> run_check(HardcodedCredentials)
    |> assert_issue()
  end

  test "CWE-798: no issue for runtime env access" do
    """
    defmodule MyApp do
      def connect do
        password = System.get_env("PASSWORD")
        password
      end
    end
    """
    |> to_source_file()
    |> run_check(HardcodedCredentials)
    |> refute_issues()
  end

  # ── CWE-502: Unsafe Deserialization ─────────────────────────────────

  alias OeditusCredo.Check.Security.UnsafeDeserialization

  test "CWE-502: reports binary_to_term without :safe" do
    """
    defmodule MyApp do
      def decode(data) do
        :erlang.binary_to_term(data)
      end
    end
    """
    |> to_source_file()
    |> run_check(UnsafeDeserialization)
    |> assert_issue()
  end

  test "CWE-502: no issue with :safe option" do
    """
    defmodule MyApp do
      def decode(data) do
        :erlang.binary_to_term(data, [:safe])
      end
    end
    """
    |> to_source_file()
    |> run_check(UnsafeDeserialization)
    |> refute_issues()
  end

  # ── CWE-20: Improper Input Validation ───────────────────────────────

  alias OeditusCredo.Check.Security.ImproperInputValidation

  test "CWE-20: no issue when changeset is used" do
    """
    defmodule MyApp do
      def create(conn, params) do
        changeset = User.changeset(%User{}, params)
        Repo.insert(changeset)
      end
    end
    """
    |> to_source_file()
    |> run_check(ImproperInputValidation)
    |> refute_issues()
  end

  # ── CWE-22: Path Traversal ─────────────────────────────────────────

  alias OeditusCredo.Check.Security.PathTraversal

  test "CWE-22: reports File.read with concatenated path" do
    """
    defmodule MyApp do
      def read_file(filename) do
        File.read!("/tmp/" <> filename)
      end
    end
    """
    |> to_source_file()
    |> run_check(PathTraversal)
    |> assert_issue()
  end

  test "CWE-22: no issue for static file paths" do
    """
    defmodule MyApp do
      def read_config do
        File.read!("config/runtime.exs")
      end
    end
    """
    |> to_source_file()
    |> run_check(PathTraversal)
    |> refute_issues()
  end

  # ── CWE-434: Unrestricted File Upload ───────────────────────────────

  alias OeditusCredo.Check.Security.UnrestrictedFileUpload

  test "CWE-434: no issue when file has no upload param" do
    """
    defmodule MyApp do
      def save(conn, params) do
        File.write!("/tmp/data", params["data"])
      end
    end
    """
    |> to_source_file()
    |> run_check(UnrestrictedFileUpload)
    |> refute_issues()
  end

  # ── CWE-352: Missing CSRF Protection ────────────────────────────────

  alias OeditusCredo.Check.Security.MissingCSRFProtection

  test "CWE-352: reports API pipeline without protect_from_forgery" do
    """
    defmodule MyRouter do
      pipeline :api do
        plug :accepts, ["json"]
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingCSRFProtection)
    |> assert_issue()
  end

  test "CWE-352: no issue when protect_from_forgery is present" do
    """
    defmodule MyRouter do
      pipeline :api do
        plug :accepts, ["json"]
        plug :protect_from_forgery
      end
    end
    """
    |> to_source_file()
    |> run_check(MissingCSRFProtection)
    |> refute_issues()
  end

  # ── CWE-918: SSRF ──────────────────────────────────────────────────

  alias OeditusCredo.Check.Security.SSRFVulnerability

  test "CWE-918: reports HTTPoison.get with user url variable" do
    """
    defmodule MyApp do
      def fetch(user_url) do
        HTTPoison.get(user_url)
      end
    end
    """
    |> to_source_file()
    |> run_check(SSRFVulnerability)
    |> assert_issue()
  end

  test "CWE-918: no issue for literal URL" do
    """
    defmodule MyApp do
      def fetch do
        HTTPoison.get("https://api.example.com/data")
      end
    end
    """
    |> to_source_file()
    |> run_check(SSRFVulnerability)
    |> refute_issues()
  end

  # ── CWE-367: TOCTOU ────────────────────────────────────────────────

  alias OeditusCredo.Check.Security.TOCTOU

  test "CWE-367: reports File.exists? followed by File.read" do
    """
    defmodule MyApp do
      def read_safe(path) do
        if File.exists?(path) do
          File.read!(path)
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(TOCTOU)
    |> assert_issue()
  end

  test "CWE-367: no issue for atomic File.read" do
    """
    defmodule MyApp do
      def read_safe(path) do
        case File.read(path) do
          {:ok, data} -> data
          {:error, _} -> nil
        end
      end
    end
    """
    |> to_source_file()
    |> run_check(TOCTOU)
    |> refute_issues()
  end
end
