defmodule Mix.Tasks.Compile.KpqcNif do
  use Mix.Task.Compiler

  @recursive true

  @impl true
  def run(_args) do
    app_path = Mix.Project.app_path()
    File.mkdir_p!(Path.join(app_path, "priv"))

    env = [
      {"ERTS_INCLUDE_DIR", erts_include_dir()},
      {"MIX_APP_PATH", app_path},
      {"KPQC_CPPFLAGS", test_entropy_flag()}
    ]

    case System.cmd("make", [],
           cd: Mix.Project.project_file() |> Path.dirname(),
           env: env,
           into: IO.stream(:stdio, :line)
         ) do
      {_, 0} -> {:ok, []}
      {_, _status} -> {:error, []}
    end
  end

  @impl true
  def clean do
    System.cmd("make", ["clean"],
      cd: Mix.Project.project_file() |> Path.dirname(),
      env: [{"MIX_APP_PATH", Mix.Project.app_path()}],
      into: IO.stream(:stdio, :line)
    )

    :ok
  end

  defp erts_include_dir do
    root = :code.root_dir() |> List.to_string()
    version = :erlang.system_info(:version) |> List.to_string()
    Path.join([root, "erts-#{version}", "include"])
  end

  defp test_entropy_flag do
    if System.get_env("KPQC_TEST_ENTROPY") == "1", do: "-DKPQC_TEST_ENTROPY", else: ""
  end
end

defmodule KpqC.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/KpqC/kpqc-elixir"

  def project do
    [
      app: :kpqc,
      version: @version,
      elixir: "~> 1.14",
      compilers: [:kpqc_nif] ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Elixir bindings for the KpqC post-quantum cryptographic algorithms",
      package: package(),
      source_url: @source_url,
      docs: [main: "readme", extras: ["README.md", "THIRD_PARTY_NOTICES.md"]]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.36.1", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: [
        "lib",
        "c_src/**/*.c",
        "c_src/**/*.h",
        "c_src/**/LICENSE",
        ".formatter.exs",
        "LICENSE",
        "Makefile",
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "mix.exs"
      ]
    ]
  end
end
