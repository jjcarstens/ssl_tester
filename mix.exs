defmodule SSLTester.MixProject do
  use Mix.Project

  def project do
    [
      app: :ssl_tester,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ssl],
      mod: {SSLTester.Application, []}
    ]
  end

  defp deps do
    [
      {:x509, "~> 0.8"}
    ]
  end
end
