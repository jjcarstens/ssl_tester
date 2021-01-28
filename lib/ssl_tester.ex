defmodule SSLTester do
  @moduledoc """
  Documentation for `SSLTester`.
  """

  def run() do
    certs = SSLTester.Certs.new()
    port = 9999

    IO.puts("Starting server on port #{port}")

    {:ok, _server_pid} =
      SSLTester.Server.start_link(port: port, ssl_opts: SSLTester.Certs.server_ssl_opts(certs))

    Process.sleep(100)
    IO.puts("Connecting...")

    {:ok, socket} =
      :ssl.connect(
        'localhost',
        port,
        [active: false] ++ SSLTester.Certs.client_ssl_opts(certs),
        1010
      )

    :ssl.recv(socket, 0, 1234)
  end
end
