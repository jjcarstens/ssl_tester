defmodule SSLTester.OTPExample do
  def start() do
    # Let the current process be the server that listens and accepts
    {:ok, listen_socket} = :ssl.listen(0, mk_opts(:listen))
    {:ok, {_, listen_port}} = :ssl.sockname(listen_socket)
    IO.puts("Listen: port = #{inspect(listen_port)}.")

    # Spawn the client process that connects to the server
    spawn(__MODULE__, :init_connect, [listen_port])

    # Accept
    {:ok, accept_sock} = :ssl.transport_accept(listen_socket)
    {:ok, ssl_listen_socket} = :ssl.handshake(accept_sock)
    IO.puts("Accept: accepted.")
    {:ok, cert} = :ssl.peercert(ssl_listen_socket)
    IO.puts("Accept: peer cert: #{inspect(:public_key.pkix_decode_cert(cert, :otp))}")
    IO.puts("Accept: sending \"hello\".")
    _ = :ssl.send(ssl_listen_socket, "hello")
    {:error, :closed} = :ssl.recv(ssl_listen_socket, 0)
    IO.puts("Accept: detected closed.")
    _ = :ssl.close(ssl_listen_socket)
    IO.puts("Listen: closing and terminating.")
    :ssl.close(listen_socket)
  end

  # Client connect
  def init_connect(listen_port) do
    {:ok, host} = :inet.gethostname()
    {:ok, client_sock} = :ssl.connect(host, listen_port, mk_opts(:connect))
    IO.puts("Connect: connected.")
    {:ok, cert} = :ssl.peercert(client_sock)
    IO.puts("Connect: peer cert: #{inspect(:public_key.pkix_decode_cert(cert, :otp))}")
    {:ok, data} = :ssl.recv(client_sock, 0)
    IO.puts("Connect: got data: #{inspect(data)}")
    IO.puts("Connect: closing and terminating.")
    :ssl.close(client_sock)
  end

  defp mk_opts(:listen), do: mk_opts("server")
  defp mk_opts(:connect), do: mk_opts("client")

  defp mk_opts(role) do
    dir = Application.app_dir(:ssl_tester, ["priv", "certs", "etc"])

    [
      {:active, false},
      {:verify, :verify_peer},
      {:depth, 2},
      {:server_name_indication, :disable},
      {:cacertfile, Path.join([dir, role, "cacerts.pem"])},
      {:certfile, Path.join([dir, role, "cert.pem"])},
      {:keyfile, Path.join([dir, role, "key.pem"])}
    ]
  end
end
