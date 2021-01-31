defmodule SSLTester.X509Example do
  # Like OTPExample, but use X509 to create all certs

  def start() do
    certs = make_certs()

    # Let the current process be the server that listens and accepts
    {:ok, listen_socket} = :ssl.listen(0, mk_opts(:listen, certs))
    {:ok, {_, listen_port}} = :ssl.sockname(listen_socket)
    IO.puts("Listen: port = #{inspect(listen_port)}.")

    # Spawn the client process that connects to the server
    spawn(__MODULE__, :init_connect, [listen_port, certs])

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
  def init_connect(listen_port, certs) do
    {:ok, host} = :inet.gethostname()
    {:ok, client_sock} = :ssl.connect(host, listen_port, mk_opts(:connect, certs))
    IO.puts("Connect: connected.")
    {:ok, cert} = :ssl.peercert(client_sock)
    IO.puts("Connect: peer cert: #{inspect(:public_key.pkix_decode_cert(cert, :otp))}")
    {:ok, data} = :ssl.recv(client_sock, 0)
    IO.puts("Connect: got data: #{inspect(data)}")
    IO.puts("Connect: closing and terminating.")
    :ssl.close(client_sock)
  end

  defp make_certs() do
    signer_key = X509.PrivateKey.new_ec(:secp256r1)

    signer_cert =
      X509.Certificate.self_signed(
        signer_key,
        "/CN=Signer Cert",
        template: :root_ca
      )

    device_key = X509.PrivateKey.new_ec(:secp256r1)

    device_cert =
      device_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=ABC12345678",
        signer_cert,
        signer_key
      )

    server_key = X509.PrivateKey.new_ec(:secp256r1)

    server_cert =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=Server",
        signer_cert,
        signer_key
      )

    %{
      device_cert: device_cert,
      device_key: device_key,
      signer_cert: signer_cert,
      signer_key: signer_key,
      server_cert: server_cert,
      server_key: server_key
    }
  end

  defp mk_opts(:listen, certs) do
    [
      {:active, false},
      {:verify, :verify_peer},
      {:depth, 2},
      {:server_name_indication, :disable},
      {:cacerts, [X509.Certificate.to_der(certs.signer_cert)]},
      {:cert, X509.Certificate.to_der(certs.server_cert)},
      {:key, {:ECPrivateKey, X509.PrivateKey.to_der(certs.server_key)}}
    ]
  end

  defp mk_opts(:connect, certs) do
    [
      {:active, false},
      {:verify, :verify_peer},
      {:depth, 2},
      {:server_name_indication, :disable},
      {:cacerts, [X509.Certificate.to_der(certs.signer_cert)]},
      {:cert, X509.Certificate.to_der(certs.device_cert)},
      {:key, {:ECPrivateKey, X509.PrivateKey.to_der(certs.device_key)}}
    ]
  end
end
