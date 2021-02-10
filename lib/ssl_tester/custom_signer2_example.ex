defmodule SSLTester.CustomSigner2Example do
  require X509.ASN1

  @moduledoc """
  Build off CustomSignerExample that is more realistic

  """

  def start() do
    certs = make_certs()

    # Let the current process be the server that listens and accepts
    {:ok, listen_socket} = :ssl.listen(0, mk_opts(:listen, certs))
    {:ok, {_, listen_port}} = :ssl.sockname(listen_socket)
    IO.puts("Listen: port = #{inspect(listen_port)}.")

    # Accept
    for run <- [:connect, :connect2] do
      # Spawn the client process that connects to the server
      spawn(fn -> test_connect(listen_port, mk_opts(run, certs)) end)

      {:ok, accept_sock} = :ssl.transport_accept(listen_socket)
      {:ok, ssl_listen_socket} = :ssl.handshake(accept_sock)
      IO.puts("Accept: accepted.")
      {:ok, cert} = :ssl.peercert(ssl_listen_socket)
      IO.puts("Accept: peer cert: #{inspect(:public_key.pkix_decode_cert(cert, :otp))}")
      IO.puts("Accept: sending \"hello\".")
      :ok = :ssl.send(ssl_listen_socket, "hello")
      {:error, :closed} = :ssl.recv(ssl_listen_socket, 0)
      IO.puts("Accept: detected closed.")
      :ok = :ssl.close(ssl_listen_socket)
    end

    IO.puts("Listen: closing and terminating.")
    :ssl.close(listen_socket)
  end

  # Client connect
  def test_connect(listen_port, ssl_opts) do
    {:ok, host} = :inet.gethostname()
    {:ok, client_sock} = :ssl.connect(host, listen_port, ssl_opts)
    IO.puts("Connect: connected.")
    {:ok, _cert} = :ssl.peercert(client_sock)
    #    IO.puts("Connect: peer cert: #{inspect(:public_key.pkix_decode_cert(cert, :otp))}")
    {:ok, 'hello'} = :ssl.recv(client_sock, 0)
    :ok = :ssl.close(client_sock)
    IO.puts("Client successful received \"hello\"")
  end

  def make_certs() do
    signer_key = X509.PrivateKey.new_ec(:secp256r1)

    signer_cert =
      X509.Certificate.self_signed(
        signer_key,
        "/CN=Signer Cert",
        template: :root_ca
      )

    # The CA is for the device to verify the server
    ca_key = X509.PrivateKey.new_ec(:secp256r1)

    ca_cert =
      X509.Certificate.self_signed(
        ca_key,
        "/CN=Trusted CA Cert",
        template: :root_ca
      )

    device_key = X509.PrivateKey.new_ec(:secp256r1)

    device_cert =
      device_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=ABC11111111",
        signer_cert,
        signer_key
      )

    device2_key = X509.PrivateKey.new_ec(:secp256r1)

    device2_cert =
      device2_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=ABC22222222",
        signer_cert,
        signer_key
      )

    server_key = X509.PrivateKey.new_ec(:secp256r1)

    server_cert =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=Server",
        ca_cert,
        ca_key
      )

    %{
      device_cert: device_cert,
      device_key: device_key,
      device2_cert: device2_cert,
      device2_key: device2_key,
      signer_cert: signer_cert,
      signer_key: signer_key,
      ca_cert: ca_cert,
      ca_key: ca_key,
      server_cert: server_cert,
      server_key: server_key
    }
  end

  defp mk_opts(:listen, certs) do
    device_pub_key = X509.PublicKey.derive(certs.device_key)

    [
      {:active, false},
      {:verify, :verify_peer},
      {:verify_fun,
       {&verify_pub_key/3,
        %{pinned_public_keys: [device_pub_key], authorized_signer: certs.signer_cert}}},
      {:depth, 2},
      {:server_name_indication, :disable},
      {:cacerts, []},
      {:cert, X509.Certificate.to_der(certs.server_cert)},
      {:key, {:ECPrivateKey, X509.PrivateKey.to_der(certs.server_key)}}
    ]
  end

  defp mk_opts(:connect, certs) do
    # Client questions:
    #   1. Should the certificate or public key be pinned?
    #   2. What happens on certificate expirations

    # Passing the signer cert in the cacerts list feels yucky since we wouldn't
    # accept a server that was signed with the signer cert. AWS IoT requires the
    # signer certs to be sent up. NH hasn't, but perhaps it should? Doesn't AWS
    # know something about the AKI not being reliable for CA cert lookup? Or is
    # there an infrastructure decision with AWS that requires the full chain?
    [
      {:active, false},
      {:verify, :verify_peer},
      {:depth, 3},
      {:server_name_indication, :disable},
      {:cacerts,
       [X509.Certificate.to_der(certs.ca_cert), X509.Certificate.to_der(certs.signer_cert)]},
      {:cert, X509.Certificate.to_der(certs.device_cert)},
      {:key, {:ECPrivateKey, X509.PrivateKey.to_der(certs.device_key)}}
    ]
  end

  defp mk_opts(:connect2, certs) do
    # Client questions:
    #   1. Should the certificate or public key be pinned?
    #   2. What happens on certificate expirations

    # Passing the signer cert in the cacerts list feels yucky since we wouldn't
    # accept a server that was signed with the signer cert. AWS IoT requires the
    # signer certs to be sent up. NH hasn't, but perhaps it should? Doesn't AWS
    # know something about the AKI not being reliable for CA cert lookup? Or is
    # there an infrastructure decision with AWS that requires the full chain?
    [
      {:active, false},
      {:verify, :verify_peer},
      {:depth, 3},
      {:server_name_indication, :disable},
      {:cacerts,
       [X509.Certificate.to_der(certs.ca_cert), X509.Certificate.to_der(certs.signer_cert)]},
      {:cert, X509.Certificate.to_der(certs.device2_cert)},
      {:key, {:ECPrivateKey, X509.PrivateKey.to_der(certs.device2_key)}}
    ]
  end

  defp verify_pub_key(cert, {:bad_cert, :unknown_ca}, state) do
    IO.puts("--> verify_pub_key unknown CA. This is expected when the chain is being passed")
    # Collect the signers. This may or may not be interesting
    new_signers = [cert | Map.get(state, :signers, [])]
    {:valid, Map.put(state, :signers, new_signers)}
  end

  defp verify_pub_key(cert, {:bad_cert, reason}, state) do
    # NOTE: what happens then signer certs expire????
    IO.puts("--> verify_pub_key bad cert: #{inspect(reason)}")
    IO.puts("   cert=#{inspect(cert)}")
    {:valid, state}
  end

  defp verify_pub_key(_cert, {:extension, extension}, state) do
    IO.puts("--> verify_pub_key got extension: #{inspect(extension)}")
    # The AKI could be found here.
    {:unknown, state}
  end

  defp verify_pub_key(cert, :valid, _state) do
    IO.puts("--> verify_pub_key told of a valid cert: #{inspect(cert)}")
    {:fail, :totally_not_expecting_a_valid_signer_cert}
  end

  defp verify_pub_key(cert, :valid_peer, state) do
    IO.puts("--> verify_pub_key told of a valid peer: #{inspect(cert)}")

    pub_key_in_cert = X509.Certificate.public_key(cert)

    # pub_key_hash = X509.PublicKey.to_der(pub_key_in_cert) |> :crypto.hash(:sha) |> Base.encode16()

    # DB lookup is on pub_key_hash. Returns device record?

    [id_from_cert] = X509.Certificate.subject(cert, X509.ASN1.oid(:"id-at-commonName"))
    IO.puts("--> Device is #{inspect(id_from_cert)} and pubkey=#{inspect(pub_key_in_cert)}")

    if pub_key_in_cert in state.pinned_public_keys do
      IO.puts(" --> Known public key, so OK!")
      {:valid, state}
    else
      IO.puts(" --> Unknown public key, so check cert chain")

      # Simulate looking up the AKI and CN - perhaps grab them both out of the extension list?
      X509.ASN1.extension(extnValue: X509.ASN1.authority_key_identifier(keyIdentifier: aki)) =
        X509.Certificate.extension(cert, :authority_key_identifier)

      X509.ASN1.extension(extnValue: known_signer_ski) =
        X509.Certificate.extension(state.authorized_signer, :subject_key_identifier)

      # Do we know that the AKI signed this certificate? - Corrupt the signature to find out????
      # NH looks up the org based on the AKI. Is this ok?
      # It would be cool to provision this device
      if aki == known_signer_ski do
        # Save the cert in the DB, pin the public key to mark it as "trusted"
        {:valid, state}
      else
        {:fail, :not_allowed}
      end
    end
  end
end
