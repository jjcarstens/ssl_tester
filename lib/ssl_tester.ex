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

  def cert_signature(cert) do
    X509.Certificate.to_der(cert)
    |> hash_der()
  end

  def public_key_signature(cert) do
    X509.Certificate.public_key(cert)
    |> X509.PublicKey.to_der()
    |> hash_der()
  end

  def corrupt_cert(cert) do
    X509.Certificate.to_der(cert)
    |> flip_bit()
    |> X509.Certificate.from_der!()
  end

  def corrupt_public_key({ck, tbs, alg, sig}) do
    corrupted_tbs =
      Tuple.to_list(tbs)
      |> Enum.map(fn
        {:OTPSubjectPublicKeyInfo, palg, {:ECPoint, bin}} ->
          {:OTPSubjectPublicKeyInfo, palg, {:ECPoint, flip_bit(bin)}}

        val ->
          val
      end)
      |> List.to_tuple()

    {ck, corrupted_tbs, alg, sig}
  end

  defp hash_der(der) do
    :crypto.hash(:sha, der)
    |> Base.encode16()
  end

  defp flip_bit(bin) do
    len = byte_size(bin) - 1
    <<a::binary-size(len), b::7, c::1>> = bin
    flipped = if c == 1, do: 0, else: 1
    <<a::binary, b::7, flipped::1>>
  end
end
