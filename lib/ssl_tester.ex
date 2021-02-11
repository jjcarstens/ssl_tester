defmodule SSLTester do
  @moduledoc """
  Documentation for `SSLTester`.
  """

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
