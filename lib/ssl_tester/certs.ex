defmodule SSLTester.Certs do
  require X509.ASN1

  defstruct [
    :signer,
    :device,
    :device2,
    :ca,
    :server
  ]

  @type corruption() :: :bad_signature | :expired

  @type cert_key_pair() :: {X509.Certificate.t(), X509.PrivateKey.t()}
  @type t() :: %__MODULE__{
          signer: cert_key_pair(),
          device: cert_key_pair(),
          device2: cert_key_pair(),
          ca: cert_key_pair(),
          server: cert_key_pair()
        }

  @spec new() :: t()
  def new() do
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

    %__MODULE__{
      device: {device_cert, device_key, :signer},
      device2: {device2_cert, device2_key, :signer},
      signer: {signer_cert, signer_key, :signer},
      ca: {ca_cert, ca_key, :ca},
      server: {server_cert, server_key, :ca}
    }
  end

  @spec cert(t(), atom(), [corruption()]) :: X509.Certificate.t()
  def cert(certs, name, corruptions \\ []) do
    {cert, _key, signer_name} = Map.fetch!(certs, name)
    preliminary_cert = Enum.reduce(corruptions, cert, &do_corruption/2)

    if :bad_signature in corruptions do
      preliminary_cert
    else
      {_signer_cert, signer_key, _} = Map.fetch!(certs, signer_name)
      resign(preliminary_cert, signer_key)
    end
  end

  defp resign(cert, signer_key) do
    cert
    |> X509.ASN1.otp_certificate(:tbsCertificate)
    |> :public_key.pkix_sign(signer_key)
    |> X509.Certificate.from_der!()
  end

  @spec cert_as_pem(t(), atom(), [atom()]) :: String.t()
  def cert_as_pem(certs, name, corruptions \\ []) do
    certs
    |> cert(name, corruptions)
    |> X509.Certificate.to_pem()
  end

  @spec private_key(t(), atom()) :: X509.PrivateKey.t()
  def private_key(certs, name) do
    {_cert, key} = Map.fetch!(certs, name)
    key
  end

  defp do_corruption(:bad_signature, cert) do
    corrupted_signature =
      X509.ASN1.otp_certificate(cert, :signature)
      |> flip_bit()

    X509.ASN1.otp_certificate(cert, signature: corrupted_signature)
  end

  defp do_corruption(:expired, cert) do
    {:ok, not_before, 0} = DateTime.from_iso8601("2018-01-01T00:00:00Z")
    {:ok, not_after, 0} = DateTime.from_iso8601("2018-12-31T23:59:59Z")
    new_validity = X509.Certificate.Validity.new(not_before, not_after)

    tbs_cert = X509.ASN1.otp_certificate(cert, :tbsCertificate)
    new_tbs_cert = X509.ASN1.tbs_certificate(tbs_cert, validity: new_validity)

    X509.ASN1.otp_certificate(cert, tbsCertificate: new_tbs_cert)
  end

  @spec save(t()) :: :ok
  def save(certs) do
    File.write!("device_cert.pem", cert_as_pem(certs, :device))
    File.write!("device2_cert.pem", cert_as_pem(certs, :device2))
    File.write!("signer_cert.pem", cert_as_pem(certs, :signer))
  end

  defp flip_bit(bin) do
    len = byte_size(bin) - 1
    <<a::binary-size(len), b::7, c::1>> = bin
    flipped = if c == 1, do: 0, else: 1
    <<a::binary, b::7, flipped::1>>
  end
end
