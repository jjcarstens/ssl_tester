defmodule SSLTester.Certs do
  defstruct [:device_cert, :device_key, :ca_cert, :ca_key]

  def new() do
    ca_key = X509.PrivateKey.new_ec(:secp256r1)

    ca_cert =
      X509.Certificate.self_signed(
        ca_key,
        "/CN=Signer Cert",
        template: :root_ca
      )

    device_key = X509.PrivateKey.new_ec(:secp256r1)

    device_cert =
      device_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=ABC12345678",
        ca_cert,
        ca_key
      )

    %__MODULE__{
      device_cert: device_cert,
      device_key: device_key,
      ca_cert: ca_cert,
      ca_key: ca_key
    }
  end

  def server_ssl_opts(%__MODULE__{} = certs) do
    [
      fail_if_no_peer_cert: true,
      verify: :verify_peer,
      # cacerts is temporary
      cacerts: [X509.Certificate.to_der(certs.ca_cert)]
    ]
  end

  def client_ssl_opts(%__MODULE__{} = certs) do
    [
      cert: X509.Certificate.to_der(certs.device_cert),
      key: {:ECPrivateKey, X509.PrivateKey.to_der(certs.device_key)},
      # Don't check the server certs, since we don't care for this experiment
      verify: :verify_none
    ]
  end
end
