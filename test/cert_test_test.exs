defmodule CertTestTest do
  use ExUnit.Case
  doctest CertTest

  def create_certs() do
    ca_key = X509.PrivateKey.new_ec(:secp256r1)

    ca =
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
        "/C=US/ST=CA/L=San Francisco/O=Acme/CN=Sample",
        ca,
        ca_key
      )

    %{device_cert: device_cert, device_key: device_key, ca_cert: ca_cert, ca_key: ca_key}
  end

  test "greets the world" do
    assert CertTest.hello() == :world
  end
end
