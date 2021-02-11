defmodule SSLTester.CertsTest do
  use ExUnit.Case
  require X509.ASN1

  alias SSLTester.Certs
  doctest Certs

  test "creates certs" do
    c = Certs.new()

    assert Certs.cert(c, :device)
    assert Certs.cert(c, :device2)
    assert Certs.cert(c, :signer)
    assert Certs.cert(c, :server)
    assert Certs.cert(c, :ca)
  end

  test "certs are signed" do
    c = Certs.new()
    device_cert_der = Certs.cert_as_der(c, :device)
    device2_cert_der = Certs.cert_as_der(c, :device2)
    signer_cert_der = Certs.cert_as_der(c, :signer)
    server_cert_der = Certs.cert_as_der(c, :server)

    signer_pubkey = Certs.cert(c, :signer) |> X509.Certificate.public_key()

    # "low level" verification
    assert :public_key.pkix_verify(device_cert_der, signer_pubkey)
    assert :public_key.pkix_verify(device2_cert_der, signer_pubkey)
    assert :public_key.pkix_verify(signer_cert_der, signer_pubkey)

    # path validation
    assert {:ok, _} = :public_key.pkix_path_validation(signer_cert_der, [device_cert_der], [])
    assert {:ok, _} = :public_key.pkix_path_validation(signer_cert_der, [device2_cert_der], [])

    # Negative testing
    refute :public_key.pkix_verify(server_cert_der, signer_pubkey)

    assert {:error, {:bad_cert, :invalid_issuer}} =
             :public_key.pkix_path_validation(signer_cert_der, [server_cert_der], [])
  end

  test "creates certs with bad signatures" do
    c = Certs.new()

    good_cert = Certs.cert(c, :device)
    bad_cert = Certs.cert(c, :device, [:bad_signature])
    signer_cert_der = Certs.cert_as_der(c, :signer)

    assert X509.ASN1.otp_certificate(good_cert, :tbsCertificate) ==
             X509.ASN1.otp_certificate(bad_cert, :tbsCertificate)

    assert X509.ASN1.otp_certificate(good_cert, :signature) !=
             X509.ASN1.otp_certificate(bad_cert, :signature)

    assert {:ok, _} = :public_key.pkix_path_validation(signer_cert_der, [good_cert], [])

    assert {:error, {:bad_cert, :invalid_signature}} =
             :public_key.pkix_path_validation(signer_cert_der, [bad_cert], [])
  end

  test "creates expired certs" do
    c = Certs.new()

    good_cert = Certs.cert(c, :device)
    bad_cert = Certs.cert(c, :device, [:expired])
    signer_cert_der = Certs.cert_as_der(c, :signer)

    assert {:ok, _} = :public_key.pkix_path_validation(signer_cert_der, [good_cert], [])

    assert {:error, {:bad_cert, :cert_expired}} =
             :public_key.pkix_path_validation(signer_cert_der, [bad_cert], [])
  end
end
