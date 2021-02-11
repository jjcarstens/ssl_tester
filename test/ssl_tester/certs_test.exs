defmodule SSLTester.CertsTest do
  use ExUnit.Case

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
end
