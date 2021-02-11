# SSLTester

Learning tool for figuring out how some SSL things actually work

## Examples

### Signer certificate
```sh
$ openssl x509 -in signer_cert.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            90:47:61:21:26:6e:88:76
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Signer Cert
        Validity
            Not Before: Feb 10 19:56:51 2021 GMT
            Not After : Feb 10 20:01:51 2046 GMT
        Subject: CN = Signer Cert
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:18:e3:6e:90:90:e8:5e:10:82:55:d7:2b:15:27:
                    f5:db:b5:a5:14:35:85:d1:63:fe:0d:6f:0d:ee:21:
                    d7:b1:2c:77:9c:cd:a0:49:bb:f8:b8:55:fc:3f:78:
                    61:f2:fe:d0:82:01:01:34:cb:b8:0b:45:d6:a5:34:
                    58:fe:8e:6c:b2
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                19:AD:8D:77:CE:76:CB:6A:A3:F3:93:4C:A5:C6:7B:F4:CC:70:59:C5
            X509v3 Authority Key Identifier:
                keyid:19:AD:8D:77:CE:76:CB:6A:A3:F3:93:4C:A5:C6:7B:F4:CC:70:59:C5

    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:62:0f:59:21:8e:5b:f6:35:84:d4:57:d7:ca:8b:
         df:d2:f0:00:d8:e6:c9:b3:76:8e:09:a9:4e:74:b0:6e:57:f7:
         02:20:05:38:d0:23:cc:1c:db:9e:92:dc:e7:2b:85:67:5e:1f:
         37:c4:3c:d0:6e:20:a5:2c:ee:95:46:a8:65:3a:04:85
-----BEGIN CERTIFICATE-----
MIIBiDCCAS+gAwIBAgIJAJBHYSEmboh2MAoGCCqGSM49BAMCMBYxFDASBgNVBAMM
C1NpZ25lciBDZXJ0MB4XDTIxMDIxMDE5NTY1MVoXDTQ2MDIxMDIwMDE1MVowFjEU
MBIGA1UEAwwLU2lnbmVyIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQY
426QkOheEIJV1ysVJ/XbtaUUNYXRY/4Nbw3uIdexLHeczaBJu/i4Vfw/eGHy/tCC
AQE0y7gLRdalNFj+jmyyo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB
/wQEAwIBhjAdBgNVHQ4EFgQUGa2Nd852y2qj85NMpcZ79MxwWcUwHwYDVR0jBBgw
FoAUGa2Nd852y2qj85NMpcZ79MxwWcUwCgYIKoZIzj0EAwIDRwAwRAIgYg9ZIY5b
9jWE1FfXyovf0vAA2ObJs3aOCalOdLBuV/cCIAU40CPMHNuektznK4VnXh83xDzQ
biClLO6VRqhlOgSF
-----END CERTIFICATE-----
```

### Device certificate

```sh
$ openssl x509 -in device_cert.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 9070925567501055020 (0x7de266be6ae8b42c)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Signer Cert
        Validity
            Not Before: Feb 10 19:56:51 2021 GMT
            Not After : Mar 12 20:01:51 2022 GMT
        Subject: CN = ABC11111111
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f1:b3:56:17:01:04:a7:b7:82:4d:8f:0a:88:ff:
                    9d:e9:c8:1a:21:e5:e4:a9:36:2f:a0:ec:d7:f1:82:
                    3d:90:f7:55:76:35:db:00:38:0f:9e:a8:9d:f2:9e:
                    72:78:ec:6a:85:08:43:98:6b:c5:cb:de:00:bd:d8:
                    e6:3b:38:c9:6f
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier:
                D1:05:77:AE:FD:E0:9F:DE:53:C5:F1:25:45:46:E4:CC:85:CE:40:2B
            X509v3 Authority Key Identifier:
                keyid:19:AD:8D:77:CE:76:CB:6A:A3:F3:93:4C:A5:C6:7B:F4:CC:70:59:C5

    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:3e:bf:09:dc:ca:67:03:32:9b:32:29:ea:3a:d7:
         50:e8:08:24:b7:9a:aa:a0:ec:d3:89:b3:f8:89:62:d0:3f:55:
         02:21:00:94:48:35:ed:39:d5:88:66:80:71:2c:a0:51:b4:0c:
         46:4a:1d:5c:ff:e4:1c:67:1f:fb:e1:da:da:25:cc:6f:1a
-----BEGIN CERTIFICATE-----
MIIBnjCCAUSgAwIBAgIIfeJmvmrotCwwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL
U2lnbmVyIENlcnQwHhcNMjEwMjEwMTk1NjUxWhcNMjIwMzEyMjAwMTUxWjAWMRQw
EgYDVQQDDAtBQkMxMTExMTExMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPGz
VhcBBKe3gk2PCoj/nenIGiHl5Kk2L6Ds1/GCPZD3VXY12wA4D56onfKecnjsaoUI
Q5hrxcveAL3Y5js4yW+jfDB6MAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgWgMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU0QV3rv3gn95T
xfElRUbkzIXOQCswHwYDVR0jBBgwFoAUGa2Nd852y2qj85NMpcZ79MxwWcUwCgYI
KoZIzj0EAwIDSAAwRQIgPr8J3MpnAzKbMinqOtdQ6Agkt5qqoOzTibP4iWLQP1UC
IQCUSDXtOdWIZoBxLKBRtAxGSh1c/+QcZx/74draJcxvGg==
-----END CERTIFICATE-----
```