# PKI Instructions

## Mock Azure Federated SSO Certificate

For testing purposes, we need to create a mock SAML assertion validation
certificate and associated private key.

First, create `assets/idp/azure_ad_app_signing_openssl.conf`:

```
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints=CA:FALSE
nsCertType = client, server, email
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName = @alt_names

[alt_names]
DNS.0 = localhost
IP.0 = 127.0.0.1

[v3_ext]
```

Next, generate a federated SSO certificate:

```bash
openssl req -x509 -sha256 -nodes \
  -config assets/idp/azure_ad_app_signing_openssl.conf \
  -subj "/CN=Mock Azure Federated SSO Certificate" \
  -days 1095 -newkey rsa:2048 \
  -keyout assets/idp/azure_ad_app_signing_key.pem \
  -out assets/idp/azure_ad_app_signing_cert.pem \
  -extensions v3_ext
```

The `azure_ad_app_signing_key.pem` is in PKCS#8 format.
The testing requires PKCS#1 format.

```bash
openssl rsa -in assets/idp/azure_ad_app_signing_key.pem \
  -out assets/idp/azure_ad_app_signing_pkcs1_key.pem
```

By replacing `-extensions v3_ext` with `-extensions v3_req` in the above
command, the following X509v3 extensions extensions would be added:

```
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Cert Type:
                SSL Client, SSL Server, S/MIME
            X509v3 Key Usage:
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication, Code Signing, E-mail Protection
            X509v3 Subject Key Identifier:
                50:15:0F:E2:4C:1B:E0:1A:D5:58:C5:5F:69:66:84:22:2A:1B:F9:9B
            X509v3 Authority Key Identifier:
                keyid:50:15:0F:E2:4C:1B:E0:1A:D5:58:C5:5F:69:66:84:22:2A:1B:F9:9B
```

As the result of the above command, the `assets/idp/azure_ad_app_signing_cert.pem`
contains mock "Mock Azure Federated SSO Certificate":

```
$ openssl x509 -noout -text -in assets/idp/azure_ad_app_signing_cert.pem
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a8:fa:03:b7:0c:cb:87:1d
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Mock Azure Federated SSO Certificate
        Validity
            Not Before: Apr 20 22:11:01 2020 GMT
            Not After : Apr 20 22:11:01 2023 GMT
        Subject: CN=Mock Azure Federated SSO Certificate
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ... omitted ...
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
         ... omitted ...
```

## Signing XML SAML Response

The understanding of the `Signature` element of `samlp:Response => Assertion` (see
[here](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)) is
rooted in the understanding of the
[XML Signature Syntax and Processing Version 2.0](https://www.w3.org/TR/xmldsig-core2/)
specification.

The below demonstration is a way to put the theory into practice.

First, install `signxml` from [XML-Security/signxml](https://github.com/XML-Security/signxml):

```bash
pip3 install signxml --user
```

Next, add the previously generated certificate to local system's trust store.
In RHEL, run the following commands:

```bash
sudo cp assets/idp/azure_ad_app_signing_cert.pem /etc/pki/ca-trust/source/anchors/mock_azure_ad_app_signing_cert.pem
sudo update-ca-trust extract
```

After running the above commands, the certificate was added to
`/etc/pki/tls/certs/ca-bundle.trust.crt`. It contains the list of CA
certificates in the extended `BEGIN/END TRUSTED CERTIFICATE` file format.
It includes trust (and/or distrust) flags specific to certificate usage. This
file is a symbolic link that refers to the consolidated output created by
the `update-ca-trust` command.

```bash
cat /etc/pki/tls/certs/ca-bundle.trust.crt | grep Azure
# Mock Azure Federated SSO Certificate
```

Note: if necessary, delete the trust by removing the key from `certifi/cacert.pem`
and local system:

```bash
sudo rm -rf /etc/pki/ca-trust/source/anchors/mock_azure_ad_app_signing_cert.pem
sudo update-ca-trust extract
```

Although the "Mock Azure Federated SSO Certificate" is in local system's trust
store, an attempt to test the signing will likely fail, because the trust is
being maintained elsewhere.

```bash
$ python3 assets/scripts/test_app_signing_cert.py

signxml.exceptions.InvalidCertificate: [18, 0, 'self signed certificate']
```

In OpenSSL, `SSL_CTX_use_certificate_file` installs a client certificate. It
does not specify the list of trusted CAs that may be used to verify a cert.

The [SSL_CTX_load_verify_locations()](https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_load_verify_locations.html)
specifies the locations at which CA certificates for verification purposes are
located.

In this demo, it is managed via `certifi` trust store at
`~/.local/lib/python3.6/site-packages/certifi/cacert.pem`.

Add the `assets/idp/azure_ad_app_signing_cert.pem` to the end of that trust
store:

```bash
echo "# Mock Azure Federated SSO Certificate" >> ~/.local/lib/python3.6/site-packages/certifi/cacert.pem
cat assets/idp/azure_ad_app_signing_cert.pem >> ~/.local/lib/python3.6/site-packages/certifi/cacert.pem
```

After the fix, it works:

```
$ python3 assets/scripts/test_app_signing_cert.py
```

The output is:

```xml
<Test>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>KP3ncf09YSgkeTt+i4PR+W0AMvUTo7M8gu0z15piPMc=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>BPqeeBYmknTfKbm1w/6yGErKByqLGRO9/K9wRICDVo+vIDmLEKhQgJk0nBRbdVC2XAY2LviqdVgFBWaUEceY4GaBMHdEZRqVWrUFcHK9aVQB6GCfHzHSibKcHpzSg2DUe58gaNCoZ0hjcwSo5nS6fcTWeMb6NSXsERAHbixZnkG3GrkHVdv3bIpMWfc6jhP5LgVmUpcDrTUD4c8MW3k82Dwe2ism0fka+7GkFwIagsyxI5Ii6hKosS1J0ILezHV62y0vKDV6547wK1lcE/BZSVY4i4M4sSEw6iSpZdSMK/tf/eBclXvg3Wp4sjZcfjmv/zaUWPDRspgjBMBEWJdtjQ==</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIIC3zCCAcegAwIBAgIJALsHQg/c6+1VMA0GCSqGSIb3DQEBCwUAMC8xLTArBgNV
BAMMJE1vY2sgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMDA0
MjAyMjM5NDFaFw0yMzA0MjAyMjM5NDFaMC8xLTArBgNVBAMMJE1vY2sgQXp1cmUg
RmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANOkIJv/yIbTb866HU/AST4SgZniIeyMtRmNcO3HGswQRzQD0LDn
tKki+QnvOjrrSAG/TZ5y1pl7l+Tw4t2FmbRlFInJZOojx9/UPnXgi7fv4mckSiae
c0zCZ14LQzXR0QEgttFqTAaaaPOlM9iNhAGpQ+3AXGxf7o3hweoinvRgsBUmfzKY
1QIK4arGcJu+Tcl7OwL4eMDAyS9UOXfNgpI/mlpYoTgFIsTSxlwqEsso1ZwzExc2
JVSRfgpaO88nDvJz6L1+O782z6jmvRjT/7GHXSV8oc8n/n0SOI6TJhjpXj0Kpzg1
BjpESv+uQooDbQJAnI8mMvJ1osycH4ucwKECAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAnA3iX6bPxI4iHJ/KcN8VvI0u7FVw+ojFjHJ65sRyQfdSXXbXym2Cl3/NgeVx
qFQn7knrV8mQn6ppWb07bDhZzjBU442ROZIt8YzsEc9nm2q0M1zdiQHDL99eZEDy
MHYHv3kcqNzTAKsHdRgZUMF+a8wTTZCVK+484hEtwxOyzrxSDwLTw3j2E77hb9s/
xwziwzIuOFtQh1ZIVgI1smnFXhaWi9JMK/GFEmsV4idcKAQpBZRjGXzBnVjfxKny
mBNtBC1oZDIComyO9aRbDOf8UaYbev4zKdegOK60tpQl0REO2GU8W39fr/Kym6BE
MJRj5+NfKgYjEG1rTSWL4TX13w==
</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
</Test>
```
