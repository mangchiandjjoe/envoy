#include <string>

namespace Envoy {
namespace Testdata {

std::string kExpectedCertificateChain =
    R"EOF(-----BEGIN CERTIFICATE-----
MIIDEDCCAnmgAwIBAgIJAKnPQcNyJm/aMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMQ0wCwYDVQQKEwRMeWZ0MRkwFwYDVQQLExBMeWZ0IEVuZ2luZWVyaW5nMRQw
EgYDVQQDEwtUZXN0IFNlcnZlcjAeFw0xNzA3MDkwMTM5MzJaFw0xOTA3MDkwMTM5
MzJaMHoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKEwRMeWZ0MRkwFwYDVQQLExBMeWZ0IEVu
Z2luZWVyaW5nMRQwEgYDVQQDEwtUZXN0IFNlcnZlcjCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEAqy+9qxHrAhi/o4GlshCoalUxMXxHBmE2vyxMs1rejBfwOl3y
IyA9r7oaHtMrqXxfF5TdjRvKWpj7dbAwGjhSOrPKXRjhT543BCAbSisCpMlA/CP7
GaNfYLOtgBHU5mz8BlXY2fLBUORnHRlFbL/myIl3oeNhuLsUNjIlJSSflL0CAwEA
AaOBnTCBmjAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggr
BgEFBQcDAgYIKwYBBQUHAwEwHgYDVR0RBBcwFYITc2VydmVyMS5leGFtcGxlLmNv
bTAdBgNVHQ4EFgQU8/1SRZup5ukZHvtfSaI/OXXXUJIwHwYDVR0jBBgwFoAU8/1S
RZup5ukZHvtfSaI/OXXXUJIwDQYJKoZIhvcNAQELBQADgYEAhOZvHhxvktcKwgVF
MoCp/sOlOV1NXHNndZxZl4uHpoUqXnTycp4VrniiQD5O6w5PjZliILpSyZTUm5HK
uXF9gTlCv9G2Y8NMXPDV13G1UuGeS4nC/Pxe55+QgHL7xyReOpJvA8grWL+dCece
Rk7e1/bKUaWuGEx0erYHNKEnpkY=
-----END CERTIFICATE-----
)EOF";

std::string kExpectedPrivateKey =
    R"EOF(-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCrL72rEesCGL+jgaWyEKhqVTExfEcGYTa/LEyzWt6MF/A6XfIj
ID2vuhoe0yupfF8XlN2NG8pamPt1sDAaOFI6s8pdGOFPnjcEIBtKKwKkyUD8I/sZ
o19gs62AEdTmbPwGVdjZ8sFQ5GcdGUVsv+bIiXeh42G4uxQ2MiUlJJ+UvQIDAQAB
AoGAGrFQBtu9ZE9NmoY9uv1D9YihKhEx1fnUmoyizRivOPMGn2NEvVtqovsG1aWh
2kStYzTwMu+RZv0RwLEfXwdHMuTGEwcqLi0c/FskUIOXZvBl9Ev7P6Yr11C5SQHe
U/Fm2rhPVcKs/UyUzT2R7dMtkhCc7Yl3koDZWX2XC9wjzsECQQDWf9T1UifSszrP
Vb0QYyva4gniPPEUQJnqsCNfKo1AyzIzCBrdxgIeO44Izjourpvrs2/6BvvF0nxx
/Y8ogfixAkEAzE6ewRohxnm0OBRL2Pcjj6EW7wJuxH4PS3E01lrwsKrgO1B04SgZ
pqDA7qrEttya/O/OP02P1HfaZOEHqc4fzQJBAL/i85vStxViiQXZ6ZyzWxQgij79
zZ0UfZzZnYsRAfQo0uucIIytClAJbvKpqpsAUTP1/gJqJOm/dtxyvJK8UsECQF5W
Kx206EWR6rI+ROtw6h2m30ULVYQrRPqr0h7sLNkWfaVFuEJC1t1Guu85MM3SvUnv
nMdEFBaiJNiRw40XnT0CQQCcwTdtTwWojjNZfzgSzzC2k0kjWXCWYfLD/OsEeaxB
Hk8EP6nnwEi/312iSoo/BxuYUc9Y/XTKUpcMiwu7MA5b
-----END RSA PRIVATE KEY-----
)EOF";

} // namespace Testdata
} // namespace Envoy
