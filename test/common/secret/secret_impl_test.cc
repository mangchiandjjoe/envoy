#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#include "common/secret/secret_impl.h"

#include "test/mocks/runtime/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"
#include "google/protobuf/text_format.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {

namespace {

const char kExpectedCertificateChain[] =
    R"(-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIJAON1ifrBZ2/BMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxl
MQ4wDAYDVQQKDAVJc3RpbzENMAsGA1UECwwEVGVzdDEQMA4GA1UEAwwHUm9vdCBD
QTEiMCAGCSqGSIb3DQEJARYTdGVzdHJvb3RjYUBpc3Rpby5pbzAgFw0xODAxMjQx
OTE1NTFaGA8yMTE3MTIzMTE5MTU1MVowWTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTEOMAwGA1UEChMFSXN0aW8x
ETAPBgNVBAMTCElzdGlvIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAyzCxr/xu0zy5rVBiso9ffgl00bRKvB/HF4AX9/ytmZ6Hqsy13XIQk8/u/By9
iCvVwXIMvyT0CbiJq/aPEj5mJUy0lzbrUs13oneXqrPXf7ir3HzdRw+SBhXlsh9z
APZJXcF93DJU3GabPKwBvGJ0IVMJPIFCuDIPwW4kFAI7R/8A5LSdPrFx6EyMXl7K
M8jekC0y9DnTj83/fY72WcWX7YTpgZeBHAeeQOPTZ2KYbFal2gLsar69PgFS0Tom
ESO9M14Yit7mzB1WDK2z9g3r+zLxENdJ5JG/ZskKe+TO4Diqi5OJt/h8yspS1ck8
LJtCole9919umByg5oruflqIlQIDAQABozUwMzALBgNVHQ8EBAMCAgQwDAYDVR0T
BAUwAwEB/zAWBgNVHREEDzANggtjYS5pc3Rpby5pbzANBgkqhkiG9w0BAQsFAAOC
AQEAltHEhhyAsve4K4bLgBXtHwWzo6SpFzdAfXpLShpOJNtQNERb3qg6iUGQdY+w
A2BpmSkKr3Rw/6ClP5+cCG7fGocPaZh+c+4Nxm9suMuZBZCtNOeYOMIfvCPcCS+8
PQ/0hC4/0J3WJKzGBssaaMufJxzgFPPtDJ998kY8rlROghdSaVt423/jXIAYnP3Y
05n8TGERBj7TLdtIVbtUIx3JHAo3PWJywA6mEDovFMJhJERp9sDHIr1BbhXK1TFN
Z6HNH6gInkSSMtvC4Ptejb749PTaePRPF7ID//eq/3AH8UK50F3TQcLjEqWUsJUn
aFKltOc+RAjzDklcUPeG4Y6eMA==
-----END CERTIFICATE-----
)";

const char kExpectedPrivateKey[] =
    R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyzCxr/xu0zy5rVBiso9ffgl00bRKvB/HF4AX9/ytmZ6Hqsy1
3XIQk8/u/By9iCvVwXIMvyT0CbiJq/aPEj5mJUy0lzbrUs13oneXqrPXf7ir3Hzd
Rw+SBhXlsh9zAPZJXcF93DJU3GabPKwBvGJ0IVMJPIFCuDIPwW4kFAI7R/8A5LSd
PrFx6EyMXl7KM8jekC0y9DnTj83/fY72WcWX7YTpgZeBHAeeQOPTZ2KYbFal2gLs
ar69PgFS0TomESO9M14Yit7mzB1WDK2z9g3r+zLxENdJ5JG/ZskKe+TO4Diqi5OJ
t/h8yspS1ck8LJtCole9919umByg5oruflqIlQIDAQABAoIBAGZI8fnUinmd5R6B
C941XG3XFs6GAuUm3hNPcUFuGnntmv/5I0gBpqSyFO0nDqYg4u8Jma8TTCIkmnFN
ogIeFU+LiJFinR3GvwWzTE8rTz1FWoaY+M9P4ENd/I4pVLxUPuSKhfA2ChAVOupU
8F7D9Q/dfBXQQCT3VoUaC+FiqjL4HvIhji1zIqaqpK7fChGPraC/4WHwLMNzI0Zg
oDdAanwVygettvm6KD7AeKzhK94gX1PcnsOi3KuzQYvkenQE1M6/K7YtEc5qXCYf
QETj0UCzB55btgdF36BGoZXf0LwHqxys9ubfHuhwKBpY0xg2z4/4RXZNhfIDih3w
J3mihcECgYEA6FtQ0cfh0Zm03OPDpBGc6sdKxTw6aBDtE3KztfI2hl26xHQoeFqp
FmV/TbnExnppw+gWJtwx7IfvowUD8uRR2P0M2wGctWrMpnaEYTiLAPhXsj69HSM/
CYrh54KM0YWyjwNhtUzwbOTrh1jWtT9HV5e7ay9Atk3UWljuR74CFMUCgYEA392e
DVoDLE0XtbysmdlfSffhiQLP9sT8+bf/zYnr8Eq/4LWQoOtjEARbuCj3Oq7bP8IE
Vz45gT1mEE3IacC9neGwuEa6icBiuQi86NW8ilY/ZbOWrRPLOhk3zLiZ+yqkt+sN
cqWx0JkIh7IMKWI4dVQgk4I0jcFP7vNG/So4AZECgYEA426eSPgxHQwqcBuwn6Nt
yJCRq0UsljgbFfIr3Wfb3uFXsntQMZ3r67QlS1sONIgVhmBhbmARrcfQ0+xQ1SqO
wqnOL4AAd8K11iojoVXLGYP7ssieKysYxKpgPE8Yru0CveE9fkx0+OGJeM2IO5hY
qHAoTt3NpaPAuz5Y3XgqaVECgYA0TONS/TeGjxA9/jFY1Cbl8gp35vdNEKKFeM5D
Z7h+cAg56FE8tyFyqYIAGVoBFL7WO26mLzxiDEUfA/0Rb90c2JBfzO5hpleqIPd5
cg3VR+cRzI4kK16sWR3nLy2SN1k6OqjuovVS5Z3PjfI3bOIBz0C5FY9Pmt0g1yc7
mDRzcQKBgQCXWCZStbdjewaLd5u5Hhbw8tIWImMVfcfs3H1FN669LLpbARM8RtAa
8dYwDVHmWmevb/WX03LiSE+GCjCBO79fa1qc5RKAalqH/1OYxTuvYOeTUebSrg8+
lQFlP2OC4GGolKrN6HVWdxtf+F+SdjwX6qGCfYkXJRLYXIFSFjFeuw==
-----END RSA PRIVATE KEY-----
)";

}  // namespace

class SecretImplTest : public testing::Test {
};

TEST_F(SecretImplTest, TestSecretInitializationFromProtobuf) {

  std::ifstream src;
  src.open("test/common/secret/test_data/secret.pb.txt", std::ifstream::in | std::ifstream::binary);

  EXPECT_TRUE(src.good());

  std::string contents;
  src.seekg(0, std::ios::end);
  auto size = src.tellg();
  if (size > 0) {
    contents.reserve(size);
  }
  src.seekg(0, std::ios::beg);
  contents.assign((std::istreambuf_iterator<char>(src)), (std::istreambuf_iterator<char>()));

  envoy::api::v2::auth::Secret secret;

  EXPECT_TRUE(::google::protobuf::TextFormat::ParseFromString(contents, &secret));

  SecretImpl secretImpl(secret, true);

  EXPECT_EQ(secretImpl.getCertificateChain(), kExpectedCertificateChain);
  EXPECT_EQ(secretImpl.getPrivateKey(), kExpectedPrivateKey);
  EXPECT_TRUE(secretImpl.isStatic());
}

}  // namespace Ssl
}  // namespace Envoy
