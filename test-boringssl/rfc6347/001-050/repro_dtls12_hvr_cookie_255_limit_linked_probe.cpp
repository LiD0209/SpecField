#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

static std::string ReadFile(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static bool Contains(const std::string &s, const std::string &needle) {
  return s.find(needle) != std::string::npos;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: repro_dtls12_hvr_cookie_255_limit_linked_probe "
                 "<boringssl-root>\n";
    return 2;
  }

  const std::string root = argv[1];
  bool ok = true;
  auto check = [&](const char *name, bool condition) {
    std::cout << name << ": " << (condition ? "PASS" : "FAIL") << "\n";
    ok = ok && condition;
  };

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
      SSL_CTX_new(DTLS_method()), SSL_CTX_free);
  check("LINK SSL_CTX_new(DTLS_method)", ctx != nullptr);
  if (ctx) {
    check("LINK DTLS1_2_VERSION min/max",
          SSL_CTX_set_min_proto_version(ctx.get(), DTLS1_2_VERSION) == 1 &&
              SSL_CTX_set_max_proto_version(ctx.get(), DTLS1_2_VERSION) == 1);
  }
  std::cout << "LINK OpenSSL_version: " << OpenSSL_version(OPENSSL_VERSION)
            << "\n";

  const std::string client = ReadFile(root + "/ssl/handshake_client.cc");
  const std::string runner_messages =
      ReadFile(root + "/ssl/test/runner/handshake_messages.go");
  const std::string runner_basic =
      ReadFile(root + "/ssl/test/runner/basic_tests.go");

  check("PRODUCT HVR parser uses u8 length-prefixed cookie",
        Contains(client, "CBS_get_u8_length_prefixed(&hello_verify_request, &cookie)") &&
            Contains(client, "hs->dtls_cookie.CopyFrom(cookie)") &&
            Contains(client, "CBS_len(&hello_verify_request) != 0"));

  check("PRODUCT HVR parser has no obsolete 32-byte cookie cap",
        !Contains(client, "cookieLen > 32") &&
            !Contains(client, "CBS_len(&cookie) > 32") &&
            !Contains(client, "dtls_cookie.size() > 32"));

  check("RUNNER HVR unmarshal rejects cookieLen > 32",
        Contains(runner_messages, "cookieLen := int(data[6])") &&
            Contains(runner_messages,
                     "if cookieLen > 32 || len(data) != 7+cookieLen"));

  check("RUNNER has DTLS-HelloVerifyRequest-255 test vector",
        Contains(runner_basic, "DTLS-HelloVerifyRequest-255") &&
            Contains(runner_basic, "HelloVerifyRequestCookieLength: 255"));

  check("RUNNER comments acknowledge RFC 6347 255-byte limit",
        Contains(runner_basic, "DTLS 1.2 allows up to a 255-byte HelloVerifyRequest cookie"));

  return ok ? 0 : 1;
}
