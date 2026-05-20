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

static int CountContains(const std::string &s, const std::string &needle) {
  int count = 0;
  size_t pos = 0;
  while ((pos = s.find(needle, pos)) != std::string::npos) {
    count++;
    pos += needle.size();
  }
  return count;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: repro_dtls12_hvr_serverhello_version_linked_probe "
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
  const std::string internal = ReadFile(root + "/ssl/internal.h");

  check("HVR parser reads server_version into a local variable",
        Contains(client, "uint16_t server_version;") &&
            Contains(client, "CBS_get_u16(&hello_verify_request, &server_version)"));

  check("HVR parser stores cookie but not server_version",
        Contains(client, "hs->dtls_cookie.CopyFrom(cookie)") &&
            Contains(client, "hs->received_hello_verify_request = true") &&
            !Contains(client, "hvr_server_version") &&
            !Contains(client, "hello_verify_request_version"));

  check("SSL_HANDSHAKE state has dtls_cookie but no HVR server_version field",
        Contains(internal, "Array<uint8_t> dtls_cookie;") &&
            Contains(internal, "received_hello_verify_request") &&
            !Contains(internal, "hvr_server_version") &&
            !Contains(internal, "hello_verify_request_version"));

  check("ServerHello parsing derives version from ServerHello only",
        Contains(client, "ParsedServerHello server_hello;") &&
            Contains(client, "parse_server_version(hs, &server_version, &alert, server_hello)") &&
            Contains(client, "ssl->s3->version = server_version"));

  check("No explicit HVR-to-ServerHello server_version equality check",
        !Contains(client, "received_hello_verify_request && server_version") &&
            !Contains(client, "dtls_cookie") ||
            CountContains(client, "received_hello_verify_request") <= 7);

  std::cout << "received_hello_verify_request occurrences in client: "
            << CountContains(client, "received_hello_verify_request") << "\n";

  return ok ? 0 : 1;
}
