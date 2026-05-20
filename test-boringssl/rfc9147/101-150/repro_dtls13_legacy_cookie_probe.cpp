#include <openssl/ssl.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string ReadFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    std::cerr << "ERROR: could not open " << path << "\n";
    std::exit(2);
  }
  std::ostringstream ss;
  ss << file.rdbuf();
  return ss.str();
}

void RequireContains(const std::string &name, const std::string &text,
                     const std::string &needle) {
  if (text.find(needle) == std::string::npos) {
    std::cerr << "ERROR: " << name << " did not contain expected text: "
              << needle << "\n";
    std::exit(3);
  }
}

void RequireNotContains(const std::string &name, const std::string &text,
                        const std::string &needle) {
  if (text.find(needle) != std::string::npos) {
    std::cerr << "ERROR: " << name << " unexpectedly contained text: "
              << needle << "\n";
    std::exit(4);
  }
}

std::vector<uint8_t> MinimalDTLS13ClientHelloBody(uint8_t cookie_len) {
  std::vector<uint8_t> body;
  auto add_u8 = [&](uint8_t v) { body.push_back(v); };
  auto add_u16 = [&](uint16_t v) {
    body.push_back(static_cast<uint8_t>(v >> 8));
    body.push_back(static_cast<uint8_t>(v));
  };

  add_u16(0xfefd);  // legacy_version = DTLS 1.2
  for (int i = 0; i < 32; i++) {
    add_u8(static_cast<uint8_t>(i + 1));
  }
  add_u8(0);          // legacy_session_id
  add_u8(cookie_len); // legacy_cookie
  for (uint8_t i = 0; i < cookie_len; i++) {
    add_u8(static_cast<uint8_t>(0xa0 + i));
  }

  add_u16(2);       // cipher_suites vector length
  add_u16(0x1301);  // TLS_AES_128_GCM_SHA256
  add_u8(1);        // compression_methods vector length
  add_u8(0);        // null compression

  std::vector<uint8_t> extensions;
  auto ext_u16 = [&](uint16_t v) {
    extensions.push_back(static_cast<uint8_t>(v >> 8));
    extensions.push_back(static_cast<uint8_t>(v));
  };
  ext_u16(43);  // supported_versions
  ext_u16(3);   // extension length
  extensions.push_back(2);
  ext_u16(0xfefc);  // DTLS 1.3

  add_u16(static_cast<uint16_t>(extensions.size()));
  body.insert(body.end(), extensions.begin(), extensions.end());
  return body;
}

void ProbeParserAcceptsNonZeroLegacyCookie() {
  SSL_library_init();

  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  if (ctx == nullptr) {
    std::cerr << "ERROR: SSL_CTX_new(DTLS_method()) failed\n";
    std::exit(5);
  }
  SSL *ssl = SSL_new(ctx);
  if (ssl == nullptr) {
    std::cerr << "ERROR: SSL_new failed\n";
    SSL_CTX_free(ctx);
    std::exit(5);
  }

  const std::vector<uint8_t> body = MinimalDTLS13ClientHelloBody(1);
  SSL_CLIENT_HELLO client_hello;
  if (!SSL_parse_client_hello(ssl, &client_hello, body.data(), body.size())) {
    std::cerr << "ERROR: SSL_parse_client_hello rejected the test ClientHello\n";
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    std::exit(6);
  }
  if (client_hello.dtls_cookie_len != 1 || client_hello.dtls_cookie == nullptr ||
      client_hello.dtls_cookie[0] != 0xa0) {
    std::cerr << "ERROR: parser did not expose the non-zero legacy_cookie\n";
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    std::exit(7);
  }

  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

}  // namespace

int main() {
  const std::string root = BORINGSSL_ROOT;
  const std::string extensions =
      ReadFile(root + "/ssl/extensions.cc");
  const std::string handshake_server =
      ReadFile(root + "/ssl/handshake_server.cc");
  const std::string handshake_client =
      ReadFile(root + "/ssl/handshake_client.cc");
  const std::string runner_go =
      ReadFile(root + "/ssl/test/runner/runner.go");
  const std::string runner_messages =
      ReadFile(root + "/ssl/test/runner/handshake_messages.go");
  const std::string runner_server =
      ReadFile(root + "/ssl/test/runner/handshake_server.go");

  ProbeParserAcceptsNonZeroLegacyCookie();

  RequireContains("extensions.cc", extensions,
                  "out->dtls_cookie = CBS_data(&cookie);");
  RequireContains("extensions.cc", extensions,
                  "out->dtls_cookie_len = CBS_len(&cookie);");
  RequireContains("handshake_server.cc", handshake_server,
                  "SSL_parse_client_hello");
  RequireContains("handshake_server.cc", handshake_server,
                  "negotiate_version");
  RequireContains("handshake_server.cc", handshake_server,
                  "ssl_parse_clienthello_tlsext");
  RequireNotContains("handshake_server.cc", handshake_server,
                     "dtls_cookie_len");
  RequireContains("handshake_client.cc", handshake_client,
                  "hs->dtls_cookie");

  RequireContains("handshake_messages.go", runner_messages,
                  "if m.isDTLS && !readUint8LengthPrefixedBytes(&reader, &m.cookie)");
  RequireContains("handshake_messages.go", runner_messages,
                  "len(cookie) != 0");
  RequireContains("handshake_server.go", runner_server,
                  "DTLS 1.3 forbids the legacy");
  RequireNotContains("runner.go", runner_go, "legacy_cookie");
  RequireNotContains("runner.go", runner_go, "NonZeroLegacyCookie");

  std::cout << "linked BoringSSL probe: PASS\n";
  std::cout << "parser behavior: non-zero DTLS legacy_cookie is accepted and exposed as dtls_cookie_len=1\n";
  std::cout << "server behavior: ssl/handshake_server.cc has no dtls_cookie_len rejection path\n";
  std::cout << "runner coverage: parser helper comments know DTLS 1.3 forbids legacy cookie, but runner.go has no named shim test for non-zero legacy_cookie rejection\n";
  std::cout << "conclusion: RFC 9147 IDs 102 and 108 are confirmed unsatisfied with the same root cause\n";
  return 0;
}
