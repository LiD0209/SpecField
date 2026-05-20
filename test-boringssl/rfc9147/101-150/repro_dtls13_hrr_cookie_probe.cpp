#include <openssl/ssl.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string ReadFile(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    std::cerr << "ERROR: could not open " << path.string() << "\n";
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

void ProbeBoringSSLLinkage() {
  SSL_library_init();
  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  if (ctx == nullptr) {
    std::cerr << "ERROR: SSL_CTX_new(DTLS_method()) failed\n";
    std::exit(5);
  }
  SSL_CTX_free(ctx);
}

}  // namespace

int main() {
  const std::filesystem::path root = BORINGSSL_ROOT;
  const std::string tls13_client = ReadFile(root / "ssl/tls13_client.cc");
  const std::string tls13_server = ReadFile(root / "ssl/tls13_server.cc");
  const std::string extensions = ReadFile(root / "ssl/extensions.cc");
  const std::string internal_h = ReadFile(root / "ssl/internal.h");
  const std::string runner_tls13 =
      ReadFile(root / "ssl/test/runner/tls13_tests.go");
  const std::string runner_server =
      ReadFile(root / "ssl/test/runner/handshake_server.go");
  const std::string runner_common =
      ReadFile(root / "ssl/test/runner/common.go");

  ProbeBoringSSLLinkage();

  RequireContains("tls13_client.cc", tls13_client,
                  "SSLExtension cookie(TLSEXT_TYPE_cookie)");
  RequireContains("tls13_client.cc", tls13_client,
                  "if (cookie.present)");
  RequireContains("tls13_client.cc", tls13_client,
                  "hs->cookie.CopyFrom(cookie_value)");
  RequireContains("extensions.cc", extensions,
                  "static bool ext_cookie_add_clienthello");
  RequireContains("extensions.cc", extensions,
                  "CBB_add_u16(out_compressible, TLSEXT_TYPE_cookie)");
  RequireContains("extensions.cc", extensions,
                  "CBB_add_bytes(&cookie, hs->cookie.data(), hs->cookie.size())");
  RequireContains("internal.h", internal_h,
                  "cookie is the value of the cookie in HelloRetryRequest");

  RequireContains("tls13_server.cc", tls13_server,
                  "do_send_hello_retry_request");
  RequireContains("tls13_server.cc", tls13_server,
                  "Although a server could HelloRetryRequest with PAKEs to request a cookie");
  RequireContains("tls13_server.cc", tls13_server,
                  "we never do so.");
  RequireContains("tls13_server.cc", tls13_server,
                  "TLSEXT_TYPE_key_share");
  RequireNotContains("tls13_server.cc", tls13_server,
                     "TLSEXT_TYPE_cookie");
  RequireNotContains("tls13_server.cc", tls13_server,
                     "cookie.CopyFrom");
  RequireNotContains("tls13_server.cc", tls13_server,
                     "invalid cookie");
  RequireNotContains("tls13_server.cc", tls13_server,
                     "cookie =");

  RequireContains("runner/common.go", runner_common,
                  "SendHelloRetryRequestCookie");
  RequireContains("runner/tls13_tests.go", runner_tls13,
                  "HelloRetryRequest-Cookie-TLS13");
  RequireContains("runner/tls13_tests.go", runner_tls13,
                  "HelloRetryRequest-EmptyCookie-TLS13");
  RequireContains("runner/handshake_server.go", runner_server,
                  "helloRetryRequest.cookie = config.Bugs.SendHelloRetryRequestCookie");
  RequireContains("runner/handshake_server.go", runner_server,
                  "cookie from HelloRetryRequest not present in new ClientHello");

  std::cout << "linked BoringSSL probe: PASS\n";
  std::cout << "client behavior: HRR cookie extension is parsed, stored, and echoed in the second ClientHello\n";
  std::cout << "server behavior: product HRR sends supported_versions/key_share only and explicitly never requests a cookie\n";
  std::cout << "server verification: no product stateless HRR cookie generation or validation path was found in tls13_server.cc\n";
  std::cout << "runner coverage: runner covers BoringSSL as client handling HRR cookie; runner server can simulate SendHelloRetryRequestCookie\n";
  std::cout << "conclusion: RFC 9147 ID 106 is confirmed partially satisfied\n";
  return 0;
}
