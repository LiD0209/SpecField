#include <openssl/ssl.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

namespace {

std::string ReadFile(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    std::cerr << "failed to open " << path << "\n";
    std::exit(2);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

void RequireContains(const std::string &name, const std::string &text,
                     const std::string &needle) {
  if (text.find(needle) == std::string::npos) {
    std::cerr << "missing evidence in " << name << ": " << needle << "\n";
    std::exit(3);
  }
  std::cout << "ok: " << name << " contains " << needle << "\n";
}

void RequireNotContains(const std::string &name, const std::string &text,
                        const std::string &needle) {
  if (text.find(needle) != std::string::npos) {
    std::cerr << "unexpected evidence in " << name << ": " << needle << "\n";
    std::exit(4);
  }
  std::cout << "ok: " << name << " does not contain " << needle << "\n";
}

std::string SliceBetween(const std::string &text, const std::string &begin,
                         const std::string &end) {
  const size_t begin_pos = text.find(begin);
  if (begin_pos == std::string::npos) {
    std::cerr << "missing slice begin: " << begin << "\n";
    std::exit(5);
  }
  const size_t end_pos = text.find(end, begin_pos);
  if (end_pos == std::string::npos) {
    std::cerr << "missing slice end: " << end << "\n";
    std::exit(6);
  }
  return text.substr(begin_pos, end_pos - begin_pos);
}

}  // namespace

int main() {
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
      SSL_CTX_new(DTLS_method()), SSL_CTX_free);
  if (!ctx) {
    std::cerr << "failed to create DTLS SSL_CTX\n";
    return 1;
  }
  std::cout << "linked BoringSSL DTLS_method successfully\n";

  const std::string root = BORINGSSL_ROOT;
  const std::string tls13_server = ReadFile(root + "/ssl/tls13_server.cc");
  const std::string tls13_client = ReadFile(root + "/ssl/tls13_client.cc");
  const std::string extensions = ReadFile(root + "/ssl/extensions.cc");
  const std::string handshake_server =
      ReadFile(root + "/ssl/handshake_server.cc");
  const std::string runner = ReadFile(root + "/ssl/test/runner/runner.go");
  const std::string runner_tls13 =
      ReadFile(root + "/ssl/test/runner/tls13_tests.go");
  const std::string runner_dtls =
      ReadFile(root + "/ssl/test/runner/dtls_tests.go");
  const std::string runner_handshake_server =
      ReadFile(root + "/ssl/test/runner/handshake_server.go");
  const std::string runner_common =
      ReadFile(root + "/ssl/test/runner/common.go");

  RequireContains("tls13_server.cc", tls13_server,
                  "state13_send_hello_retry_request");
  RequireContains("tls13_server.cc", tls13_server,
                  "Although a server could HelloRetryRequest with PAKEs to request a cookie");
  RequireContains("tls13_server.cc", tls13_server, "we never do so");
  const std::string hrr_sender =
      SliceBetween(tls13_server, "static enum ssl_hs_wait_t do_send_hello_retry_request",
                   "static enum ssl_hs_wait_t do_send_server_hello");
  RequireContains("server HRR sender", hrr_sender, "TLSEXT_TYPE_supported_versions");
  RequireContains("server HRR sender", hrr_sender, "TLSEXT_TYPE_key_share");
  RequireNotContains("server HRR sender", hrr_sender, "TLSEXT_TYPE_cookie");
  RequireNotContains("server HRR sender", hrr_sender, "hs->cookie");

  RequireContains("extensions.cc", extensions, "TLSEXT_TYPE_cookie");
  RequireContains("extensions.cc", extensions, "ext_cookie_add_clienthello");
  RequireContains("extensions.cc", extensions, "forbid_parse_serverhello");
  RequireContains("extensions.cc", extensions, "ignore_parse_clienthello");
  RequireContains("extensions.cc", extensions, "dont_add_serverhello");
  RequireContains("tls13_client.cc", tls13_client,
                  "SSLExtension cookie(TLSEXT_TYPE_cookie)");
  RequireContains("tls13_client.cc", tls13_client, "hs->cookie.CopyFrom(cookie_value)");
  RequireContains("extensions.cc", extensions, "CBB_add_bytes(&cookie, hs->cookie.data()");

  RequireContains("handshake_server.cc", handshake_server,
                  "{TLSEXT_TYPE_cookie, false}");
  RequireNotContains("server HRR sender", hrr_sender, "illegal_parameter");

  RequireContains("runner.go", runner, "addTLS13HandshakeTests()");
  RequireContains("runner.go", runner, "addDTLSRetransmitTests()");
  RequireContains("runner common.go", runner_common,
                  "SendHelloRetryRequestCookie []byte");
  RequireContains("runner tls13_tests.go", runner_tls13,
                  "HelloRetryRequest-Cookie-TLS13");
  RequireContains("runner tls13_tests.go", runner_tls13,
                  "SendHelloRetryRequestCookie: []byte(\"cookie\")");
  RequireContains("runner dtls_tests.go", runner_dtls,
                  "SendHelloRetryRequestCookie: []byte(\"cookie\")");
  RequireContains("runner handshake_server.go", runner_handshake_server,
                  "newClientHello.tls13Cookie");
  RequireContains("runner handshake_server.go", runner_handshake_server,
                  "cookie from HelloRetryRequest not present in new ClientHello");

  std::cout << "RESULT: confirmed. BoringSSL client handles HRR cookie echo, "
               "but product server HRR construction never adds a cookie and "
               "there is no server-side DTLS 1.3 stateless cookie generation/"
               "verification path. Runner coverage exercises peer-sent HRR "
               "cookies against BoringSSL clients, not BoringSSL server cookie "
               "issuance and validation.\n";
  return 0;
}
