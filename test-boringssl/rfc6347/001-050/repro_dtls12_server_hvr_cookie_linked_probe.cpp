#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

static std::string ReadFile(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static bool Contains(const std::string &text, const std::string &needle) {
  return text.find(needle) != std::string::npos;
}

static bool ContainsAny(const std::string &text,
                        const std::vector<std::string> &needles) {
  for (const auto &needle : needles) {
    if (Contains(text, needle)) {
      return true;
    }
  }
  return false;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: repro_dtls12_server_hvr_cookie_linked_probe "
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
  const std::string server = ReadFile(root + "/ssl/handshake_server.cc");
  const std::string handshake = ReadFile(root + "/ssl/handshake.cc");
  const std::string extensions = ReadFile(root + "/ssl/extensions.cc");
  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");
  const std::string d1_pkt = ReadFile(root + "/ssl/d1_pkt.cc");
  const std::string ssl_h = ReadFile(root + "/include/openssl/ssl.h");
  const std::string runner_server =
      ReadFile(root + "/ssl/test/runner/handshake_server.go");

  check("CLIENT parses HelloVerifyRequest",
        Contains(client, "DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            Contains(client,
                     "CBS_get_u8_length_prefixed(&hello_verify_request, "
                     "&cookie)") &&
            Contains(client, "hs->dtls_cookie.CopyFrom(cookie)") &&
            Contains(client, "hs->transcript.Init()") &&
            Contains(client, "return ssl_add_client_hello(hs)"));

  check("PRODUCT API has no DTLSv1_listen or cookie callbacks",
        !ContainsAny(ssl_h, {"DTLSv1_listen", "SSL_CTX_set_cookie",
                             "SSL_set_cookie", "generate_cookie",
                             "verify_cookie", "SSL_OP_COOKIE_EXCHANGE"}));

  check("PRODUCT server has no HelloVerifyRequest message generation",
        !ContainsAny(server, {"DTLS1_MT_HELLO_VERIFY_REQUEST",
                              "HelloVerifyRequest", "hello_verify_request",
                              "helloVerifyRequestMsg"}));

  check("PRODUCT server has no stateless cookie verify path",
        !ContainsAny(server + handshake + d1_both + d1_pkt,
                     {"verify_cookie", "generate_cookie", "HMAC(Secret",
                      "SSL_OP_COOKIE_EXCHANGE", "DTLSv1_listen"}));

  check("PRODUCT ClientHello parser only exposes dtls_cookie bytes",
        Contains(extensions, "out->dtls_cookie = CBS_data(&cookie)") &&
            Contains(extensions, "out->dtls_cookie_len = CBS_len(&cookie)") &&
            !ContainsAny(server,
                         {"dtls_cookie_len", "dtls_cookie",
                          "client_hello.dtls_cookie"}));

  check("RUNNER has server-side HVR cookie behavior only in test peer",
        Contains(runner_server, "shouldSendHelloVerifyRequest") &&
            Contains(runner_server, "helloVerifyRequest := &helloVerifyRequestMsg") &&
            Contains(runner_server, "io.ReadFull") &&
            Contains(runner_server, "bytes.Equal(newClientHello.cookie"));

  return ok ? 0 : 1;
}
