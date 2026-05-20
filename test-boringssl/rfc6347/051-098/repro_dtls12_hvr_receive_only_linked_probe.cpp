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
    std::cerr << "usage: repro_dtls12_hvr_receive_only_linked_probe "
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

  const std::string ssl3_h = ReadFile(root + "/include/openssl/ssl3.h");
  const std::string ssl_h = ReadFile(root + "/include/openssl/ssl.h");
  const std::string client = ReadFile(root + "/ssl/handshake_client.cc");
  const std::string server = ReadFile(root + "/ssl/handshake_server.cc");
  const std::string runner_server =
      ReadFile(root + "/ssl/test/runner/handshake_server.go");
  const std::string runner_messages =
      ReadFile(root + "/ssl/test/runner/handshake_messages.go");

  check("HVR handshake type constant is present",
        Contains(ssl3_h, "DTLS1_MT_HELLO_VERIFY_REQUEST 3"));

  check("Client dispatches HelloVerifyRequest only once",
        Contains(client, "SSL_is_dtls(ssl) && !hs->received_hello_verify_request") &&
            Contains(client, "msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            Contains(client, "handle_hello_verify_request(hs, msg)"));

  check("Client parses HVR server_version and u8 cookie syntax",
        Contains(client, "CBS hello_verify_request = msg.body, cookie") &&
            Contains(client, "CBS_get_u16(&hello_verify_request, &server_version)") &&
            Contains(client, "CBS_get_u8_length_prefixed(&hello_verify_request, &cookie)") &&
            Contains(client, "CBS_len(&hello_verify_request) != 0"));

  check("Client copies cookie and resends ClientHello",
        Contains(client, "hs->dtls_cookie.CopyFrom(cookie)") &&
            Contains(client, "hs->received_hello_verify_request = true") &&
            Contains(client, "return ssl_add_client_hello(hs);"));

  check("Client excludes initial ClientHello/HVR from transcript",
        Contains(client, "DTLS resets the handshake buffer after HelloVerifyRequest") &&
            Contains(client, "hs->transcript.Init()"));

  check("Product server has no HVR generation path",
        !Contains(server, "DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            !Contains(server, "HelloVerifyRequest") &&
            !Contains(server, "hello_verify_request"));

  check("Product public API exposes no legacy DTLS HVR cookie exchange",
        !Contains(ssl_h, "SSL_OP_COOKIE_EXCHANGE") &&
            !Contains(ssl_h, "DTLSv1_listen"));

  check("Runner has HVR generation but is not product libssl",
        Contains(runner_server, "helloVerifyRequest := &helloVerifyRequestMsg") &&
            Contains(runner_messages, "func (m *helloVerifyRequestMsg) marshal() []byte") &&
            Contains(runner_messages, "x[0] = typeHelloVerifyRequest"));

  return ok ? 0 : 1;
}
