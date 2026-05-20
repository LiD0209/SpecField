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

static bool Contains(const std::string &s, const std::string &needle) {
  return s.find(needle) != std::string::npos;
}

static bool AnyContains(const std::vector<std::string> &files,
                        const std::string &needle) {
  for (const auto &file : files) {
    if (Contains(file, needle)) {
      return true;
    }
  }
  return false;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: repro_dtls12_hvr_server_generation_linked_probe "
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

  const std::string ssl_h = ReadFile(root + "/include/openssl/ssl.h");
  const std::string ssl3_h = ReadFile(root + "/include/openssl/ssl3.h");
  const std::string client = ReadFile(root + "/ssl/handshake_client.cc");
  const std::string server = ReadFile(root + "/ssl/handshake_server.cc");
  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");
  const std::string dtls_record = ReadFile(root + "/ssl/dtls_record.cc");
  const std::string runner_server =
      ReadFile(root + "/ssl/test/runner/handshake_server.go");
  const std::string runner_messages =
      ReadFile(root + "/ssl/test/runner/handshake_messages.go");

  std::vector<std::string> product_files = {ssl_h, ssl3_h, client, server,
                                            d1_both, dtls_record};

  check("HVR message type constant is defined",
        Contains(ssl3_h, "DTLS1_MT_HELLO_VERIFY_REQUEST 3"));

  check("Product client parses HelloVerifyRequest",
        Contains(client, "handle_hello_verify_request") &&
            Contains(client, "DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            Contains(client, "CBS_get_u8_length_prefixed(&hello_verify_request, &cookie)") &&
            Contains(client, "hs->dtls_cookie.CopyFrom(cookie)") &&
            Contains(client, "hs->transcript.Init()"));

  check("Product server file has no HelloVerifyRequest send path",
        !Contains(server, "DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            !Contains(server, "hello_verify_request") &&
            !Contains(server, "HelloVerifyRequest"));

  check("Product public API has no legacy DTLS cookie exchange option",
        !Contains(ssl_h, "SSL_OP_COOKIE_EXCHANGE") &&
            !Contains(ssl_h, "DTLSv1_listen"));

  check("Product server does not build HVR server_version/cookie body",
        !Contains(server, "CBB_add_u16(&body, DTLS1_VERSION)") &&
            !Contains(server, "CBB_add_u16(&body, DTLS1_2_VERSION)") &&
            !Contains(server, "DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            !Contains(server, "helloVerifyRequest") &&
            !Contains(server, "HelloVerifyRequest"));

  check("DTLS record sealing uses ordinary next_record counter",
        Contains(dtls_record, "DTLSRecordNumber record_number = write_epoch->next_record") &&
            Contains(dtls_record, "write_epoch->next_record = record_number.Next()") &&
            Contains(d1_both, "msg.epoch = ssl->d1->write_epoch.epoch()"));

  check("Runner, not product libssl, implements server HVR generation",
        Contains(runner_server, "helloVerifyRequestMsg") &&
            Contains(runner_server, "Per RFC 6347, the version field in HelloVerifyRequest SHOULD") &&
            Contains(runner_messages, "typeHelloVerifyRequest") &&
            Contains(runner_messages, "func (m *helloVerifyRequestMsg) marshal"));

  return ok ? 0 : 1;
}
