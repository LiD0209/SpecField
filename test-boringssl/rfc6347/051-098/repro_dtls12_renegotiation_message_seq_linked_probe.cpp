#include <openssl/crypto.h>
#include <openssl/err.h>
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
    std::cerr << "usage: repro_dtls12_renegotiation_message_seq_linked_probe "
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

  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
      ctx ? SSL_new(ctx.get()) : nullptr, SSL_free);
  check("LINK SSL_new", ssl != nullptr);
  if (ssl) {
    check("Initial DTLS handshake write seq is 0",
          SSL_get_dtls_handshake_write_seq(ssl.get()) == 0);
    check("Initial DTLS handshake read seq is 0",
          SSL_get_dtls_handshake_read_seq(ssl.get()) == 0);
    ERR_clear_error();
    int renegotiate_ret = SSL_renegotiate(ssl.get());
    unsigned long err = ERR_peek_error();
    check("Caller-initiated renegotiation returns failure",
          renegotiate_ret == 0 && err != 0);
    std::cout << "SSL_renegotiate error: " << ERR_reason_error_string(err)
              << "\n";
    ERR_clear_error();
  }

  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");
  const std::string d1_pkt = ReadFile(root + "/ssl/d1_pkt.cc");
  const std::string d1_lib = ReadFile(root + "/ssl/d1_lib.cc");
  const std::string ssl_lib = ReadFile(root + "/ssl/ssl_lib.cc");
  const std::string ssl_h = ReadFile(root + "/include/openssl/ssl.h");
  const std::string internal = ReadFile(root + "/ssl/internal.h");
  const std::string runner_conn =
      ReadFile(root + "/ssl/test/runner/conn.go");
  const std::string runner_tests =
      ReadFile(root + "/ssl/test/runner/renegotiation_tests.go");

  check("DTLS message_seq is written from handshake_write_seq",
        Contains(d1_both, "CBB_add_u16(cbb, ssl->d1->handshake_write_seq)") &&
            Contains(d1_both, "ssl->d1->handshake_write_seq++"));

  check("DTLS initial handshake seq fields default to zero",
        Contains(internal, "uint16_t handshake_write_seq = 0") &&
            Contains(internal, "uint16_t handshake_read_seq = 0") &&
            Contains(d1_lib, "handshake_write_overflow(false)") &&
            Contains(d1_lib, "handshake_read_overflow(false)"));

  check("DTLS post-handshake record path marks renegotiation unsupported",
        Contains(d1_pkt, "DTLS resets handshake message numbers on each") &&
            Contains(d1_pkt, "renegotiations and retransmissions are ambiguous") &&
            Contains(d1_pkt, "unsupported\n    // renegotiation attempt"));

  check("Public docs say initiating renegotiation is unsupported",
        Contains(ssl_h, "There is no support in BoringSSL for initiating renegotiations as a client") &&
            Contains(ssl_h, "or server"));

  check("SSL_renegotiate rejects caller-initiated renegotiation",
        Contains(ssl_lib, "Caller-initiated renegotiation is not supported") &&
            Contains(ssl_lib, "ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED"));

  check("Runner notes DTLS renegotiation resets message sequence numbers",
        Contains(runner_conn, "In DTLS, renegotiation resets the message sequence numbers"));

  check("Runner tests document DTLS renegotiation not supported by BoringSSL",
        Contains(runner_tests, "We do not support renegotiation in DTLS, even if enabled"));

  return ok ? 0 : 1;
}
