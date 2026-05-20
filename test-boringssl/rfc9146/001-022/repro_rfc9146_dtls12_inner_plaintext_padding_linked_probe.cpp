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
    std::cerr << "usage: "
                 "repro_rfc9146_dtls12_inner_plaintext_padding_linked_probe "
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

  const std::string dtls = ReadFile(root + "/ssl/dtls_record.cc");
  const std::string internal = ReadFile(root + "/ssl/internal.h");

  check("Generic DTLS plaintext limit exists",
        Contains(dtls, "SSL3_RT_MAX_PLAIN_LENGTH + (has_padding ? 1 : 0)") &&
            Contains(dtls, "SSL_R_DATA_LENGTH_TOO_LONG"));

  check("Generic DTLS 1.2 record header length exists",
        Contains(internal, "#define DTLS_PLAINTEXT_RECORD_HEADER_LENGTH 13"));

  check("No RFC9146 length_of_DTLSInnerPlaintext field",
        !Contains(dtls, "length_of_DTLSInnerPlaintext") &&
            !Contains(internal, "length_of_DTLSInnerPlaintext") &&
            !Contains(dtls, "DTLSInnerPlaintext"));

  check("Zero padding removal is gated to DTLS 1.3",
        Contains(dtls, "DTLS 1.3 hides the record type inside the encrypted data") &&
            Contains(dtls, "ssl_protocol_version(ssl) >= TLS1_3_VERSION") &&
            Contains(dtls, "while (record.type == 0)"));

  check("No DTLS 1.2 CID padding construction on write path",
        Contains(dtls, "out[0] = type;") &&
            Contains(dtls, "SealScatter(") &&
            !Contains(dtls, "zeros[length_of_padding]") &&
            !Contains(dtls, "tls12_cid"));

  check("No CID-specific plaintext length state",
        !Contains(dtls, "cid_length") &&
            !Contains(internal, "cid_length") &&
            !Contains(dtls, "ConnectionId"));

  return ok ? 0 : 1;
}
