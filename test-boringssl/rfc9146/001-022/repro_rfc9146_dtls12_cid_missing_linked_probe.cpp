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
    std::cerr << "usage: repro_rfc9146_dtls12_cid_missing_linked_probe "
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
  const std::string tls1_h = ReadFile(root + "/include/openssl/tls1.h");
  const std::string ssl3_h = ReadFile(root + "/include/openssl/ssl3.h");
  const std::string internal = ReadFile(root + "/ssl/internal.h");
  const std::string extensions = ReadFile(root + "/ssl/extensions.cc");
  const std::string dtls = ReadFile(root + "/ssl/dtls_record.cc");
  const std::string method = ReadFile(root + "/ssl/dtls_method.cc");

  check("connection_id(54) extension is absent",
        !Contains(tls1_h, "TLSEXT_TYPE_connection_id") &&
            !Contains(extensions, "connection_id") &&
            !Contains(extensions, "0x0036"));

  check("tls12_cid(25) content type is absent",
        !Contains(ssl3_h, "TLS12_CID") &&
            !Contains(ssl3_h, "tls12_cid") &&
            !Contains(ssl_h, "TLS12_CID") &&
            !Contains(internal, "TLS12_CID") &&
            !Contains(dtls, "tls12_cid"));

  check("DTLS 1.2 parser has no CID field",
        Contains(dtls, "static bool parse_dtls12_record") &&
            Contains(dtls, "CBS_get_u64(in, &epoch_and_seq)") &&
            Contains(dtls, "CBS_get_u16_length_prefixed(in, &out->body)") &&
            !Contains(dtls, "cid_length") &&
            !Contains(dtls, "out->cid"));

  check("DTLS 1.2 writer emits RFC 6347 header only",
        Contains(dtls, "out[0] = type;") &&
            Contains(dtls, "CRYPTO_store_u64_be(out + 3, record_number.combined())") &&
            Contains(dtls, "CRYPTO_store_u16_be(out + 11, ciphertext_len)") &&
            !Contains(dtls, "DTLSInnerPlaintext"));

  check("DTLS 1.3 CID bit is rejected rather than negotiated",
        Contains(dtls, "if (out->type & 0x10)") &&
            Contains(dtls, "Connection ID bit set, which we didn't negotiate") &&
            Contains(dtls, "return false;") &&
            Contains(dtls, "We set C=0 (no Connection ID)"));

  check("AEAD additional data has no RFC9146 CID construction",
        Contains(dtls, "record.header") &&
            Contains(dtls, "SealScatter(") &&
            Contains(dtls, "dtls_aead_sequence(ssl, record_number), header") &&
            !Contains(dtls, "seq_num_placeholder") &&
            !Contains(dtls, "cid_length") &&
            !Contains(dtls, "length_of_DTLSInnerPlaintext"));

  check("DTLSInnerPlaintext-like padding only exists for DTLS 1.3",
        Contains(dtls, "DTLS 1.3 hides the record type inside the encrypted data") &&
            Contains(dtls, "ssl_protocol_version(ssl) >= TLS1_3_VERSION") &&
            Contains(dtls, "while (record.type == 0)"));

  check("No CID peer address update state machine",
        !Contains(ssl_h, "peer address") &&
            !Contains(internal, "peer_address") &&
            !Contains(dtls, "peer_address") &&
            !Contains(method, "peer_address") &&
            !Contains(dtls, "connection_id"));

  return ok ? 0 : 1;
}
