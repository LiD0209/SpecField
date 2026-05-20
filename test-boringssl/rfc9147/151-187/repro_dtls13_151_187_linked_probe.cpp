#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <fstream>
#include <initializer_list>
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

static bool NotContainsAny(const std::string &s,
                           std::initializer_list<const char *> needles) {
  for (const char *needle : needles) {
    if (Contains(s, needle)) {
      return false;
    }
  }
  return true;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: repro_dtls13_151_187_linked_probe <boringssl-root>\n";
    return 2;
  }

  const std::string root = argv[1];
  const std::string dtls_record = ReadFile(root + "/ssl/dtls_record.cc");
  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");
  const std::string d1_pkt = ReadFile(root + "/ssl/d1_pkt.cc");
  const std::string ssl3_h = ReadFile(root + "/include/openssl/ssl3.h");
  const std::string ssl_dir = ReadFile(root + "/ssl");

  bool ok = true;
  auto check = [&](const char *id, const char *name, bool condition) {
    std::cout << id << " " << name << ": " << (condition ? "PASS" : "FAIL")
              << "\n";
    ok = ok && condition;
  };

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
      SSL_CTX_new(DTLS_method()), SSL_CTX_free);
  check("LINK", "SSL_CTX_new(DTLS_method) succeeds", ctx != nullptr);
  if (ctx) {
    check("LINK", "DTLS 1.3 min/max setters are callable",
          SSL_CTX_set_min_proto_version(ctx.get(), DTLS1_3_VERSION) == 1 &&
              SSL_CTX_set_max_proto_version(ctx.get(), DTLS1_3_VERSION) == 1);
  }
  std::cout << "LINK OpenSSL_version: " << OpenSSL_version(OPENSSL_VERSION)
            << "\n";

  check("ID152", "heartbeat content type is not defined",
        !Contains(ssl3_h, "SSL3_RT_HEARTBEAT") &&
            !Contains(d1_both, "SSL3_RT_HEARTBEAT") &&
            !Contains(d1_pkt, "SSL3_RT_HEARTBEAT"));
  check("ID152", "non-handshake dispatch has no heartbeat branch",
        Contains(d1_both, "case SSL3_RT_ACK:") &&
            Contains(d1_pkt, "if (type == SSL3_RT_ACK)") &&
            NotContainsAny(d1_both, {"heartbeat", "Heartbeat"}));

  check("ID153", "DTLS 1.3 CID bit is rejected",
        Contains(dtls_record, "Connection ID bit set") &&
            Contains(dtls_record, "return false;"));
  check("ID153", "sender fixes C bit to zero",
        Contains(dtls_record, "We set C=0 (no Connection ID)") &&
            Contains(dtls_record, "0x2c"));
  check("ID153", "no DTLS 1.2 tls12_cid demux symbols",
        !Contains(dtls_record, "tls12_cid") &&
            !Contains(dtls_record, "DTLSCiphertext with CID"));

  check("ID157", "ACK encoding uses a length-prefixed vector",
        Contains(d1_both, "CBB_add_u16_length_prefixed(&cbb, &child)") &&
            Contains(d1_both, "SSL3_RT_ACK"));
  check("ID157", "ACK scheduling is gated by non-empty records_to_ack",
        Contains(d1_both,
                 "ssl->d1->sending_ack = !ssl->d1->records_to_ack.empty();"));
  check("ID157", "send_ack assumes space for at least one RecordNumber",
        Contains(d1_both, "No room for even one ACK") &&
            Contains(d1_both, "std::min((max_plaintext - 2) / 16"));

  check("ID185", "NewConnectionId/cid_spare handling absent",
        NotContainsAny(dtls_record,
                       {"NewConnectionId", "new_connection_id", "cid_spare"}));
  check("ID186", "cid_immediate handling absent",
        NotContainsAny(dtls_record, {"cid_immediate", "ConnectionIdUsage"}));
  check("ID187", "RequestConnectionId handling absent",
        NotContainsAny(dtls_record,
                       {"RequestConnectionId", "request_connection_id"}));
  check("CID_ROOT", "CID update findings share ID153 missing CID root cause",
        !Contains(dtls_record, "connection_id") &&
            Contains(dtls_record, "Connection ID bit set"));

  return ok ? 0 : 1;
}
