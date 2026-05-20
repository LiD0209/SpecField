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
  const std::string dtls_method = ReadFile(root + "/ssl/dtls_method.cc");
  const std::string tls13_both = ReadFile(root + "/ssl/tls13_both.cc");
  const std::string d1_pkt = ReadFile(root + "/ssl/d1_pkt.cc");
  const std::string internal = ReadFile(root + "/ssl/internal.h");
  const std::string runner = ReadFile(root + "/ssl/test/runner/runner.go");
  const std::string key_update_tests =
      ReadFile(root + "/ssl/test/runner/key_update_tests.go");
  const std::string common = ReadFile(root + "/ssl/test/runner/common.go");

  RequireContains("dtls_method.cc", dtls_method,
                  "static bool next_epoch");
  const std::string next_epoch =
      SliceBetween(dtls_method, "static bool next_epoch",
                   "static bool dtls1_set_read_state");
  RequireContains("next_epoch", next_epoch, "uint16_t *out");
  RequireContains("next_epoch", next_epoch, "uint16_t prev");
  RequireContains("next_epoch", next_epoch, "if (prev == 0xffff)");
  RequireContains("next_epoch", next_epoch, "SSL_R_TOO_MANY_KEY_UPDATES");
  RequireContains("next_epoch", next_epoch, "return false");
  RequireContains("next_epoch", next_epoch, "*out = prev + 1");
  RequireNotContains("next_epoch", next_epoch, "0xffffffffffff");
  RequireNotContains("next_epoch", next_epoch, "2^48");

  RequireContains("dtls_method.cc", dtls_method,
                  "ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE)");
  RequireContains("dtls_method.cc", dtls_method,
                  "if (!next_epoch(ssl, &epoch, level, ssl->d1->write_epoch.epoch()))");

  RequireContains("tls13_both.cc", tls13_both,
                  "static bool tls13_receive_key_update");
  const std::string receive_key_update =
      SliceBetween(tls13_both, "static bool tls13_receive_key_update",
                   "bool tls13_post_handshake");
  RequireContains("tls13_receive_key_update", receive_key_update,
                  "key_update_request == SSL_KEY_UPDATE_REQUESTED");
  RequireContains("tls13_receive_key_update", receive_key_update,
                  "tls13_add_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)");
  RequireNotContains("tls13_receive_key_update", receive_key_update,
                     "SSL_R_TOO_MANY_KEY_UPDATES");
  RequireNotContains("tls13_receive_key_update", receive_key_update,
                     "ignore");
  RequireNotContains("tls13_receive_key_update", receive_key_update,
                     "0xffff");

  RequireContains("tls13_both.cc", tls13_both,
                  "static const uint8_t kMaxKeyUpdates = 32");
  RequireContains("tls13_both.cc", tls13_both,
                  "ssl->s3->key_update_count > kMaxKeyUpdates");

  RequireContains("d1_pkt.cc", d1_pkt, "queued_key_update");
  RequireContains("d1_pkt.cc", d1_pkt, "SSL_KEY_UPDATE_REQUESTED");
  RequireContains("d1_pkt.cc", d1_pkt, "tls13_add_key_update(ssl, request_type)");

  RequireContains("internal.h", internal, "enum class QueuedKeyUpdate");
  RequireContains("internal.h", internal, "kUpdateRequested");
  RequireContains("internal.h", internal, "queued_key_update");

  RequireContains("runner.go", runner, "addKeyUpdateTests()");
  RequireContains("runner.go", runner, "SendKeyUpdate(test.keyUpdateRequest)");
  RequireContains("runner.go", runner, "ReadKeyUpdate()");
  RequireContains("common.go", common, "keyUpdateRequested");
  RequireContains("common.go", common, "AllowEpochOverflow");
  RequireContains("key_update_tests.go", key_update_tests,
                  "const maxClientKeyUpdates = 0xffff - 3");
  RequireContains("key_update_tests.go", key_update_tests,
                  "KeyUpdate-ReadEpochOverflow-DTLS");
  RequireContains("key_update_tests.go", key_update_tests,
                  "KeyUpdate-WriteEpochOverflow-DTLS");
  RequireContains("key_update_tests.go", key_update_tests,
                  "expectedError:      \":TOO_MANY_KEY_UPDATES:\"");
  RequireContains("key_update_tests.go", key_update_tests,
                  "expectedError:                \":TOO_MANY_KEY_UPDATES:\"");
  RequireContains("key_update_tests.go", key_update_tests,
                  "rejects KeyUpdates at epoch 0xffff");
  RequireContains("key_update_tests.go", key_update_tests,
                  "9147 does not prescribe this limit");
  RequireContains("key_update_tests.go", key_update_tests,
                  "but we enforce it");

  std::cout
      << "RESULT: confirmed partial. BoringSSL responds to received "
         "update_requested KeyUpdate by attempting tls13_add_key_update with "
         "SSL_KEY_UPDATE_NOT_REQUESTED. In DTLS this allocates the next write "
         "epoch through next_epoch, which is uint16_t-based and fails at "
         "0xffff with SSL_R_TOO_MANY_KEY_UPDATES. The receiver path has no "
         "branch to ignore update_requested when sending a response would "
         "exceed the RFC 9147 sending limit. Runner tests explicitly expect "
         "TOO_MANY_KEY_UPDATES at the 0xffff DTLS epoch boundary, reflecting "
         "BoringSSL's 16-bit epoch model rather than RFC 9147's 2^48-1 "
         "sending limit and ignore-update_requested rule.\n";
  return 0;
}
