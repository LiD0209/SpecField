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
  const std::string internal = ReadFile(root + "/ssl/internal.h");
  const std::string dtls_method = ReadFile(root + "/ssl/dtls_method.cc");
  const std::string dtls_record = ReadFile(root + "/ssl/dtls_record.cc");
  const std::string d1_pkt = ReadFile(root + "/ssl/d1_pkt.cc");
  const std::string runner = ReadFile(root + "/ssl/test/runner/runner.go");
  const std::string runner_dtls = ReadFile(root + "/ssl/test/runner/dtls.go");
  const std::string runner_key_update =
      ReadFile(root + "/ssl/test/runner/key_update_tests.go");
  const std::string runner_common = ReadFile(root + "/ssl/test/runner/common.go");

  RequireContains("internal.h", internal,
                  "DTLSRecordNumber(uint16_t epoch, uint64_t sequence)");
  RequireContains("internal.h", internal, "uint16_t epoch() const");
  RequireContains("internal.h", internal,
                  "combined_ = (uint64_t{epoch} << 48) | sequence");
  RequireContains("internal.h", internal,
                  "static constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1");
  RequireContains("internal.h", internal, "uint16_t epoch = 0;");
  RequireContains("internal.h", internal,
                  "size_t dtls_record_header_write_len(const SSL *ssl, uint16_t epoch)");
  RequireContains("internal.h", internal,
                  "bool dtls_seal_record(SSL *ssl, DTLSRecordNumber *out_number");
  RequireContains("internal.h", internal,
                  "const uint8_t *in, size_t in_len, uint16_t epoch");

  RequireContains("dtls_method.cc", dtls_method,
                  "static bool next_epoch(const SSL *ssl, uint16_t *out");
  RequireContains("dtls_method.cc", dtls_method, "if (prev == 0xffff)");
  RequireContains("dtls_method.cc", dtls_method, "SSL_R_TOO_MANY_KEY_UPDATES");
  RequireContains("dtls_method.cc", dtls_method, "*out = prev + 1");
  RequireContains("dtls_method.cc", dtls_method,
                  "new_epoch.next_record = DTLSRecordNumber(epoch, 0)");

  RequireContains("dtls_record.cc", dtls_record,
                  "static uint16_t reconstruct_epoch");
  RequireContains("dtls_record.cc", dtls_record,
                  "uint16_t max_epoch = ssl->d1->read_epoch.epoch");
  RequireContains("dtls_record.cc", dtls_record,
                  "DTLSReadEpoch *dtls_get_read_epoch(const SSL *ssl, uint16_t epoch)");
  RequireContains("dtls_record.cc", dtls_record,
                  "DTLSWriteEpoch *dtls_get_write_epoch(const SSL *ssl, uint16_t epoch)");
  RequireContains("dtls_record.cc", dtls_record,
                  "Although DTLS 1.3 can support sequence numbers up to 2^64-1");
  RequireContains("dtls_record.cc", dtls_record,
                  "enforce the DTLS 1.2 2^48-1 limit");
  RequireContains("dtls_record.cc", dtls_record, "out[0] = 0x2c | (epoch & 0x3)");
  RequireContains("dtls_record.cc", dtls_record,
                  "CRYPTO_store_u16_be(out + 1, write_epoch->next_record.sequence())");
  RequireContains("dtls_record.cc", dtls_record,
                  "CRYPTO_store_u64_be(out + 3, record_number.combined())");

  RequireContains("d1_pkt.cc", d1_pkt, "epoch > UINT16_MAX");
  RequireContains("d1_pkt.cc", d1_pkt,
                  "DTLSRecordNumber number(static_cast<uint16_t>(epoch), seq)");

  RequireContains("runner.go", runner, "addKeyUpdateTests()");
  RequireContains("runner.go", runner, "sendKeyUpdates int");
  RequireContains("runner.go", runner, "tlsConn.SendKeyUpdate");
  RequireContains("runner.go", runner, "shimSendsKeyUpdateBeforeRead");
  RequireContains("runner dtls.go", runner_dtls, "Epoch              uint16");
  RequireContains("runner dtls.go", runner_dtls, "func (c *DTLSController) OutEpoch() uint16");
  RequireContains("runner dtls.go", runner_dtls, "func (c *DTLSController) WriteACK(epoch uint16");
  RequireContains("runner dtls.go", runner_dtls,
                  "Store the Epoch as a uint64, so that tests can send ACKs for epochs that");
  RequireContains("runner common.go", runner_common,
                  "AllowEpochOverflow allows DTLS epoch numbers to wrap around");
  RequireContains("runner key_update_tests.go", runner_key_update,
                  "const maxClientKeyUpdates = 0xffff - 3");
  RequireContains("runner key_update_tests.go", runner_key_update,
                  "KeyUpdate-ReadEpochOverflow-DTLS");
  RequireContains("runner key_update_tests.go", runner_key_update,
                  "KeyUpdate-WriteEpochOverflow-DTLS");

  std::cout << "RESULT: confirmed. BoringSSL product code models DTLS epochs "
               "as uint16_t and rejects/wrap-guards at 0xffff, while runner "
               "tests intentionally cover this 16-bit overflow behavior. ACK "
               "RecordNumber carries uint64 fields on the wire, but product "
               "code casts epochs into the 16-bit DTLSRecordNumber model.\n";
  return 0;
}
