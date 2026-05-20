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
  const std::string d1_lib = ReadFile(root + "/ssl/d1_lib.cc");
  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");
  const std::string internal = ReadFile(root + "/ssl/internal.h");
  const std::string runner = ReadFile(root + "/ssl/test/runner/runner.go");
  const std::string dtls_tests =
      ReadFile(root + "/ssl/test/runner/dtls_tests.go");
  const std::string test_config = ReadFile(root + "/ssl/test/test_config.cc");
  const std::string packeted_bio =
      ReadFile(root + "/ssl/test/packeted_bio.cc");

  RequireContains("internal.h", internal, "#define DTLS1_MTU_TIMEOUTS 2");

  RequireContains("d1_lib.cc", d1_lib, "int DTLSv1_handle_timeout(SSL *ssl)");
  RequireContains("d1_lib.cc", d1_lib, "ssl->d1->num_timeouts++");
  RequireContains("d1_lib.cc", d1_lib, "ssl->d1->num_timeouts > DTLS1_MTU_TIMEOUTS");
  RequireContains("d1_lib.cc", d1_lib, "SSL_OP_NO_QUERY_MTU");
  RequireContains("d1_lib.cc", d1_lib, "BIO_CTRL_DGRAM_GET_FALLBACK_MTU");
  RequireContains("d1_lib.cc", d1_lib, "ssl->d1->mtu = (unsigned)mtu");

  const std::string update_mtu =
      SliceBetween(d1_both, "static void dtls1_update_mtu", "enum seal_result_t");
  RequireContains("dtls1_update_mtu", update_mtu, "BIO_CTRL_DGRAM_QUERY_MTU");
  RequireContains("dtls1_update_mtu", update_mtu, "SSL_OP_NO_QUERY_MTU");
  RequireContains("dtls1_update_mtu", update_mtu, "ssl->d1->mtu = (unsigned)mtu");

  const std::string send_flight =
      SliceBetween(d1_both, "static int send_flight(SSL *ssl)",
                   "static int send_ack");
  RequireContains("send_flight", send_flight, "dtls1_update_mtu(ssl)");
  RequireContains("send_flight", send_flight, "packet.InitForOverwrite(ssl->d1->mtu)");

  const std::string flush =
      SliceBetween(d1_both, "int dtls1_flush(SSL *ssl)",
                   "unsigned int dtls1_min_mtu");
  RequireContains("dtls1_flush", flush, "send_flight(ssl)");
  RequireContains("dtls1_flush", flush, "ssl->d1->outgoing_written = 0");
  RequireContains("dtls1_flush", flush, "ssl->d1->outgoing_offset = 0");

  const std::string seal_next_record =
      SliceBetween(d1_both, "static seal_result_t seal_next_record",
                   "static bool seal_next_packet");
  RequireContains("seal_next_record", seal_next_record,
                  "dtls_seal_max_input_len");
  RequireContains("seal_next_record", seal_next_record,
                  "capacity = fragments.size() - CBB_len(&cbb)");
  RequireContains("seal_next_record", seal_next_record,
                  "todo = std::min");
  RequireContains("seal_next_record", seal_next_record,
                  "CBB_add_u24(&cbb, range.start)");
  RequireContains("seal_next_record", seal_next_record,
                  "CBB_add_u24_length_prefixed");
  RequireContains("seal_next_record", seal_next_record,
                  "ssl->d1->outgoing_offset = range.start + todo");
  RequireNotContains("seal_next_record", seal_next_record,
                     "BIO_CTRL_DGRAM_GET_FALLBACK_MTU");

  RequireContains("runner.go", runner, "addDTLSRetransmitTests()");
  RequireContains("dtls_tests.go", dtls_tests,
                  "DTLS-Retransmit-ChangeMTU");
  RequireContains("dtls_tests.go", dtls_tests, "c.SetMTU(mtu)");
  RequireContains("dtls_tests.go", dtls_tests, "c.ReadRetransmit()");
  RequireContains("dtls_tests.go", dtls_tests,
                  "Change the MTU every iteration");
  RequireContains("test_config.cc", test_config, "SSL_OP_NO_QUERY_MTU");
  RequireContains("test_config.cc", test_config, "SSL_set_mtu");
  RequireContains("packeted_bio.cc", packeted_bio, "SSL_set_mtu(data->ssl, mtu)");

  std::cout
      << "RESULT: partial. BoringSSL has a retransmission-timeout path that "
         "sets ssl->d1->mtu from BIO_CTRL_DGRAM_GET_FALLBACK_MTU after more "
         "than two timeouts, and retransmission fragmentation uses the current "
         "ssl->d1->mtu. The remaining gap is that, when PMTU is unknown and no "
         "valid BIO fallback MTU is supplied, the product code does not derive "
         "its own progressively smaller record sizes. Runner coverage changes "
         "MTU manually via SetMTU/SSL_set_mtu, which exercises retransmission "
         "under different MTUs but not autonomous unknown-PMTU backoff.\n";
  return 0;
}
