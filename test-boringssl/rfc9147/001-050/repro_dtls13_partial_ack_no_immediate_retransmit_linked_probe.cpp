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
    std::cerr << "unexpected immediate retransmit scheduling in " << name
              << ": " << needle << "\n";
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
  const std::string d1_pkt = ReadFile(root + "/ssl/d1_pkt.cc");
  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");
  const std::string d1_lib = ReadFile(root + "/ssl/d1_lib.cc");

  RequireContains("d1_pkt.cc", d1_pkt, "dtls1_process_ack");
  RequireContains("d1_pkt.cc", d1_pkt, "CBS_get_u64(&record_numbers, &epoch)");
  RequireContains("d1_pkt.cc", d1_pkt, "acked.MarkRange");
  RequireContains("d1_pkt.cc", d1_pkt, "dtls1_stop_timer(ssl)");
  RequireContains("d1_pkt.cc", d1_pkt, "Schedule a retransmit");

  const std::string partial_ack_branch = SliceBetween(
      d1_pkt, "// We may still be able to drop unused write epochs.",
      "ssl_do_msg_callback");
  RequireContains("partial ACK branch", partial_ack_branch,
                  "dtls_clear_unused_write_epochs(ssl)");
  RequireNotContains("partial ACK branch", partial_ack_branch,
                     "sending_flight = true");
  RequireNotContains("partial ACK branch", partial_ack_branch,
                     "retransmit_timer.Start");
  RequireNotContains("partial ACK branch", partial_ack_branch,
                     "dtls1_start_timer");

  RequireContains("d1_both.cc", d1_both, "NextUnmarkedRange");
  RequireContains("d1_both.cc", d1_both, "if (ssl->d1->sending_flight)");
  RequireContains("d1_both.cc", d1_both,
                  "retransmit_timer.StartMicroseconds");
  RequireContains("d1_lib.cc", d1_lib, "retransmit_timer.IsExpired");
  RequireContains("d1_lib.cc", d1_lib, "ssl->d1->sending_flight = true");

  std::cout << "RESULT: confirmed partial. ACKed ranges are tracked, but the "
               "partial ACK branch does not immediately schedule retransmit; "
               "existing timer expiry is the observed scheduling path.\n";
  return 0;
}
