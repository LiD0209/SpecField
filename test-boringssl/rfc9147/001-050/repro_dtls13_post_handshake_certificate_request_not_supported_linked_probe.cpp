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

std::string SliceBetween(const std::string &text, const std::string &begin,
                         const std::string &end) {
  const size_t begin_pos = text.find(begin);
  if (begin_pos == std::string::npos) {
    std::cerr << "missing slice begin: " << begin << "\n";
    std::exit(4);
  }
  const size_t end_pos = text.find(end, begin_pos);
  if (end_pos == std::string::npos) {
    std::cerr << "missing slice end: " << end << "\n";
    std::exit(5);
  }
  return text.substr(begin_pos, end_pos - begin_pos);
}

void RequireNotContains(const std::string &name, const std::string &text,
                        const std::string &needle) {
  if (text.find(needle) != std::string::npos) {
    std::cerr << "unexpected evidence in " << name << ": " << needle << "\n";
    std::exit(6);
  }
  std::cout << "ok: " << name << " does not contain " << needle << "\n";
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
  const std::string handshake = ReadFile(root + "/ssl/handshake.cc");
  const std::string tls13_both = ReadFile(root + "/ssl/tls13_both.cc");
  const std::string d1_both = ReadFile(root + "/ssl/d1_both.cc");

  RequireContains("handshake.cc", handshake,
                  "We will never initiate post-handshake auth");
  RequireContains("handshake.cc", handshake,
                  "The largest acceptable post-handshake message for a server is a");
  RequireContains("handshake.cc", handshake, "KeyUpdate");
  RequireContains("handshake.cc", handshake, "return 1;");

  const std::string post_handshake = SliceBetween(
      tls13_both, "bool tls13_post_handshake", "BSSL_NAMESPACE_END");
  RequireContains("tls13_post_handshake", post_handshake,
                  "SSL3_MT_NEW_SESSION_TICKET");
  RequireContains("tls13_post_handshake", post_handshake, "SSL3_MT_KEY_UPDATE");
  RequireContains("tls13_post_handshake", post_handshake,
                  "SSL_R_UNEXPECTED_MESSAGE");
  RequireNotContains("tls13_post_handshake", post_handshake,
                     "SSL3_MT_CERTIFICATE_REQUEST");

  const std::string implicit_ack = SliceBetween(
      d1_both, "During the handshake, if we receive any portion of the next flight",
      "msg_hdr.seq - ssl->d1->handshake_read_seq");
  RequireContains("DTLS implicit ACK block", implicit_ack,
                  "This only applies during the handshake");
  RequireContains("DTLS implicit ACK block", implicit_ack,
                  "After the handshake, the next");
  RequireContains("DTLS implicit ACK block", implicit_ack,
                  "post-handshake transaction");
  RequireContains("DTLS implicit ACK block", implicit_ack,
                  "implicit_ack = true");

  std::cout << "RESULT: confirmed issue. BoringSSL does not implement DTLS/TLS "
               "1.3 post-handshake CertificateRequest processing; post-handshake "
               "dispatch only accepts NewSessionTicket and KeyUpdate, so ID029 "
               "should not be classified as satisfied for CertificateRequest "
               "implicit acknowledgement.\n";
  return 0;
}
