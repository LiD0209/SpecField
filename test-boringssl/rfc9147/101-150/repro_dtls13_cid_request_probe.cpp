#include <openssl/ssl.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string ReadFile(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    std::cerr << "ERROR: could not open " << path.string() << "\n";
    std::exit(2);
  }
  std::ostringstream ss;
  ss << file.rdbuf();
  return ss.str();
}

std::string ReadTree(const std::filesystem::path &root,
                     const std::string &extension) {
  std::string out;
  for (const auto &entry : std::filesystem::recursive_directory_iterator(root)) {
    if (!entry.is_regular_file() || entry.path().extension() != extension) {
      continue;
    }
    out.append("\n/* FILE: ");
    out.append(entry.path().generic_string());
    out.append(" */\n");
    out.append(ReadFile(entry.path()));
  }
  return out;
}

void RequireContains(const std::string &name, const std::string &text,
                     const std::string &needle) {
  if (text.find(needle) == std::string::npos) {
    std::cerr << "ERROR: " << name << " did not contain expected text: "
              << needle << "\n";
    std::exit(3);
  }
}

void RequireNotContains(const std::string &name, const std::string &text,
                        const std::string &needle) {
  if (text.find(needle) != std::string::npos) {
    std::cerr << "ERROR: " << name << " unexpectedly contained text: "
              << needle << "\n";
    std::exit(4);
  }
}

void ProbeBoringSSLLinkage() {
  SSL_library_init();
  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  if (ctx == nullptr) {
    std::cerr << "ERROR: SSL_CTX_new(DTLS_method()) failed\n";
    std::exit(5);
  }
  SSL_CTX_free(ctx);
}

}  // namespace

int main() {
  const std::filesystem::path root = BORINGSSL_ROOT;
  const std::string ssl_cc = ReadTree(root / "ssl", ".cc");
  const std::string ssl_h = ReadTree(root / "ssl", ".h");
  const std::string public_ssl_h = ReadFile(root / "include/openssl/ssl.h");
  const std::string runner_go = ReadTree(root / "ssl/test/runner", ".go");
  const std::string dtls_record = ReadFile(root / "ssl/dtls_record.cc");

  ProbeBoringSSLLinkage();

  RequireContains("dtls_record.cc", dtls_record,
                  "Connection ID bit set, which we didn't negotiate.");
  RequireContains("dtls_record.cc", dtls_record,
                  "C=0 (no Connection ID)");
  RequireContains("dtls_record.cc", dtls_record,
                  "out[0] = 0x2c | (epoch & 0x3);");

  RequireNotContains("ssl/*.cc", ssl_cc, "RequestConnectionId");
  RequireNotContains("ssl/*.cc", ssl_cc, "NewConnectionId");
  RequireNotContains("ssl/*.cc", ssl_cc, "request_connection_id");
  RequireNotContains("ssl/*.cc", ssl_cc, "new_connection_id");
  RequireNotContains("ssl/*.cc", ssl_cc, "num_cids");
  RequireNotContains("ssl/*.cc", ssl_cc, "cid_spare");
  RequireNotContains("ssl/*.cc", ssl_cc, "too_many_cids_requested");
  RequireNotContains("ssl/*.h", ssl_h, "SSL3_MT_REQUEST_CONNECTION_ID");
  RequireNotContains("ssl/*.h", ssl_h, "SSL3_MT_NEW_CONNECTION_ID");
  RequireNotContains("include/openssl/ssl.h", public_ssl_h,
                     "SSL_set_connection_id");
  RequireNotContains("include/openssl/ssl.h", public_ssl_h,
                     "connection_id");

  RequireContains("runner/*.go", runner_go, "DTLS13RecordHeader-CIDBit");
  RequireContains("runner/*.go", runner_go, "DTLS13RecordHeaderSetCIDBit");
  RequireNotContains("runner/*.go", runner_go, "RequestConnectionId");
  RequireNotContains("runner/*.go", runner_go, "NewConnectionId");
  RequireNotContains("runner/*.go", runner_go, "num_cids");
  RequireNotContains("runner/*.go", runner_go, "too_many_cids_requested");

  std::cout << "linked BoringSSL probe: PASS\n";
  std::cout << "record behavior: DTLS 1.3 CID bit is rejected as not negotiated, and sent records force C=0\n";
  std::cout << "source behavior: no RequestConnectionId/NewConnectionId/num_cids state machine or handshake type support was found in ssl/*.cc or ssl/*.h\n";
  std::cout << "runner coverage: runner has DTLS13RecordHeader-CIDBit negative coverage, but no RequestConnectionId/NewConnectionId tests\n";
  std::cout << "conclusion: RFC 9147 IDs 145 and 146 are confirmed unsatisfied with the same root cause\n";
  return 0;
}
