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

void RequireContains(const std::string &name, const std::string &text,
                     const std::string &needle) {
  if (text.find(needle) == std::string::npos) {
    std::cerr << "ERROR: " << name << " did not contain expected text: "
              << needle << "\n";
    std::exit(3);
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
  const std::string dtls_record = ReadFile(root / "ssl/dtls_record.cc");
  const std::string version_tests =
      ReadFile(root / "ssl/test/runner/version_tests.go");
  const std::string runner_go = ReadFile(root / "ssl/test/runner/runner.go");

  ProbeBoringSSLLinkage();

  RequireContains("dtls_record.cc", dtls_record,
                  "static uint16_t dtls_record_version");
  RequireContains("dtls_record.cc", dtls_record,
                  "ssl_protocol_version(ssl) >= TLS1_3_VERSION ? DTLS1_2_VERSION");
  RequireContains("dtls_record.cc", dtls_record,
                  "CBS_get_u16(in, &out->version)");
  RequireContains("dtls_record.cc", dtls_record,
                  "version_ok = (out->version >> 8) == DTLS1_VERSION_MAJOR");
  RequireContains("dtls_record.cc", dtls_record,
                  "version_ok = out->version == dtls_record_version(ssl)");
  RequireContains("dtls_record.cc", dtls_record,
                  "if (!version_ok)");
  RequireContains("dtls_record.cc", dtls_record,
                  "return false;");

  RequireContains("version_tests.go", version_tests,
                  "func addRecordVersionTests()");
  RequireContains("version_tests.go", version_tests,
                  "CheckRecordVersion-");
  RequireContains("version_tests.go", version_tests,
                  "SendRecordVersion: 0x03ff");
  RequireContains("version_tests.go", version_tests,
                  "expectedError: \":WRONG_VERSION_NUMBER:\"");
  RequireContains("version_tests.go", version_tests,
                  "LooseInitialRecordVersion-");
  RequireContains("version_tests.go", version_tests,
                  "GarbageInitialRecordVersion-");
  RequireContains("runner.go", runner_go, "addRecordVersionTests()");

  std::cout << "linked BoringSSL probe: PASS\n";
  std::cout << "send behavior: dtls_record_version freezes DTLS 1.3 outbound legacy_record_version at DTLS 1.2\n";
  std::cout << "receive behavior: parse_dtls12_record still reads and checks DTLSPlaintext legacy_record_version\n";
  std::cout << "receive detail: epoch 0 permits only DTLS major byte, later epochs require exact dtls_record_version\n";
  std::cout << "runner coverage: addRecordVersionTests registers CheckRecordVersion and initial-record-version tests\n";
  std::cout << "conclusion: RFC 9147 ID 109 is confirmed partially satisfied\n";
  return 0;
}
