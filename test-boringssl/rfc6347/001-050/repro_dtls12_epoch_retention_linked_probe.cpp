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
    std::cerr << "usage: repro_dtls12_epoch_retention_linked_probe "
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

  const std::string method = ReadFile(root + "/ssl/dtls_method.cc");
  const std::string record = ReadFile(root + "/ssl/dtls_record.cc");
  const std::string internal = ReadFile(root + "/ssl/internal.h");

  check("DTLS 1.2 read state directly replaces read_epoch",
        Contains(method, "} else {\n    ssl->d1->read_epoch = std::move(new_epoch);") &&
            Contains(method, "ssl->d1->has_change_cipher_spec = false;"));

  check("Source comment says DTLS 1.2 would ignore previous epoch",
        Contains(method, "In principle,\n    // we could do the same in DTLS 1.2") &&
            Contains(method, "we would ignore every record from\n    // the previous epoch anyway"));

  check("DTLS 1.3 read state is staged in next_read_epoch",
        Contains(method, "ssl->d1->next_read_epoch = MakeUnique<DTLSReadEpoch>(std::move(new_epoch));"));

  check("DTLS 1.2 parser only considers one read epoch",
        Contains(record, "In DTLS 1.2, we only need to consider one\n  // epoch.") &&
            Contains(record, "if (epoch == ssl->d1->read_epoch.epoch &&") &&
            Contains(record, "out->read_epoch = &ssl->d1->read_epoch;"));

  check("Unknown or stale epoch records are discarded",
        Contains(record, "record.read_epoch == nullptr") &&
            Contains(record, "Drop this record. It's from an unknown epoch or is a replay."));

  check("DTLS 1.3 promotion retains previous read epoch",
        Contains(record, "Also save the previous epoch. This allows us to handle") &&
            Contains(record, "prev->epoch = std::move(ssl->d1->read_epoch);") &&
            Contains(record, "ssl->d1->prev_read_epoch = std::move(prev);"));

  check("internal.h marks previous read epoch as DTLS 1.3 only",
        Contains(internal, "next_read_epoch is the next read epoch in DTLS 1.3") &&
            Contains(internal, "prev_read_epoch is the previous read epoch in DTLS 1.3"));

  check("Epoch wrap protection is present",
        Contains(method, "if (prev == 0xffff)") &&
            Contains(method, "SSL_R_TOO_MANY_KEY_UPDATES"));

  return ok ? 0 : 1;
}
