#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

static std::string read_file(const char *path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static bool contains(const std::string &s, const std::string &needle) {
  return s.find(needle) != std::string::npos;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: repro_dtls12_hvr_static_probe <boringssl-root>\n";
    return 2;
  }
  const std::string root = argv[1];
  const std::string client = read_file((root + "/ssl/handshake_client.cc").c_str());
  const std::string server = read_file((root + "/ssl/handshake_server.cc").c_str());
  const std::string d1_pkt = read_file((root + "/ssl/d1_pkt.cc").c_str());
  const std::string ssl_h = read_file((root + "/include/openssl/ssl.h").c_str());

  bool ok = true;
  auto check = [&](const char *name, bool condition) {
    std::cout << name << ": " << (condition ? "PASS" : "FAIL") << "\n";
    ok = ok && condition;
  };

  check("client parses HelloVerifyRequest type",
        contains(client, "DTLS1_MT_HELLO_VERIFY_REQUEST"));
  check("client copies HVR cookie into next ClientHello",
        contains(client, "hs->dtls_cookie.CopyFrom(cookie)") &&
            contains(client, "CBB_add_bytes(&child, hs->dtls_cookie.data()"));
  check("client resets transcript after HVR",
        contains(client, "DTLS resets the handshake buffer after HelloVerifyRequest") &&
            contains(client, "hs->transcript.Init()"));
  check("server exposes no SSL_OP_COOKIE_EXCHANGE API",
        !contains(ssl_h, "SSL_OP_COOKIE_EXCHANGE"));
  check("server has no HVR send path",
        !contains(server, "DTLS1_MT_HELLO_VERIFY_REQUEST") &&
            !contains(server, "HelloVerifyRequest"));
  check("DTLS 1.2 renegotiation is explicitly unsupported",
        contains(d1_pkt, "unsupported") && contains(d1_pkt, "renegotiation"));

  return ok ? 0 : 1;
}
