cmake_minimum_required(VERSION 3.22)
project(dtls12_server_hvr_cookie_probe CXX)

set(BORINGSSL_ROOT "D:/project/boringssl-main" CACHE PATH "BoringSSL source root")
set(BORINGSSL_BUILD "D:/project/boringssl-main/build-codex-vs18-msvc" CACHE PATH "BoringSSL build root")

add_executable(repro_dtls12_server_hvr_cookie_linked_probe
  repro_dtls12_server_hvr_cookie_linked_probe.cpp
)

add_executable(repro_dtls12_hvr_cookie_255_limit_linked_probe
  repro_dtls12_hvr_cookie_255_limit_linked_probe.cpp
)

add_executable(repro_dtls12_epoch_retention_linked_probe
  repro_dtls12_epoch_retention_linked_probe.cpp
)

target_compile_features(repro_dtls12_server_hvr_cookie_linked_probe PRIVATE cxx_std_17)
target_compile_features(repro_dtls12_hvr_cookie_255_limit_linked_probe PRIVATE cxx_std_17)
target_compile_features(repro_dtls12_epoch_retention_linked_probe PRIVATE cxx_std_17)
target_include_directories(repro_dtls12_server_hvr_cookie_linked_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)
target_include_directories(repro_dtls12_hvr_cookie_255_limit_linked_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)
target_include_directories(repro_dtls12_epoch_retention_linked_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)
target_link_libraries(repro_dtls12_server_hvr_cookie_linked_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
  advapi32
  bcrypt
)
target_link_libraries(repro_dtls12_epoch_retention_linked_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
  advapi32
  bcrypt
)
target_link_libraries(repro_dtls12_hvr_cookie_255_limit_linked_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
  advapi32
  bcrypt
)
