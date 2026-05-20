cmake_minimum_required(VERSION 3.20)
project(boringssl_rfc9147_051_100_probes CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BORINGSSL_ROOT "D:/project/boringssl-main" CACHE PATH "BoringSSL source root")
set(BORINGSSL_BUILD "D:/project/boringssl-main/build-codex-vs18-msvc" CACHE PATH "BoringSSL build root")

add_executable(repro_dtls13_epoch_width_probe
  repro_dtls13_epoch_width_probe.cpp
)

target_include_directories(repro_dtls13_epoch_width_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)

target_compile_definitions(repro_dtls13_epoch_width_probe PRIVATE
  BORINGSSL_ROOT="${BORINGSSL_ROOT}"
)

target_link_libraries(repro_dtls13_epoch_width_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
)

add_executable(repro_dtls13_hrr_cookie_probe
  repro_dtls13_hrr_cookie_probe.cpp
)

target_include_directories(repro_dtls13_hrr_cookie_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)

target_compile_definitions(repro_dtls13_hrr_cookie_probe PRIVATE
  BORINGSSL_ROOT="${BORINGSSL_ROOT}"
)

target_link_libraries(repro_dtls13_hrr_cookie_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
)

add_executable(repro_dtls13_pmtu_backoff_probe
  repro_dtls13_pmtu_backoff_probe.cpp
)

target_include_directories(repro_dtls13_pmtu_backoff_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)

target_compile_definitions(repro_dtls13_pmtu_backoff_probe PRIVATE
  BORINGSSL_ROOT="${BORINGSSL_ROOT}"
)

target_link_libraries(repro_dtls13_pmtu_backoff_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
)

add_executable(repro_dtls13_key_update_epoch_limit_probe
  repro_dtls13_key_update_epoch_limit_probe.cpp
)

target_include_directories(repro_dtls13_key_update_epoch_limit_probe PRIVATE
  "${BORINGSSL_ROOT}/include"
)

target_compile_definitions(repro_dtls13_key_update_epoch_limit_probe PRIVATE
  BORINGSSL_ROOT="${BORINGSSL_ROOT}"
)

target_link_libraries(repro_dtls13_key_update_epoch_limit_probe PRIVATE
  "${BORINGSSL_BUILD}/Release/ssl.lib"
  "${BORINGSSL_BUILD}/Release/crypto.lib"
  ws2_32
  crypt32
)
