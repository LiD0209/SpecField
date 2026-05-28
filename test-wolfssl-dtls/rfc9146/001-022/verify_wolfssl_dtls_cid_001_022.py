import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="replace")

def require(name, cond, detail):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    print(f"PASS {name}: {detail}")

def test_cmake_cid_requires_dtls13():
    cmake = read("CMakeLists.txt")
    cache = read("build/CMakeCache.txt")
    require("cmake default off", re.search(r'add_option\("WOLFSSL_DTLS_CID".*?"no"\s+"yes;no"\)', cmake, re.S) is not None, "CMake option defaults to no")
    require("cmake requires dtls13", "if(NOT WOLFSSL_DTLS13)" in cmake and "CID are supported only for DTLSv1.3" in cmake, "CMake rejects CID without DTLS 1.3")
    require("existing build cid off", "WOLFSSL_DTLS_CID:BOOL=no" in cache, "checked build cache has CID disabled")

def test_constants_and_record_paths():
    ih = read("wolfssl/internal.h")
    internal = read("src/internal.c")
    require("extension 54", "#define TLSXT_CONNECTION_ID              0x0036" in ih, "connection_id extension constant is 54")
    require("content type 25", "dtls12_cid         = 25" in ih, "tls12_cid content type is 25")
    require("record type set", "args->type = dtls12_cid" in internal, "sender sets outer record type when tx CID exists")
    require("cid emitted", "wolfSSL_dtls_cid_get_tx(ssl, output + DTLS12_CID_OFFSET, cidSz)" in internal, "sender writes negotiated tx CID")
    require("inner type appended", "output[args->idx++] = (byte)type; /* type goes after input */" in internal, "sender serializes inner content type")

def test_aad_matches_rfc9146_shape():
    internal = read("src/internal.c")
    require("aad placeholder", "XMEMSET(additional + idx, 0xFF, SEQ_SZ)" in internal, "AAD starts with eight 0xff bytes")
    require("aad tls12 cid", internal.count("additional[idx++] = dtls12_cid") >= 2, "AAD includes tls12_cid in the expected positions")
    require("aad cid length", "additional[idx++] = cidSz" in internal, "AAD includes cid_length")
    require("aad inner length", "c16toa(sz, additional + idx)" in internal, "AAD includes length_of_DTLSInnerPlaintext")

def test_peer_update_lacks_strict_newer_gate():
    internal = read("src/internal.c")
    require("previous epoch accepted", "ssl->keys.curEpoch == peerSeq->nextEpoch - 1" in internal, "DTLS 1.2 window logic accepts previous epoch window")
    start = internal.find("static void dtlsProcessPendingPeer(WOLFSSL* ssl, int deprotected)")
    end = internal.find("#endif", start)
    require("pending peer function found", start >= 0 and end > start, "dtlsProcessPendingPeer is present")
    body = internal[start:end]
    require("peer update after deprotect", "wolfSSL_dtls_set_peer" in body and "deprotected" in body, "pending peer is promoted after deprotection")
    strict_terms = ["newest datagram", "newer", "latest", "lastEpoch", "lastSeq"]
    require("no strict newer gate", not any(term in body for term in strict_terms), "peer promotion body has no explicit newest-datagram comparison")

if __name__ == "__main__":
    test_cmake_cid_requires_dtls13()
    test_constants_and_record_paths()
    test_aad_matches_rfc9146_shape()
    test_peer_update_lacks_strict_newer_gate()
