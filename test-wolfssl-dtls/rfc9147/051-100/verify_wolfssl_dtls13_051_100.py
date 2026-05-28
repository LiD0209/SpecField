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

def test_close_notify_lacks_epoch_sequence_gate():
    ih = read("wolfssl/internal.h")
    internal = read("src/internal.c")
    require("close notify state", "word16            closeNotify:1" in ih and "ssl->options.closeNotify = 1" in internal, "close_notify is represented as a state flag")
    absent = ["closeNotifyEpoch", "closeNotifySeq", "closureEpoch", "closureSeq", "close_notify_epoch", "close_notify_seq"]
    require("no stored closure pair", not any(term in ih + internal for term in absent), "no stored closure alert epoch/sequence pair")
    post_close_window = re.search(r"closeNotify.{0,160}(curEpoch64|curSeq|epoch/sequence|sequence)", internal, re.S)
    require("no post-close pair comparison", post_close_window is None, "no code compares later records with a stored closure pair")

def test_epoch_send_limit_is_64bit_wrap_not_2p48():
    dtls13 = read("src/dtls13.c")
    require("64-bit wrap checks", "w64Increment(&ssl->dtls13Epoch)" in dtls13 and "if (w64IsZero(ssl->dtls13Epoch))" in dtls13, "epoch update detects wrap to zero")
    forbidden = ["0x0000ffffffffffff", "0xffffffffffff", "281474976710655", "2^48", "1ULL << 48", "W64_MAX_48"]
    require("no 2^48 send limit", not any(term in dtls13 for term in forbidden), "no explicit 2^48-1 sending epoch limit found")
    require("receiver has no upper-bound gate", "Dtls13ReconstructEpochNumber" in dtls13 and "return SEQUENCE_ERROR" in dtls13, "receiver reconstructs by known epoch slots, not by enforcing 2^48")

def test_retransmission_pmtu_backoff_not_present():
    dtls13 = read("src/dtls13.c")
    internal = read("src/internal.c")
    require("fragmentation path exists", "Dtls13SendFragmented" in dtls13 and "wolfssl_local_GetMaxPlaintextSize" in dtls13, "handshake fragmentation uses current max plaintext size")
    require("retransmission path exists", "Dtls13RtxTimeout" in dtls13 and "Dtls13RtxSendBuffered" in dtls13, "retransmission timer resends buffered records")
    body = dtls13[dtls13.find("int Dtls13RtxTimeout"):dtls13.find("static int Dtls13RtxHasKeyUpdateBuffered")]
    backoff_terms = ["pmtu", "PMTU", "mtu", "Mtu", "maxFrag", "smaller", "back off", "backoff"]
    require("no rtx pmtu backoff", not any(term in body for term in backoff_terms), "timeout retransmission path does not shrink record size")
    require("mtu sizing elsewhere", "adjust plaintext size to fit in MTU" in internal, "MTU sizing exists for normal send sizing, not repeated retransmission backoff")

def test_keyupdate_response_lacks_2p48_limit_gate():
    tls13 = read("src/tls13.c")
    require("keyupdate response exists", "case update_requested:" in tls13 and "ssl->keys.keyUpdateRespond = 1" in tls13 and "return SendTls13KeyUpdate(ssl)" in tls13, "update_requested schedules a response")
    require("dtls wait gate exists", "ssl->options.dtls && ssl->dtls13WaitKeyUpdateAck" in tls13, "DTLS suppresses concurrent KeyUpdate while waiting for ACK")
    response_region = tls13[tls13.find("if (ssl->keys.keyUpdateRespond)"):tls13.find("WOLFSSL_LEAVE(\"DoTls13KeyUpdate\"", tls13.find("if (ssl->keys.keyUpdateRespond)"))]
    limit_terms = ["2^48", "281474976710655", "0x0000ffffffffffff", "1ULL << 48", "W64_MAX_48"]
    require("no limit gate in response", not any(term in response_region for term in limit_terms), "response decision is not gated by the RFC 2^48-1 epoch limit")

if __name__ == "__main__":
    test_close_notify_lacks_epoch_sequence_gate()
    test_epoch_send_limit_is_64bit_wrap_not_2p48()
    test_retransmission_pmtu_backoff_not_present()
    test_keyupdate_response_lacks_2p48_limit_gate()
