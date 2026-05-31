#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
REPO = ROOT / "wolfssl-master"


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8", errors="replace")


def check(name: str, condition: bool) -> bool:
    print(f"{name}: {'PASS' if condition else 'FAIL'}")
    return condition


def main() -> int:
    dtls13 = read("src/dtls13.c")
    internal = read("wolfssl/internal.h")
    test_dtls = read("tests/api/test_dtls.c")

    ok = True
    ok &= check("ACK RecordNumber node stores only next/epoch/seq", "typedef struct Dtls13RecordNumber" in internal and "w64wrapper epoch;" in internal and "w64wrapper seq;" in internal and "already" not in internal[internal.find("typedef struct Dtls13RecordNumber"):internal.find("typedef struct Dtls13Rtx")])
    ok &= check("ACK list has bounded seenRecordsCount", "Dtls13RecordNumber *seenRecords;" in internal and "word16 seenRecordsCount;" in internal and "DTLS13_ACK_MAX_RECORDS" in internal)
    ok &= check("Dtls13RtxAddAck drops immediately when seenRecordsCount reaches max", "seenRecordsCount >= DTLS13_ACK_MAX_RECORDS" in dtls13 and "return 0; /* list full, silently drop */" in dtls13)
    ok &= check("Dtls13RtxAddAck drops when insertion position count reaches max", "DTLS 1.3 ACK list full, dropping record" in dtls13 and "if (count >= DTLS13_MAX_ACK_RECORDS)" in dtls13)
    ok &= check("Dtls13RtxAddAck suppresses duplicates but has no acknowledged-state replacement", "already in list. no duplicates." in dtls13 and "acknowledged" not in dtls13[dtls13.find("int Dtls13RtxAddAck"):dtls13.find("static void Dtls13RtxFlushAcks")])
    ok &= check("ACK writer rejects recordsCount over DTLS13_ACK_MAX_RECORDS", "if (recordsCount > DTLS13_ACK_MAX_RECORDS)" in dtls13 and "return BUFFER_E;" in dtls13)
    ok &= check("Unit test asserts one-over-limit is silently dropped", "one over limit - must be silently dropped" in test_dtls and "seenRecordsCount, DTLS13_ACK_MAX_RECORDS" in test_dtls)
    ok &= check("Unit test covers overflow safety, not priority by unacknowledged status", "test_dtls13_ack_overflow" in test_dtls and "already acknowledged" not in test_dtls[test_dtls.find("int test_dtls13_ack_overflow"):test_dtls.find("int test_dtls13_ack_dup_write_counter")])

    if ok:
        print("RESULT: confirmed ACK list is bounded and silently drops new records at capacity without acknowledged/unacknowledged priority metadata")
        return 0
    print("RESULT: probe found unexpected implementation differences")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
