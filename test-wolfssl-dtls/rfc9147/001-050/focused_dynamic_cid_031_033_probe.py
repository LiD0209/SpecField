#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[4]
REPO = ROOT / "wolfssl-master"

FILES = [
    REPO / "wolfssl" / "internal.h",
    REPO / "src" / "tls13.c",
    REPO / "src" / "dtls.c",
    REPO / "src" / "dtls13.c",
]

SEARCH_DIRS = [
    REPO / "src",
    REPO / "wolfssl",
    REPO / "tests",
]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def check(name: str, condition: bool) -> bool:
    print(f"{name}: {'PASS' if condition else 'FAIL'}")
    return condition


def all_source() -> str:
    chunks = []
    for directory in SEARCH_DIRS:
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".c", ".h", ".cc", ".cpp"}:
                chunks.append(read(path))
    return "\n".join(chunks)


def main() -> int:
    missing = [str(path) for path in FILES if not path.exists()]
    if missing:
        print("Missing required files:")
        for path in missing:
            print(path)
        return 2

    internal = read(REPO / "wolfssl" / "internal.h")
    tls13 = read(REPO / "src" / "tls13.c")
    dtls = read(REPO / "src" / "dtls.c")
    dtls13 = read(REPO / "src" / "dtls13.c")
    source = all_source()

    ok = True
    ok &= check("CIDInfo stores only tx/rx current CIDs", "ConnectionID* tx;" in internal and "ConnectionID* rx;" in internal and "byte negotiated : 1;" in internal)
    ok &= check("Handshake enum has no request_connection_id", "request_connection_id" not in internal)
    ok &= check("Handshake enum has no new_connection_id", "new_connection_id" not in internal)
    ok &= check("TLS13 handshake dispatcher has no RequestConnectionId/NewConnectionId branch", "RequestConnectionId" not in tls13 and "NewConnectionId" not in tls13)
    ok &= check("No ConnectionIdUsage symbols", "ConnectionIdUsage" not in source)
    ok &= check("No cid_immediate symbol", "cid_immediate" not in source)
    ok &= check("No cid_spare symbol", "cid_spare" not in source)
    ok &= check("No too_many_cids_requested alert symbol", "too_many_cids_requested" not in source)
    ok &= check("DTLS CID API rejects changing CID during a connection", "doesn't support changing the CID during a" in dtls)
    ok &= check("DTLS extension parser rejects changing CID on rehandshake", "don't support changing the CID on a rehandshake" in dtls)
    ok &= check("DTLS 1.3 record layer can add current negotiated CID", "Dtls13AddCID" in dtls13 and "wolfSSL_dtls_cid_get_tx" in dtls13)
    ok &= check("DTLS 1.3 record layer validates current RX CID", "Dtls13UnifiedHeaderParseCID" in dtls13 and "DtlsCIDCheck" in dtls13)

    if ok:
        print("RESULT: confirmed static CID support exists, dynamic RFC9147 CID update messages and queues are absent")
        return 0
    print("RESULT: probe found unexpected implementation differences")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
