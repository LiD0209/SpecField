#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
REPO = ROOT / "wolfssl-master"

SOURCE_DIRS = [
    REPO / "src",
    REPO / "wolfssl",
    REPO / "tests",
]


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8", errors="replace")


def check(name: str, condition: bool) -> bool:
    print(f"{name}: {'PASS' if condition else 'FAIL'}")
    return condition


def all_source() -> str:
    chunks = []
    for directory in SOURCE_DIRS:
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".c", ".h", ".cc", ".cpp"}:
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def enum_block(text: str) -> str:
    start = text.find("enum HandShakeType")
    end = text.find("enum ProvisionSide", start)
    if start < 0 or end < 0:
        return ""
    return text[start:end]


def function_block(text: str, name: str, next_marker: str) -> str:
    start = text.find(name)
    end = text.find(next_marker, start + len(name)) if start >= 0 else -1
    if start < 0:
        return ""
    if end < 0:
        return text[start:]
    return text[start:end]


def main() -> int:
    required = [
        REPO / "wolfssl" / "internal.h",
        REPO / "src" / "tls13.c",
        REPO / "src" / "dtls13.c",
        REPO / "src" / "dtls.c",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("Missing required files:")
        for path in missing:
            print(path)
        return 2

    internal = read("wolfssl/internal.h")
    tls13 = read("src/tls13.c")
    dtls13 = read("src/dtls13.c")
    dtls = read("src/dtls.c")
    source = all_source()

    hs_enum = enum_block(internal)
    dtls_recv = function_block(
        dtls13,
        "static int _Dtls13HandshakeRecv",
        "int Dtls13HandshakeRecv",
    )
    tls13_dispatch = function_block(
        tls13,
        "int DoTls13HandShakeMsgType",
        "int DoTls13HandShakeMsg(WOLFSSL* ssl",
    )

    ok = True
    ok &= check("HandshakeType enum exists", bool(hs_enum))
    ok &= check("HandshakeType enum includes normal TLS 1.3 messages",
        all(token in hs_enum for token in [
            "client_hello", "server_hello", "encrypted_extensions",
            "certificate_request", "certificate", "certificate_verify",
            "finished", "session_ticket", "key_update",
        ]))
    ok &= check("HandshakeType enum lacks request_connection_id(9)",
        "request_connection_id" not in hs_enum and " =   9" not in hs_enum)
    ok &= check("HandshakeType enum lacks new_connection_id(10)",
        "new_connection_id" not in hs_enum and " =  10" not in hs_enum)
    ok &= check("DTLS 1.3 handshake receive path exists",
        "GetDtlsHandShakeHeader" in dtls_recv and
        "DoTls13HandShakeMsgType" in dtls_recv)
    ok &= check("TLS 1.3 handshake dispatcher handles ordinary body cases",
        all(token in tls13_dispatch for token in [
            "case server_hello", "case encrypted_extensions",
            "case certificate_request", "case certificate",
            "case certificate_verify", "case finished",
            "case session_ticket", "case key_update",
        ]))
    ok &= check("TLS 1.3 dispatcher has no dynamic CID body branch",
        "request_connection_id" not in tls13_dispatch and
        "new_connection_id" not in tls13_dispatch and
        "RequestConnectionId" not in tls13_dispatch and
        "NewConnectionId" not in tls13_dispatch)
    ok &= check("Repository has no RequestConnectionId implementation",
        "RequestConnectionId" not in source)
    ok &= check("Repository has no NewConnectionId implementation",
        "NewConnectionId" not in source)
    ok &= check("Repository has no ConnectionIdUsage implementation",
        "ConnectionIdUsage" not in source)
    ok &= check("Static DTLS CID support exists",
        "WOLFSSL_DTLS_CID" in source and
        "TLSX_CONNECTION_ID" in source and
        "Dtls13AddCID" in dtls13 and
        "Dtls13UnifiedHeaderParseCID" in dtls13)
    ok &= check("CID state is current tx/rx, not a dynamic CID body queue",
        "ConnectionID* tx;" in internal and
        "ConnectionID* rx;" in internal and
        "byte negotiated : 1;" in internal and
        "receiver_provided" not in source and
        "spare_cid" not in source)
    ok &= check("Existing API rejects changing CID during a connection",
        "doesn't support changing the CID during a" in dtls)

    if ok:
        print("RESULT: confirmed partial satisfaction for RFC9147 DTLSHandshake.body: normal body cases exist, request_connection_id/new_connection_id branches are absent")
        return 0

    print("RESULT: probe found unexpected implementation differences")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
