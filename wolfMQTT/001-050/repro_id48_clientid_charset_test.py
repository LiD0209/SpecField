import json
import socket


HOST = "127.0.0.1"
PORT = 28985


def recv_packet(sock):
    first = sock.recv(1)
    if not first:
        return b""

    remain = 0
    mul = 1
    vbi = b""
    while True:
        b = sock.recv(1)
        if not b:
            return first + vbi
        vbi += b
        val = b[0]
        remain += (val & 0x7F) * mul
        if (val & 0x80) == 0:
            break
        mul *= 128

    payload = b""
    while len(payload) < remain:
        chunk = sock.recv(remain - len(payload))
        if not chunk:
            break
        payload += chunk
    return first + vbi + payload


def decode_vbi(buf, off):
    mul = 1
    val = 0
    i = off
    while True:
        b = buf[i]
        i += 1
        val += (b & 0x7F) * mul
        if (b & 0x80) == 0:
            return val, i
        mul *= 128


def parse_connack(pkt):
    out = {"connack_hex": pkt.hex()}
    if len(pkt) < 4 or pkt[0] != 0x20:
        out["is_connack"] = False
        return out

    remain, pos = decode_vbi(pkt, 1)
    body = pkt[pos:pos + remain]
    out["is_connack"] = True
    out["ack_flags"] = body[0] if len(body) > 0 else None
    out["return_or_reason_code"] = body[1] if len(body) > 1 else None
    return out


def build_connect_mqtt311(client_id_bytes):
    vh = (
        b"\x00\x04MQTT"
        b"\x04"      # protocol level 4 (MQTT 3.1.1)
        b"\x02"      # clean session = 1
        b"\x00\x3C"  # keep alive = 60
    )
    payload = len(client_id_bytes).to_bytes(2, "big") + client_id_bytes
    remain = len(vh) + len(payload)
    if remain > 127:
        raise ValueError("test packet too long for single-byte remaining length")
    return bytes([0x10, remain]) + vh + payload


def one_case(name, client_id_bytes):
    result = {
        "case": name,
        "client_id_hex": client_id_bytes.hex(),
        "client_id_len_bytes": len(client_id_bytes),
    }
    sock = socket.create_connection((HOST, PORT), timeout=2)
    sock.settimeout(1.5)
    try:
        sock.sendall(build_connect_mqtt311(client_id_bytes))
        connack = recv_packet(sock)
        result.update(parse_connack(connack))

        alive = True
        try:
            sock.sendall(b"\xC0\x00")  # PINGREQ
            ping = recv_packet(sock)
            result["ping_resp_hex"] = ping.hex()
            if ping != b"\xD0\x00":
                alive = False
        except Exception as e:  # noqa: BLE001
            result["ping_error"] = f"{type(e).__name__}: {e}"
            alive = False
        result["alive_after_connack"] = alive
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return result


def main():
    # MQTT-3.1.3-5 reference whitelist:
    # 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
    cases = [
        ("allowed_len1", b"A"),
        ("allowed_len23", b"AbCdEfGhIjKlMnOpQrStUvW"),  # 23 bytes
        ("allowed_digits", b"0123456789"),
        ("non_whitelist_underscore", b"abc_def"),
        ("non_whitelist_hyphen", b"abc-def"),
        ("non_whitelist_slash", b"abc/def"),
        ("non_whitelist_space", b"abc def"),
        ("non_whitelist_dollar", b"abc$def"),
        ("non_ascii_utf8", "[non-English text removed]A".encode("utf-8")),
        ("len24_whitelist_chars", b"AbCdEfGhIjKlMnOpQrStUvWx"),  # 24 bytes
    ]

    for name, cid in cases:
        print(json.dumps(one_case(name, cid), ensure_ascii=False))


if __name__ == "__main__":
    main()
