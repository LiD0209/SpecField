import json
import socket


PORT = 28983


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
    out = {}
    if not pkt or pkt[0] != 0x20:
        return out

    remain, pos = decode_vbi(pkt, 1)
    body = pkt[pos:pos + remain]

    if len(body) >= 2:
        out["ack_flags"] = body[0]
        out["return_or_reason_code"] = body[1]

    # MQTT v5 CONNACK properties (if any)
    if len(body) > 2:
        props_len, p = decode_vbi(body, 2)
        props = body[p:p + props_len]
        j = 0
        while j < len(props):
            prop_id = props[j]
            j += 1
            if prop_id == 0x12 and j + 2 <= len(props):  # Assigned Client Identifier
                slen = (props[j] << 8) | props[j + 1]
                j += 2
                sval = props[j:j + slen]
                j += slen
                out["assigned_client_id"] = sval.decode("utf-8", errors="replace")
                break
            # This script only needs property 0x12 for current repro.
            break
    return out


def one_case(name, packet):
    result = {"case": name}
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=2)
    sock.settimeout(1.5)
    try:
        sock.sendall(packet)
        connack = recv_packet(sock)
        result["connack_hex"] = connack.hex()
        result.update(parse_connack(connack))

        alive = True
        try:
            sock.sendall(bytes.fromhex("c0 00"))  # PINGREQ
            ping_resp = recv_packet(sock)
            result["ping_resp_hex"] = ping_resp.hex()
            if ping_resp == b"":
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
    cases = [
        (
            "mqtt311_emptyid_clean0",
            bytes.fromhex("10 0c 00 04 4d 51 54 54 04 00 00 3c 00 00"),
        ),
        (
            "mqtt311_emptyid_clean1",
            bytes.fromhex("10 0c 00 04 4d 51 54 54 04 02 00 3c 00 00"),
        ),
        (
            "mqtt5_emptyid_clean0",
            bytes.fromhex("10 0d 00 04 4d 51 54 54 05 00 00 3c 00 00 00"),
        ),
        (
            "mqtt5_emptyid_clean1",
            bytes.fromhex("10 0d 00 04 4d 51 54 54 05 02 00 3c 00 00 00"),
        ),
    ]

    for name, packet in cases:
        print(json.dumps(one_case(name, packet), ensure_ascii=False))


if __name__ == "__main__":
    main()
