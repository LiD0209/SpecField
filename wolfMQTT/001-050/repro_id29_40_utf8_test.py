import json
import socket


PORT = 28984
HOST = "127.0.0.1"


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
    out = {"packet_hex": pkt.hex()}
    if len(pkt) < 4 or pkt[0] != 0x20:
        out["is_connack"] = False
        return out

    remain, pos = decode_vbi(pkt, 1)
    body = pkt[pos:pos + remain]
    out["is_connack"] = True
    out["ack_flags"] = body[0] if len(body) > 0 else None
    out["return_code"] = body[1] if len(body) > 1 else None
    return out


def parse_suback(pkt):
    out = {"packet_hex": pkt.hex()}
    if len(pkt) < 5 or pkt[0] != 0x90:
        out["is_suback"] = False
        return out

    remain, pos = decode_vbi(pkt, 1)
    body = pkt[pos:pos + remain]
    out["is_suback"] = True
    if len(body) >= 2:
        out["packet_id"] = (body[0] << 8) | body[1]
        out["return_codes"] = list(body[2:])
    return out


def build_connect(client_id: bytes):
    vh = (
        b"\x00\x04MQTT"  # protocol name
        b"\x04"          # protocol level 4 (3.1.1)
        b"\x02"          # clean session=1
        b"\x00\x3C"      # keep alive 60
    )
    payload = len(client_id).to_bytes(2, "big") + client_id
    remain = len(vh) + len(payload)
    return bytes([0x10, remain]) + vh + payload


def build_subscribe(topic: bytes, packet_id: int = 1):
    payload = (
        packet_id.to_bytes(2, "big")
        + len(topic).to_bytes(2, "big")
        + topic
        + b"\x00"  # qos 0
    )
    remain = len(payload)
    return bytes([0x82, remain]) + payload


def ping_alive(sock):
    try:
        sock.sendall(b"\xC0\x00")
        pkt = recv_packet(sock)
        return {
            "alive_after_ping": pkt == b"\xD0\x00",
            "ping_resp_hex": pkt.hex(),
        }
    except Exception as e:  # noqa: BLE001
        return {"alive_after_ping": False, "ping_error": f"{type(e).__name__}: {e}"}


def run_connect_case(name, client_id):
    out = {"case": name, "client_id_hex": client_id.hex()}
    sock = socket.create_connection((HOST, PORT), timeout=2)
    sock.settimeout(2)
    try:
        sock.sendall(build_connect(client_id))
        connack = recv_packet(sock)
        out.update(parse_connack(connack))
        out.update(ping_alive(sock))
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def run_subscribe_case(name, topic):
    out = {"case": name, "topic_hex": topic.hex()}
    sock = socket.create_connection((HOST, PORT), timeout=2)
    sock.settimeout(2)
    try:
        sock.sendall(build_connect(b"subcheck"))
        connack = recv_packet(sock)
        out["connect"] = parse_connack(connack)

        sock.sendall(build_subscribe(topic, packet_id=7))
        suback = recv_packet(sock)
        out["subscribe"] = parse_suback(suback)
        out.update(ping_alive(sock))
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def main():
    connect_cases = [
        ("connect_valid_ascii", b"abc"),
        ("connect_clientid_overlong", bytes.fromhex("c0af")),
        ("connect_clientid_surrogate", bytes.fromhex("eda080")),
        ("connect_clientid_u0000", b"A\x00B"),
        ("connect_clientid_bom_prefix", bytes.fromhex("efbbbf41")),
    ]
    subscribe_cases = [
        ("subscribe_topic_overlong", b"t/" + bytes.fromhex("c0af")),
        ("subscribe_topic_surrogate", b"t/" + bytes.fromhex("eda080")),
        ("subscribe_topic_u0000", b"t/\x00A"),
    ]

    for name, cid in connect_cases:
        print(json.dumps(run_connect_case(name, cid), ensure_ascii=False))
    for name, topic in subscribe_cases:
        print(json.dumps(run_subscribe_case(name, topic), ensure_ascii=False))


if __name__ == "__main__":
    main()
