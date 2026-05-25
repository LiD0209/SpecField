# BoringSSL 151-187 Partial/Unsatisfied Classification

- Classified items: 6

## missing optional feature/path

- Count: 1
- Risk counts: {"medium": 1}

| ID | status | risk | variable | verification | reason |
|---:|---|---|---|---|---|
| 152 | 部分满足 | medium | Outer Content Type | confirmed_partial | Unsupported Heartbeat is safely rejected/not dispatched, but the implementation cannot process Heartbeat records if that feature is required. |

## missing feature/path

- Count: 1
- Risk counts: {"high": 1}

| ID | status | risk | variable | verification | reason |
|---:|---|---|---|---|---|
| 153 | 不满足 | high | Outer Content Type | confirmed_unsatisfied | CID-capable operation is not implemented. |

## incomplete ACK behavior

- Count: 1
- Risk counts: {"medium": 1}

| ID | status | risk | variable | verification | reason |
|---:|---|---|---|---|---|
| 157 | 部分满足 | medium | record_numbers | confirmed_partial | Normal ACK generation works, but the special empty ACK shortcut is not implemented. |

## missing CID update feature/path

- Count: 3
- Risk counts: {"high": 3}

| ID | status | risk | variable | verification | reason |
|---:|---|---|---|---|---|
| 185 | 不满足 | high | usage | confirmed_unsatisfied | NewConnectionId usage=cid_spare cannot be implemented because BoringSSL has no DTLS CID update state machine and no CID-capable record support. Root cause same as ID153. |
| 186 | 不满足 | high | usage | confirmed_unsatisfied | cid_immediate switching cannot be implemented because the sender always uses C=0 and there is no state transition to select a new CID for future records. Root cause same as ID153. |
| 187 | 不满足 | high | usage | confirmed_unsatisfied | RequestConnectionId cannot trigger a cid_spare NewConnectionId response because RequestConnectionId/NewConnectionId handling and CID-capable records are absent. Root cause same as ID153. |
