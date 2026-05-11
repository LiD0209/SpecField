# BoringSSL 151-187 ????/?????

- ??????: 6

## missing optional feature/path

- ??: 1
- ????: {"medium": 1}

| ID | ?? | ?? | ?? | ???? | ?? |
|---:|---|---|---|---|---|
| 152 | ???? | medium | Outer Content Type | confirmed_partial | Confirmed partial: unsupported Heartbeat is safely rejected/not dispatched, but the implementation cannot process Heartbeat records if that feature were required by the deployment. |

## missing feature/path

- ??: 1
- ????: {"high": 1}

| ID | ?? | ?? | ?? | ???? | ?? |
|---:|---|---|---|---|---|
| 153 | ??? | high | Outer Content Type | confirmed_unsatisfied | Confirmed unsatisfied for CID-capable operation: the record layer has no DTLS 1.2 CID demux path and rejects DTLS 1.3 CID headers. |

## incomplete ACK behavior

- ??: 1
- ????: {"medium": 1}

| ID | ?? | ?? | ?? | ???? | ?? |
|---:|---|---|---|---|---|
| 157 | ???? | medium | record_numbers | confirmed_partial | Confirmed partial: regular ACK generation works, but the special empty ACK shortcut is not implemented. |

## missing CID update feature/path

- ??: 3
- ????: {"high": 3}

| ID | ?? | ?? | ?? | ???? | ?? |
|---:|---|---|---|---|---|
| 185 | ??? | high | usage | confirmed_unsatisfied | Confirmed unsatisfied: BoringSSL cannot process cid_spare because DTLS CID update support is absent. |
| 186 | ??? | high | usage | confirmed_unsatisfied | Confirmed unsatisfied: there is no mechanism to switch future records to a new CID immediately. |
| 187 | ??? | high | usage | confirmed_unsatisfied | Confirmed unsatisfied: RequestConnectionId cannot trigger a cid_spare NewConnectionId response. |
