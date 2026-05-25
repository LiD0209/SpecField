# BoringSSL 151-187 Comparison Table

- 满足: 31
- 部分满足: 2
- 不满足: 4

| ID | variable | action | status | note |
|---:|---|---|---|---|
| 151 | Outer Content Type | must equal mapped constant for Application Data demultiplexing | 满足 | BoringSSL implements the normal DTLS demultiplexing path for supported record types. |
| 152 | Outer Content Type | must equal mapped constant for Heartbeat demultiplexing | 部分满足 | Heartbeat appears in the RFC demux table, but BoringSSL has no Heartbeat feature or handler. Unsupported Heartbeat records are rejected/not dispatched, while processing Heartbeat records is unavailable. |
| 153 | Outer Content Type | must equal mapped constant for encrypted_record with CID demultiplexing | 不满足 | BoringSSL has no DTLS 1.2 tls12_cid demux path, rejects DTLS 1.3 records with the C bit set, and always sends DTLS 1.3 encrypted records with C=0. |
| 154 | Outer Content Type | must equal mapped constant for ACK demultiplexing | 满足 | BoringSSL implements the normal DTLS demultiplexing path for supported record types. |
| 155 | Outer Content Type | invalid if value check fails; reject packet | 满足 | BoringSSL implements the normal DTLS demultiplexing path for supported record types. |
| 156 | record_numbers | validated range check | 满足 | BoringSSL implements the normal DTLS ACK parsing or generation path for this field. |
| 157 | record_numbers | set to empty / absent | 部分满足 | ACK encoding can represent a length-prefixed record_numbers vector, but dtls1_schedule_ack only sends ACKs when records_to_ack is non-empty and send_ack assumes space for at least one RecordNumber. |
| 158 | record_numbers | must be in numerically increasing order | 满足 | BoringSSL implements the normal DTLS ACK parsing or generation path for this field. |
| 159 | Sequence Number | must equal | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 160 | Sequence Number | must equal | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 161 | Sequence Number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 162 | Sequence Number | validated range check | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 163 | Sequence Number | validated range check | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 164 | sequence_number | must be compared as part of an epoch/sequence number pair; data with a pair after that of the valid received closure alert must be ignored | 满足 | BoringSSL implements close_notify processing in the audited DTLS record path. |
| 165 | sequence_number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 166 | sequence_number | must not exceed upper bound | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 167 | sequence_number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 168 | sequence_number | must not update validation window state based on this sequence number | 满足 | BoringSSL implements replay-window validation and record-number tracking for this requirement. |
| 169 | sequence_number | must equal | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 170 | sequence_number | set to constant | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 171 | sequence_number | must not equal any other received sequence number in that epoch during the lifetime of the association | 满足 | BoringSSL implements replay-window validation and record-number tracking for this requirement. |
| 172 | sequence_number | invalid if value check fails | 满足 | BoringSSL implements replay-window validation and record-number tracking for this requirement. |
| 173 | sequence_number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 174 | sequence_number | must be checked against a list of received records within the window | 满足 | BoringSSL implements replay-window validation and record-number tracking for this requirement. |
| 175 | sequence_number | validated as new | 满足 | BoringSSL implements replay-window validation and record-number tracking for this requirement. |
| 176 | sequence_number | must not wrap; invalid if wrap would occur without abandoning association or rekeying | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 177 | sequence_number | set to new value | 满足 | BoringSSL implements the corresponding DTLS handshake message serialization or tracking path. |
| 178 | sequence_number | set to constant | 满足 | BoringSSL implements replay-window validation and record-number tracking for this requirement. |
| 179 | sequence_number | must be present / must be absent | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 180 | sequence_number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 181 | sequence_number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 182 | sequence_number | derived/computed from another field | 满足 | BoringSSL implements the corresponding DTLS record-layer parsing, construction, validation, or state update path. |
| 183 | server_hello | must not treat EncryptedExtensions as safely acknowledgeable before ServerHello is received | 满足 | BoringSSL implements the normal DTLS ACK parsing or generation path for this field. |
| 184 | type | ACK must not be sent | 满足 | BoringSSL implements the normal DTLS ACK parsing or generation path for this field. |
| 185 | usage | must equal / selected behavior | 不满足 | NewConnectionId usage=cid_spare cannot be implemented because BoringSSL has no DTLS CID update state machine and no CID-capable record support. Root cause same as ID153. |
| 186 | usage | must equal / selected behavior | 不满足 | cid_immediate switching cannot be implemented because the sender always uses C=0 and there is no state transition to select a new CID for future records. Root cause same as ID153. |
| 187 | usage | set to constant | 不满足 | RequestConnectionId cannot trigger a cid_spare NewConnectionId response because RequestConnectionId/NewConnectionId handling and CID-capable records are absent. Root cause same as ID153. |
