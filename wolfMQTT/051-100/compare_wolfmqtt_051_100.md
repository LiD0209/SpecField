# wolfMQTT-master 051-100 comparison results

- [non-English text removed]: `output/02_variable_changes.json` [non-English text removed]）
- target code: `wolfMQTT-master`
- satisfied: 26
- partialsatisfied: 16
- [non-English text removed]satisfied: 8
- not applicable: 0
- [non-English text removed]: 0
- [non-English text removed]validation: all_locatable=True, references=145

| ID | source_idx | variable | action | status | [non-English text removed] |
|---:|---:|---|---|---|---|---:|
| 51 | 50 | CONNACK return code | set to constant | [non-English text removed] ClientId + clean_session=0 [non-English text removed] 0x02（Identifier rejected）。 | 3 |
| 52 | 51 | CONNACK return code | must not equal zero | partialsatisfied | partialvalidation[non-English text removed] CONNACK。 | 4 |
| 53 | 52 | CONNACK return code | set to constant | satisfied | CONNECT validation[non-English text removed] 0。 | 2 |
| 54 | 53 | CONNACK return code | must not equal | satisfied | [non-English text removed]。 | 4 |
| 55 | 54 | CONNACK return code | set to constant | [non-English text removed]satisfied | same as ID51：[non-English text removed] ClientId + clean_session=0 [non-English text removed] 0x02。 | 3 |
| 56 | 55 | CONNACK return code | set to constant | satisfied | [non-English text removed] clean_session=0 connection[non-English text removed] 0。 | 3 |
| 57 | 56 | CONNACK return code | set to constant | satisfied | [non-English text removed] clean_session=1 connection[non-English text removed] 0。 | 3 |
| 58 | 57 | CONNACK return code | set to constant | satisfied | [non-English text removed] 0。 | 3 |
| 59 | 58 | CONNACK return code | set to constant | partialsatisfied | [non-English text removed]。 | 3 |
| 60 | 59 | CONNACK return code | set to constant | partialsatisfied | same as ID59：0x02 [non-English text removed]partial ClientId rejectionpath[non-English text removed]。 | 3 |
| 61 | 60 | CONNACK return code | set to constant | satisfied | server[non-English text removed]。 | 2 |
| 62 | 61 | CONNACK return code | set to constant | [non-English text removed]。 | 3 |
| 63 | 62 | Connect Acknowledge Flags | validated value constraint | partialsatisfied | [non-English text removed]explicitvalidation bits7..1 [non-English text removed] 0。 | 3 |
| 64 | 63 | Connect Flags | indicates presence or absence of payload fields | satisfied | Connect Flags [non-English text removed]。 | 4 |
| 65 | 64 | Connect Return code | selected from offered list | satisfied | [non-English text removed]。 | 4 |
| 66 | 65 | Connect Return code | invalid if value selection fails | partialsatisfied | [non-English text removed]。 | 4 |
| 67 | 66 | continuation bit | set to 1 | satisfied | Remaining Length [non-English text removed] continuation bit。 | 3 |
| 68 | 67 | continuation bit | must not equal 0 to continue decoding | satisfied | Remaining Length [non-English text removed] `(encodedByte & 128) != 0`。 | 2 |
| 69 | 68 | DUP | value ignored for judgment | satisfied | [non-English text removed]processing。 | 3 |
| 70 | 69 | DUP | set to constant | partialsatisfied | broker [non-English text removed] QoS0+dup=1。 | 2 |
| 71 | 70 | DUP | set to constant | partialsatisfied | QoS1 [non-English text removed] duplicate。 | 3 |
| 72 | 71 | DUP | set to constant | partialsatisfied | QoS2 [non-English text removed]mandatory。 | 3 |
| 73 | 72 | DUP | set to constant | partialsatisfied | QoS0 [non-English text removed]。 | 2 |
| 74 | 73 | DUP | set to constant | partialsatisfied | “[non-English text removed]mandatoryvalidation。 | 3 |
| 75 | 74 | DUP | must not be derived/computed from another field | partialsatisfied | broker [non-English text removed]。 | 3 |
| 76 | 75 | DUP | set to constant | [non-English text removed]satisfied | not found[non-English text removed]path。 | 3 |
| 77 | 76 | DUP flag | set to constant | partialsatisfied | same as ID74：QoS0 DUP=0 [non-English text removed]mandatory。 | 3 |
| 78 | 77 | DUP flag | set to constant | [non-English text removed]satisfied | same as ID76：Client/Server [non-English text removed]。 | 3 |
| 79 | 78 | DUP flag | derived/computed from another condition | partialsatisfied | [non-English text removed]。 | 2 |
| 80 | 79 | encodedByte | set to X MOD 128 | satisfied | Variable Byte Integer [non-English text removed] `encodedByte = X MOD 128`。 | 1 |
| 81 | 80 | encodedByte | set from next byte in stream | satisfied | [non-English text removed]。 | 1 |
| 82 | 81 | encodedByte | set to encodedByte OR 128 | satisfied | [non-English text removed] `encodedByte \|= 128`。 | 2 |
| 83 | 82 | flags | must equal value listed in that table | [non-English text removed]validation。 | 3 |
| 84 | 83 | flags | invalid if value check fails | [non-English text removed]“invalid flags -> close connection”processing。 | 3 |
| 85 | 84 | flags | invalid if value check fails | [non-English text removed]satisfied | same as ID84：[non-English text removed]processing。 | 3 |
| 86 | 85 | Keep Alive | validated upper bound check | partialsatisfied | client[non-English text removed]。 | 3 |
| 87 | 86 | Keep Alive | upper bound check | partialsatisfied | same as ID86：[non-English text removed]。 | 3 |
| 88 | 87 | Keep Alive | validated timeout check | satisfied | server[non-English text removed]。 | 3 |
| 89 | 88 | Keep Alive | must equal zero to turn off keep alive mechanism | satisfied | Keep Alive [non-English text removed]）。 | 1 |
| 90 | 89 | Keep Alive | must not exceed inactivity limit; invalid if value check fails | satisfied | [non-English text removed]disconnect。 | 3 |
| 91 | 90 | Keep Alive | validated range check | satisfied | Keep Alive use 16 [non-English text removed]）。 | 3 |
| 92 | 91 | length | must equal byte count of the UTF-8 encoded string itself | satisfied | UTF-8 string[non-English text removed]。 | 3 |
| 93 | 92 | length | derived/computed from another field | satisfied | Password [non-English text removed]。 | 3 |
| 94 | 93 | length | validated range check | satisfied | UTF-8 stringlength[non-English text removed]boundaryvalidation。 | 3 |
| 95 | 94 | length | derived/computed from another field | satisfied | Will Message length[non-English text removed]length。 | 3 |
| 96 | 95 | Packet Identifier | must equal previous value / reuse same value | partialsatisfied | packet_id [non-English text removed]。 | 4 |
| 97 | 96 | Packet Identifier | must equal corresponding PUBLISH Packet value | satisfied | PUBACK/PUBREC/PUBREL [non-English text removed] packet_id。 | 4 |
| 98 | 97 | Packet Identifier | must be absent | satisfied | QoS0 [non-English text removed]。 | 3 |
| 99 | 98 | Packet Identifier | must equal corresponding SUBSCRIBE or UNSUBSCRIBE Packet value | satisfied | SUBACK/UNSUBACK [non-English text removed] SUBSCRIBE/UNSUBSCRIBE [non-English text removed] packet_id。 | 4 |
| 100 | 99 | Packet Identifier | must equal | satisfied | [non-English text removed]。 | 3 |
