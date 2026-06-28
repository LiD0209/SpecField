# wolfMQTT-master 101-150 comparison results

- [non-English text removed]: `output/02_variable_changes.json` [non-English text removed]）
- target code: `wolfMQTT-master`
- satisfied: 27
- partialsatisfied: 17
- [non-English text removed]satisfied: 6
- not applicable: 0
- [non-English text removed]: 0
- [non-English text removed]validation: all_locatable=True, references=163

| ID | source_idx | variable | action | status | [non-English text removed] |
|---:|---:|---|---|---|---|---:|
| 101 | 100 | Packet Identifier | validity judgment changes; subsequent matching Packet Identifier is treated as a new publication | partialsatisfied | PUBCOMP [non-English text removed]。 | 4 |
| 102 | 101 | Packet Identifier | selected from unused set | partialsatisfied | Broker [non-English text removed] id。 | 4 |
| 103 | 102 | Packet Identifier | must equal / derived from another field | satisfied | UNSUBACK [non-English text removed] UNSUBSCRIBE。 | 2 |
| 104 | 103 | Packet Identifier | must equal | satisfied | receives PUBREL [non-English text removed] packet id。 | 3 |
| 105 | 104 | Packet Identifier | must equal | satisfied | receives PUBREC [non-English text removed] packet id。 | 3 |
| 106 | 105 | Packet Identifier | must equal | satisfied | SUBACK [non-English text removed] SUBSCRIBE。 | 2 |
| 107 | 106 | Packet Identifier | must be selected from unused values | partialsatisfied | QoS1 [non-English text removed]use”validation。 | 4 |
| 108 | 107 | Packet Identifier | copy from another field | satisfied | QoS1 [non-English text removed]。 | 3 |
| 109 | 108 | Packet Identifier | must be present | satisfied | QoS1 [non-English text removed] 0）。 | 3 |
| 110 | 109 | Packet Identifier | copy from another field | satisfied | QoS2 [non-English text removed]。 | 3 |
| 111 | 110 | Packet Identifier | must be selected from unused values | partialsatisfied | QoS2 [non-English text removed]。 | 4 |
| 112 | 111 | Packet Identifier | must be present | satisfied | QoS2 [non-English text removed] 0）。 | 3 |
| 113 | 112 | Packet Identifier | must equal | satisfied | [non-English text removed] packet id。 | 2 |
| 114 | 113 | Packet Identifier | derived/copied from another field | satisfied | SUBACK [non-English text removed] SUBSCRIBE。 | 2 |
| 115 | 114 | Packet Identifier | derived/copied from another field | satisfied | UNSUBACK [non-English text removed] UNSUBSCRIBE。 | 2 |
| 116 | 115 | Packet Identifier | clear/discard | [non-English text removed]“discard packet identifier”explicitstatus[non-English text removed]。 | 4 |
| 117 | 116 | Packet Identifier | store | [non-English text removed]satisfied | not found Method B [non-English text removed]logic。 | 4 |
| 118 | 117 | Packet Identifier | store | [non-English text removed]。 | 4 |
| 119 | 118 | Packet Identifier | must be absent | satisfied | QoS0 PUBLISH [non-English text removed]。 | 3 |
| 120 | 119 | Packet Identifier | must equal | satisfied | SUBACK use[non-English text removed] packet id。 | 2 |
| 121 | 120 | Packet Identifier | must be present and non-zero 16-bit | partialsatisfied | [non-English text removed] SUBSCRIBE/UNSUBSCRIBE/PUBLISH(QoS>0) [non-English text removed] non-zero validation；[non-English text removed]validation non-zero。 | 6 |
| 122 | 121 | Packet Identifier | must equal | satisfied | UNSUBACK [non-English text removed]。 | 2 |
| 123 | 122 | Packet Identifier | must equal | partialsatisfied | receives[non-English text removed]。 | 4 |
| 124 | 123 | Packet Identifier | must equal | [non-English text removed]satisfied | clean_session=0 [non-English text removed] PUBLISH/PUBREL。 | 4 |
| 125 | 124 | Packet Identifier | must equal original value / reuse original | [non-English text removed]。 | 4 |
| 126 | 125 | Packet Identifier | set to same value as another field | satisfied | [non-English text removed] packet id。 | 2 |
| 127 | 126 | Packet Identifier | derived/computed from another field | satisfied | [non-English text removed] packet id。 | 2 |
| 128 | 127 | Packet Identifier | set to same value as tracked identifier | satisfied | PUBCOMP [non-English text removed] packet id。 | 2 |
| 129 | 128 | Packet Identifier | becomes available for reuse | partialsatisfied | ACK processing[non-English text removed]。 | 4 |
| 130 | 129 | Packet Identifier | set to a currently unused value | partialsatisfied | [non-English text removed]。 | 4 |
| 131 | 130 | Packet Identifier | must equal original PUBLISH Packet Identifier | satisfied | PUBACK/PUBREC/PUBREL pathmedium packet id [non-English text removed]。 | 4 |
| 132 | 131 | Packet Identifier | must equal Packet Identifier used in corresponding request | satisfied | SUBACK/UNSUBACK [non-English text removed]。 | 3 |
| 133 | 132 | Packet Identifier | must be present and must not equal zero | partialsatisfied | field[non-English text removed]。 | 5 |
| 134 | 133 | Packet Identifier | must equal prior Packet Identifier used for that packet | partialsatisfied | [non-English text removed]。 | 4 |
| 135 | 134 | Packet Identifier | must be present | satisfied | QoS1/2 PUBLISH [non-English text removed] packet id。 | 3 |
| 136 | 135 | Packet Identifier | derived/computed from another field | satisfied | PUBACK [non-English text removed] PUBLISH。 | 2 |
| 137 | 136 | Packet Identifier | derived/computed from another field | satisfied | PUBREC [non-English text removed] PUBLISH。 | 2 |
| 138 | 137 | Packet Identifier | same requirements apply as for Client assignment and reuse | partialsatisfied | Server [non-English text removed]。 | 4 |
| 139 | 138 | Password | must be absent | partialsatisfied | [non-English text removed]explicitrejection。 | 4 |
| 140 | 139 | Password | must be absent | partialsatisfied | same as ID139：Password Flag=0 [non-English text removed]。 | 4 |
| 141 | 140 | Password | must be present | satisfied | Password Flag=1 [non-English text removed]。 | 2 |
| 142 | 141 | Password | must be present | satisfied | same as ID141：Password Flag=1 [non-English text removed]。 | 2 |
| 143 | 142 | Password | must be present as next field | partialsatisfied | [non-English text removed]。 | 4 |
| 144 | 143 | Password | validated range check | satisfied | Password fieldlengthuse 16-bit [non-English text removed]boundaryvalidation（0..65535）。 | 4 |
| 145 | 144 | Password | invalid if value check fails | satisfied | [non-English text removed]）。 | 4 |
| 146 | 145 | Password Flag | must equal | partialsatisfied | Password Flag=0 [non-English text removed]。 | 2 |
| 147 | 146 | Password Flag | must equal | satisfied | Password Flag=1 [non-English text removed]error。 | 2 |
| 148 | 147 | Password Flag | set to constant | partialsatisfied | [non-English text removed]。 | 4 |
| 149 | 148 | Password Flag | must equal | partialsatisfied | Password Flag=1 [non-English text removed]。 | 4 |
| 150 | 149 | Payload | must be present | [non-English text removed]satisfied | SUBSCRIBE [non-English text removed] payload（topic_count=0），[non-English text removed]。 | 5 |
