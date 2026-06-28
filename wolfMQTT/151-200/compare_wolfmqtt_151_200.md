# wolfMQTT-master 151-200 comparison results

- [non-English text removed]: `output/02_variable_changes.json` [non-English text removed]）
- target code: `wolfMQTT-master`
- satisfied: 16
- partialsatisfied: 16
- [non-English text removed]satisfied: 18
- not applicable: 0
- [non-English text removed]: 0
- [non-English text removed]validation: all_locatable=True, references=153

| ID | source_idx | variable | action | status | [non-English text removed] |
|---:|---:|---|---|---|---|---:|
| 151 | 150 | Payload | must be present and contain at least one Topic Filter; invalid if absent | [non-English text removed]satisfied | UNSUBSCRIBE [non-English text removed] payload（topic_count=0），[non-English text removed]。 | 4 |
| 152 | 151 | Payload | must be absent | [non-English text removed]validation Remaining Length/payload [non-English text removed] 0。 | 3 |
| 153 | 152 | Payload | must be absent | [non-English text removed]validation Remaining Length [non-English text removed] PINGRESP。 | 3 |
| 154 | 153 | Payload | must be absent | partialsatisfied | [non-English text removed]mandatory remain_len=0。 | 4 |
| 155 | 154 | Payload | must be absent | partialsatisfied | PUBCOMP [non-English text removed] packet id（remain_len=2）；[non-English text removed] 2。 | 4 |
| 156 | 155 | Payload | must be absent | partialsatisfied | PUBREL [non-English text removed] packet id（remain_len=2）；[non-English text removed] 2。 | 4 |
| 157 | 156 | Payload | must be absent | satisfied | UNSUBACK [non-English text removed] payload。 | 3 |
| 158 | 157 | Payload | invalid if value check fails | [non-English text removed]satisfied | SUBSCRIBE [non-English text removed]。 | 4 |
| 159 | 158 | Payload | derived/computed from another field | satisfied | PUBLISH payload length[non-English text removed] variable header length[non-English text removed]。 | 3 |
| 160 | 159 | Payload | must not be present / must not be stored | satisfied | RETAIN=1 [non-English text removed]。 | 3 |
| 161 | 160 | Payload | must equal | satisfied | [non-English text removed]“retained + payload=0 => [non-English text removed]。 | 3 |
| 162 | 161 | Payload | must be absent | partialsatisfied | PUBACK [non-English text removed] payload；decoding side[non-English text removed]validation remain_len>=2，[non-English text removed]validation。 | 3 |
| 163 | 162 | Payload | must be absent | partialsatisfied | PUBREC [non-English text removed] payload；decoding side[non-English text removed]validation。 | 3 |
| 164 | 163 | Payload | validated range check | satisfied | PUBLISH payload [non-English text removed]boundaryprocessing。 | 3 |
| 165 | 164 | QoS | must not equal 0 when Packet Identifier is required; if QoS is set to 0 then Packet Identifier must be absent | partialsatisfied | encoding sidesatisfied QoS>0 [non-English text removed]validation packet id [non-English text removed] 0。 | 5 |
| 166 | 165 | QoS | derived/computed from another field | satisfied | [non-English text removed]。 | 3 |
| 167 | 166 | QoS | validated range check | [non-English text removed]path。 | 4 |
| 168 | 167 | QoS | set to constant | satisfied | QoS0 [non-English text removed] 0。 | 2 |
| 169 | 168 | QoS | set to constant | partialsatisfied | QoS1 [non-English text removed]。 | 3 |
| 170 | 169 | QoS | set to constant | partialsatisfied | QoS2 [non-English text removed]rejection。 | 3 |
| 171 | 170 | QoS | must not equal 0 when Packet Identifier is required; if equal to 0 then Packet Identifier must be absent | partialsatisfied | QoS [non-English text removed]。 | 4 |
| 172 | 171 | QoS | validated range check with comparison > 0 | partialsatisfied | QoS>0 [non-English text removed]。 | 3 |
| 173 | 172 | QoS | derived/computed from another field | satisfied | [non-English text removed]）。 | 2 |
| 174 | 173 | QoS | set/overwrite/select | satisfied | SUBACK [non-English text removed]。 | 4 |
| 175 | 174 | QoS | derived/computed from another field | partialsatisfied | [non-English text removed]logic。 | 4 |
| 176 | 175 | QoS | validated range check | [non-English text removed]satisfied | clean_session=0 [non-English text removed]。 | 3 |
| 177 | 176 | QoS | must equal | partialsatisfied | QoS0 + DUP [non-English text removed]。 | 2 |
| 178 | 177 | QoS | set to constant | partialsatisfied | [non-English text removed]。 | 2 |
| 179 | 178 | QoS | membership check | [non-English text removed]satisfied | SUBSCRIBE [non-English text removed]。 | 3 |
| 180 | 179 | QoS | invalid if value check fails | [non-English text removed]satisfied | SUBSCRIBE medium[non-English text removed]。 | 3 |
| 181 | 180 | QoS | derived/computed from another field | satisfied | [non-English text removed]：QoS1->PUBACK，QoS2->PUBREC，QoS0 [non-English text removed]。 | 3 |
| 182 | 181 | QoS | selected from offered list | partialsatisfied | [non-English text removed]。 | 3 |
| 183 | 182 | QoS bits | invalid if value check fails | [non-English text removed] PUBLISH QoS bits=11 [non-English text removed]。 | 3 |
| 184 | 183 | QoS bits | must not equal | [non-English text removed]rejection。 | 2 |
| 185 | 184 | QoS bits | invalid if value check fails | [non-English text removed]satisfied | same as ID183：receives QoS bits=11 [non-English text removed]。 | 3 |
| 186 | 185 | QoS bits | must not equal forbidden combination | [non-English text removed]satisfied | same as ID184：forbidden QoS bits [non-English text removed]。 | 2 |
| 187 | 186 | Remaining Length | validated upper bound check | satisfied | Remaining Length [non-English text removed]。 | 3 |
| 188 | 187 | Remaining Length | must equal number of bytes remaining within the current packet, including data in the variable header and the payload, excluding the bytes used to encode the Remaining Length | partialsatisfied | [non-English text removed]。 | 4 |
| 189 | 188 | Remaining Length | derived/computed from another field | satisfied | CONNECT [non-English text removed]。 | 4 |
| 190 | 189 | Remaining Length | derived/computed from another field | satisfied | PUBLISH payload length[non-English text removed]。 | 2 |
| 191 | 190 | Remaining Length | set to constant | satisfied | PUBACK [non-English text removed]path Remaining Length [non-English text removed] 2。 | 2 |
| 192 | 191 | Remaining Length | set to constant | satisfied | PUBREC [non-English text removed]path Remaining Length [non-English text removed] 2。 | 2 |
| 193 | 192 | Remaining Length | set to decoded value | satisfied | Remaining Length [non-English text removed]。 | 3 |
| 194 | 193 | Requested QoS | must equal one of allowed values | [non-English text removed]satisfied | Requested QoS [non-English text removed]）。 | 2 |
| 195 | 194 | Requested QoS | invalid if value check fails | [non-English text removed]satisfied | Requested QoS [non-English text removed]protocolerrordisconnectconnection。 | 3 |
| 196 | 195 | Requested QoS | selected from offered list | partialsatisfied | server[non-English text removed]。 | 4 |
| 197 | 196 | Reserved bits | set to constant / must equal listed table value | [non-English text removed]validation。 | 3 |
| 198 | 197 | Reserved bits | must equal zero; invalid if not zero | [non-English text removed]satisfied | DISCONNECT reserved bits [non-English text removed]explicit invalid->disconnect validation[non-English text removed]。 | 3 |
| 199 | 198 | Reserved bits | must equal | [non-English text removed]satisfied | SUBSCRIBE [non-English text removed] 0。 | 2 |
| 200 | 199 | Reserved bits | invalid if value check fails | [non-English text removed]satisfied | reserved bits [non-English text removed] invalid->disconnect processing。 | 3 |
