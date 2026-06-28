# wolfMQTT-master 301-336 comparison results（stored in 301-350 [non-English text removed]）

- [non-English text removed]：`output/02_variable_changes.json` [non-English text removed]）
- target code：`wolfMQTT-master`
- satisfied：20
- partialsatisfied：12
- [non-English text removed]satisfied：4
- not applicable：0
- [non-English text removed]：0
- [non-English text removed]validation：all_locatable=True, references=108

| ID | source_idx | variable | action | status | [non-English text removed] |
|---:|---:|---|---|---|---|---:|
| 301 | 300 | Will Flag | must equal | satisfied | Will Flag=0 [non-English text removed]decoding side `enable_lwt` [non-English text removed]。 | 3 |
| 302 | 301 | Will Flag | must equal | satisfied | Will Flag=1 [non-English text removed] LWT。 | 3 |
| 303 | 302 | Will Flag | must equal | satisfied | Will Flag=1 [non-English text removed]。 | 3 |
| 304 | 303 | Will Flag | must equal 1 | satisfied | server CONNECT processing[non-English text removed] Will logic。 | 3 |
| 305 | 304 | Will Message | must be absent | partialsatisfied | Will Flag=0 [non-English text removed]validation。 | 3 |
| 306 | 305 | Will Message | must be absent | partialsatisfied | same as ID305：missing[non-English text removed]explicitrejection。 | 3 |
| 307 | 306 | Will Message | must be present | satisfied | Will Flag=1 [non-English text removed]error。 | 3 |
| 308 | 307 | Will Message | must be present / stored | satisfied | CONNECT [non-English text removed] Will Topic/Payload/QoS/Retain [non-English text removed]clientconnection。 | 3 |
| 309 | 308 | Will Message | discard / clear without publishing | satisfied | receives DISCONNECT [non-English text removed]publish。 | 3 |
| 310 | 309 | Will Message | clear/remove | satisfied | Will publish[non-English text removed]clears；normal DISCONNECT [non-English text removed]clears。 | 3 |
| 311 | 310 | Will Message | removed/cleared from stored Session state | satisfied | same as ID310，Will [non-English text removed]。 | 3 |
| 312 | 311 | Will Message | must be present as next field | satisfied | Will Flag=1 [non-English text removed] CONNECT payloadmedium[non-English text removed]。 | 3 |
| 313 | 312 | Will Message | must be present / stored | satisfied | connection[non-English text removed]（`bc->has_will=1`）。 | 3 |
| 314 | 313 | Will Message | must be present | satisfied | Will Flag=1 [non-English text removed] Will fieldpath。 | 3 |
| 315 | 314 | Will QoS | set to constant | partialsatisfied | encoding side[non-English text removed]validation Will Flag=0 [non-English text removed] 0。 | 3 |
| 316 | 315 | Will QoS | must equal | partialsatisfied | same as ID315：missing[non-English text removed]protocolrejection。 | 3 |
| 317 | 316 | Will QoS | set to constant | partialsatisfied | same as ID315/316：[non-English text removed]mandatoryvalidation。 | 3 |
| 318 | 317 | Will QoS | validated range check | [non-English text removed]satisfied | not found[non-English text removed] Will QoS=3（reserved value）[non-English text removed]。 | 3 |
| 319 | 318 | Will QoS | validated membership check | [non-English text removed]satisfied | same as ID318：[non-English text removed] {0,1,2}。 | 3 |
| 320 | 319 | Will QoS | must not equal | [non-English text removed]satisfied | same as ID318/319：Will QoS=3 [non-English text removed]error。 | 3 |
| 321 | 320 | Will QoS | used/selected from Connect Flags | satisfied | Will Flag=1 [non-English text removed]use。 | 3 |
| 322 | 321 | Will Retain | set to constant | partialsatisfied | encoding side[non-English text removed]。 | 3 |
| 323 | 322 | Will Retain | must equal | partialsatisfied | same as ID322：Will Flag=0 [non-English text removed]。 | 3 |
| 324 | 323 | Will Retain | must equal | satisfied | Will Retain=0 [non-English text removed]。 | 3 |
| 325 | 324 | Will Retain | must equal | satisfied | Will Retain=1 [non-English text removed] retained processingpath（[non-English text removed] retained）。 | 3 |
| 326 | 325 | Will Retain | used/selected from Connect Flags | satisfied | Will Retain [non-English text removed]connectionstatus。 | 3 |
| 327 | 326 | Will topic | must be absent | partialsatisfied | Will Flag=0 [non-English text removed] Will topic payload。 | 3 |
| 328 | 327 | Will topic | must be absent | partialsatisfied | same as ID327：[non-English text removed]。 | 3 |
| 329 | 328 | Will topic | must be present | satisfied | Will Flag=1 [non-English text removed] Will topic。 | 3 |
| 330 | 329 | Will topic | must be valid UTF-8; invalid if value check fails | partialsatisfied | Will topic [non-English text removed]validation。 | 3 |
| 331 | 330 | Will topic | must be present as next field | satisfied | Will Flag=1 [non-English text removed] CONNECT medium Will [non-English text removed]。 | 3 |
| 332 | 331 | Will topic | must be present | satisfied | Will Flag=1 [non-English text removed] Will topic field。 | 3 |
| 333 | 332 | Will topic | must satisfy validity check | partialsatisfied | Will topic [non-English text removed]。 | 3 |
| 334 | 333 | Will topic | must be valid UTF-8; invalid if value check fails | partialsatisfied | same as ID330/333：Will topic [non-English text removed]semanticvalidation。 | 3 |
| 335 | 334 | Will topic | must not equal or include U+0000; invalid if value check fails | [non-English text removed]satisfied | not found[non-English text removed] Will topic medium U+0000 [non-English text removed]explicitrejection。 | 3 |
| 336 | 335 | Will topic | validated range check | satisfied | Will topic stringlength[non-English text removed]boundaryvalidation。 | 3 |
