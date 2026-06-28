# wolfMQTT-master 251-300 comparison results

- [non-English text removed]：`output/02_variable_changes.json` [non-English text removed]）
- target code：`wolfMQTT-master`
- satisfied：19
- partialsatisfied：23
- [non-English text removed]satisfied：8
- not applicable：0
- [non-English text removed]：0
- [non-English text removed]validation：all_locatable=True, references=151

| ID | source_idx | variable | action | status | [non-English text removed] |
|---:|---:|---|---|---|---|---:|
| 251 | 250 | Topic Filter | must not equal / include forbidden character | [non-English text removed]satisfied | not found[non-English text removed] Topic Filter medium U+0000 [non-English text removed]。 | 4 |
| 252 | 251 | Topic Filter | validated range check | satisfied | string[non-English text removed]。 | 3 |
| 253 | 252 | Topic Filter | must equal corresponding Topic Name level character for character | satisfied | [non-English text removed]。 | 3 |
| 254 | 253 | Topic Filter | invalid if value check fails | partialsatisfied | [non-English text removed] Topic Filter。 | 3 |
| 255 | 254 | Topic Filter | validity check | partialsatisfied | SUBSCRIBE [non-English text removed] UTF-8 semanticvalidation。 | 3 |
| 256 | 255 | Topic Filter | validity check | partialsatisfied | UNSUBSCRIBE [non-English text removed]。 | 3 |
| 257 | 256 | Topic Filter | must equal | satisfied | [non-English text removed]。 | 3 |
| 258 | 257 | Topic Filter | must not equal wildcard-start pattern for matching with '$'-prefixed Topic Name | satisfied | [non-English text removed]。 | 3 |
| 259 | 258 | Topic Filter | must not be modified or normalized | satisfied | [non-English text removed]。 | 3 |
| 260 | 259 | Topic Filter | must equal wildcard placement constraint | partialsatisfied | [non-English text removed]。 | 3 |
| 261 | 260 | Topic Filter | must equal whole-level placement constraint | [non-English text removed]processing。 | 3 |
| 262 | 261 | Topic Name | validated range check | [non-English text removed]satisfied | not found Topic Name [non-English text removed]。 | 3 |
| 263 | 262 | Topic Name | must not contain | [non-English text removed]rejectionvalidation。 | 3 |
| 264 | 263 | Topic Name | must be valid UTF-8; invalid if value check fails | partialsatisfied | [non-English text removed]。 | 3 |
| 265 | 264 | Topic Name | must be valid UTF-8; invalid if value check fails | partialsatisfied | Topic Name [non-English text removed] UTF-8 semanticvalidation。 | 3 |
| 266 | 265 | Topic Name | must not equal or include U+0000; invalid if value check fails | [non-English text removed]satisfied | Topic Name [non-English text removed]rejection。 | 3 |
| 267 | 266 | Topic Name | validated range check | satisfied | Topic Name use 2 [non-English text removed]lengthfield（0..65535）[non-English text removed]。 | 3 |
| 268 | 267 | Topic Name | validated range check | satisfied | encoding side[non-English text removed]。 | 3 |
| 269 | 268 | Topic Name | must not contain | partialsatisfied | Broker [non-English text removed]rejection Topic Name medium[non-English text removed]。 | 3 |
| 270 | 269 | Topic Name | must not contain | partialsatisfied | [non-English text removed]pathexplicitrejection[non-English text removed] Topic Name。 | 3 |
| 271 | 270 | Topic Name | validated range check | [non-English text removed]validation。 | 3 |
| 272 | 271 | Topic Name | must not equal / include forbidden character | [non-English text removed]satisfied | not found Topic Name [non-English text removed]rejection。 | 3 |
| 273 | 272 | Topic Name | validated range check | satisfied | Topic Name length[non-English text removed]。 | 3 |
| 274 | 273 | Topic Name | must equal corresponding Topic Filter level character for character | satisfied | [non-English text removed]。 | 3 |
| 275 | 274 | Topic Name | must match | satisfied | Broker [non-English text removed]。 | 3 |
| 276 | 275 | Topic Name | must equal required type/format | partialsatisfied | PUBLISH [non-English text removed] UTF-8 semanticvalidation。 | 3 |
| 277 | 276 | Topic Name | must not contain | partialsatisfied | [non-English text removed] Broker rejection Topic Name medium +/#，[non-English text removed]validation。 | 3 |
| 278 | 277 | Topic Name | validity check | partialsatisfied | PUBLISH Topic Name [non-English text removed]semanticvalidation。 | 3 |
| 279 | 278 | Topic Name | must be present | satisfied | PUBLISH [non-English text removed]processing Packet Identifier/[non-English text removed]。 | 3 |
| 280 | 279 | Topic Name | invalid if value check fails | satisfied | Topic Name [non-English text removed]。 | 3 |
| 281 | 280 | Topic Name | must not be modified or normalized | satisfied | [non-English text removed]。 | 3 |
| 282 | 281 | User Name | must be absent | partialsatisfied | CONNECT [non-English text removed]field”。 | 3 |
| 283 | 282 | User Name | must be absent | partialsatisfied | same as ID282：[non-English text removed]rejection。 | 3 |
| 284 | 283 | User Name | must be present | satisfied | [non-English text removed]。 | 3 |
| 285 | 284 | User Name | must be present | satisfied | same as ID284：Flag=1 [non-English text removed]。 | 3 |
| 286 | 285 | User Name | invalid if value check fails | partialsatisfied | [non-English text removed]semantic。 | 3 |
| 287 | 286 | User Name | must be valid UTF-8; invalid if value check fails | partialsatisfied | User Name field[non-English text removed]validation。 | 3 |
| 288 | 287 | User Name | must be present as next field | satisfied | CONNECT payload[non-English text removed]medium，User Name Flag=1 [non-English text removed]。 | 3 |
| 289 | 288 | User Name | must be valid UTF-8; invalid if value check fails | partialsatisfied | User Name [non-English text removed]。 | 3 |
| 290 | 289 | User Name | must not equal or include U+0000; invalid if value check fails | [non-English text removed]satisfied | not found[non-English text removed] User Name medium U+0000 [non-English text removed]explicitrejection。 | 3 |
| 291 | 290 | User Name | validated range check | satisfied | User Name [non-English text removed]range。 | 3 |
| 292 | 291 | User Name | must equal valid UTF-8 encoded string format | partialsatisfied | CONNECT medium User Name uselength[non-English text removed]validation UTF-8 semanticvalid[non-English text removed]。 | 3 |
| 293 | 292 | User Name Flag | must equal | partialsatisfied | [non-English text removed]。 | 3 |
| 294 | 293 | User Name Flag | must equal | partialsatisfied | [non-English text removed]payload。 | 3 |
| 295 | 294 | User Name Flag | must equal | satisfied | encoding side[non-English text removed] User Name Flag=1。 | 3 |
| 296 | 295 | User Name Flag | must equal | satisfied | [non-English text removed]field。 | 3 |
| 297 | 296 | Variable header | must be absent | partialsatisfied | DISCONNECT [non-English text removed]explicitvalidation remaining length=0。 | 3 |
| 298 | 297 | Variable header | must be absent | partialsatisfied | PINGREQ [non-English text removed] remaining length=0；broker receives PINGREQ [non-English text removed]/payload。 | 3 |
| 299 | 298 | Variable header | must be absent | partialsatisfied | PINGRESP [non-English text removed]validation remaining length [non-English text removed] 0。 | 3 |
| 300 | 299 | Will Flag | must equal | partialsatisfied | Will processinglogic[non-English text removed]“Connect accepted => Will Flag=1”[non-English text removed]。 | 3 |
