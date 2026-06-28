# wolfMQTT-master 001-050 comparison results

- [non-English text removed]: `output/02_variable_changes.json` [non-English text removed]）
- target code: `wolfMQTT-master`
- satisfied: 15
- partialsatisfied: 13
- [non-English text removed]satisfied: 19
- not applicable: 3
- [non-English text removed]: 0
- [non-English text removed]validation: all_locatable=True, references=141

| ID | source_idx | variable | action | status | [non-English text removed] |
|---:|---:|---|---|---|---|---:|
| 1 | 0 | CleanSession | must equal 0 for stored session behavior | partialsatisfied | clean_session=0 [non-English text removed]。 | 4 |
| 2 | 1 | Bits 3,2,1 and 0 of the fixed header | set to constant | satisfied | SUBSCRIBE [non-English text removed] 0010。 | 2 |
| 3 | 2 | Bits 3,2,1 and 0 of the fixed header | set to constant | satisfied | UNSUBSCRIBE [non-English text removed] 0010。 | 2 |
| 4 | 3 | Bits 3,2,1 and 0 of the fixed header | invalid if value check fails | [non-English text removed]satisfied | SUBSCRIBE [non-English text removed]validation packet type，[non-English text removed]。 | 4 |
| 5 | 4 | Bits 3,2,1 and 0 of the fixed header | invalid if value check fails | [non-English text removed]satisfied | UNSUBSCRIBE [non-English text removed]path。 | 4 |
| 6 | 5 | Bits 3,2,1 and 0 of the fixed header | set to constant | satisfied | PUBREL [non-English text removed] 0010。 | 3 |
| 7 | 6 | Bits 3,2,1 and 0 of the fixed header | set to constant | satisfied | same as ID6，PUBREL [non-English text removed] 0010 semantic。 | 3 |
| 8 | 7 | Bits 3,2,1 and 0 of the fixed header | invalid if value check fails | [non-English text removed]。 | 4 |
| 9 | 8 | Bits 3,2,1 and 0 of the fixed header | invalid if value check fails | [non-English text removed]satisfied | same as ID8，PUBREL [non-English text removed]。 | 4 |
| 10 | 9 | Bits 3,2,1 and 0 of the fixed header | set to constant | satisfied | SUBSCRIBE [non-English text removed]。 | 2 |
| 11 | 10 | Bits 3,2,1 and 0 of the fixed header | invalid if value check fails | [non-English text removed]satisfied | SUBSCRIBE [non-English text removed]connection。 | 4 |
| 12 | 11 | Bits 3,2,1 and 0 of the fixed header | set to constant | satisfied | UNSUBSCRIBE [non-English text removed]。 | 2 |
| 13 | 12 | Bits 3,2,1 and 0 of the fixed header | invalid if value check fails | [non-English text removed]satisfied | UNSUBSCRIBE [non-English text removed]。 | 4 |
| 14 | 13 | CleanSession | must equal 0 for stored session behavior | partialsatisfied | [non-English text removed]。 | 4 |
| 15 | 14 | CleanSession | must equal 0 | partialsatisfied | clean_session=0 [non-English text removed]status。 | 4 |
| 16 | 15 | CleanSession | must equal 1 | satisfied | clean_session=1 [non-English text removed]semantic。 | 3 |
| 17 | 16 | CleanSession | set to constant | [non-English text removed] clean_session=1；client[non-English text removed]。 | 4 |
| 18 | 17 | CleanSession | must not equal | [non-English text removed] ClientId + clean_session=0 [non-English text removed]connection，MQTT5 path[non-English text removed] ID。 | 4 |
| 19 | 18 | CleanSession | set to constant | [non-English text removed]satisfied | same as ID17：[non-English text removed] clean_session=1。 | 3 |
| 20 | 19 | CleanSession | invalid if value check fails | [non-English text removed] ClientId + clean_session=0 [non-English text removed]。 | 3 |
| 21 | 20 | CleanSession | must equal | partialsatisfied | [non-English text removed]。 | 2 |
| 22 | 21 | CleanSession | set to constant | satisfied | clean_session=1 path[non-English text removed]。 | 2 |
| 23 | 22 | CleanSession | set to constant | not applicable | [non-English text removed] broker protocolmandatoryvalidation[non-English text removed]。 | 0 |
| 24 | 23 | CleanSession | should not equal | not applicable | [non-English text removed]。 | 0 |
| 25 | 24 | CleanSession | set to constant | partialsatisfied | [non-English text removed]。 | 3 |
| 26 | 25 | CleanSession | set to constant | not applicable | [non-English text removed]。 | 0 |
| 27 | 26 | CleanSession | must equal | [non-English text removed]satisfied | clean_session=0 [non-English text removed]。 | 3 |
| 28 | 27 | CleanSession | must equal 0 to trigger session resume behavior | partialsatisfied | clean_session=0 [non-English text removed]。 | 3 |
| 29 | 28 | Client identifier | invalid if value check fails | [non-English text removed] UTF-8 well-formed validation，[non-English text removed]。 | 3 |
| 30 | 29 | Client identifier | validated equality check | satisfied | server[non-English text removed]processing。 | 2 |
| 31 | 30 | Client identifier | must be interpreted as U+FEFF and must not be skipped or stripped | partialsatisfied | [non-English text removed]validation。 | 3 |
| 32 | 31 | Client identifier | must not include | [non-English text removed]satisfied | not found[non-English text removed]rejectionvalidation。 | 2 |
| 33 | 32 | Client identifier | must not include | [non-English text removed]satisfied | not found U+0000 [non-English text removed]rejectionvalidation。 | 3 |
| 34 | 33 | Client identifier | invalid if value check fails | [non-English text removed]。 | 3 |
| 35 | 34 | Client identifier | must be present / must be first field | satisfied | CONNECT [non-English text removed]。 | 4 |
| 36 | 35 | Client identifier | must be present / must be first field | satisfied | ClientId [non-English text removed]path。 | 2 |
| 37 | 36 | Client identifier | must be present | satisfied | [non-English text removed]medium ClientId field[non-English text removed]field。 | 2 |
| 38 | 37 | Client identifier | must be present | satisfied | [non-English text removed]fieldprocessing。 | 3 |
| 39 | 38 | Client identifier | must be valid UTF-8; invalid if value check fails | [non-English text removed]satisfied | ClientId UTF-8 valid[non-English text removed]。 | 3 |
| 40 | 39 | Client identifier | must not equal or include U+0000; invalid if value check fails | [non-English text removed]satisfied | ClientId [non-English text removed]。 | 3 |
| 41 | 40 | Client identifier | validated range check | partialsatisfied | protocol[non-English text removed]）。 | 3 |
| 42 | 41 | Client identifier | must equal zero bytes | satisfied | [non-English text removed]length ClientId。 | 2 |
| 43 | 42 | Client identifier | invalid if value check fails | [non-English text removed]length ClientId + clean_session=0 [non-English text removed]。 | 3 |
| 44 | 43 | Client identifier | set to server-assigned unique value | partialsatisfied | MQTT5 path[non-English text removed]。 | 3 |
| 45 | 44 | Client identifier | set to constant | partialsatisfied | same as ID44：[non-English text removed]。 | 3 |
| 46 | 45 | Client identifier | invalid if value check fails | partialsatisfied | ClientId [non-English text removed]。 | 4 |
| 47 | 46 | Client identifier | validated value constraint | satisfied | 0x02(Identifier rejected) semantic[non-English text removed]。 | 3 |
| 48 | 47 | Client identifier | validated range check and character-set membership check | partialsatisfied | [non-English text removed]explicitvalidationlogic。 | 2 |
| 49 | 48 | Client identifier | invalid if value check fails | partialsatisfied | [non-English text removed] ClientId+clean_session=0 [non-English text removed]。 | 2 |
| 50 | 49 | Client identifier | must be valid UTF-8; invalid if value check fails | [non-English text removed] well-formed validation。 | 3 |
