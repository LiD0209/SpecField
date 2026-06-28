# Dynamic Connection ID Excessive-Request Handling

This finding is covered by the combined report:

`id145_146_dynamic_connection_id_request_response_confirmed_unsatisfied.md`

Meaning: this item is based on the RFC 9147 `MAY` exception for excessive `RequestConnectionId.num_cids` requests. It is not an independent hard MUST violation. It remains unsatisfied here because wolfSSL lacks the underlying RFC 9147 `RequestConnectionId` / `NewConnectionId` dynamic CID state machine.
