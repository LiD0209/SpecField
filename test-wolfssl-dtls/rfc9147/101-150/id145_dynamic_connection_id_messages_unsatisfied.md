# ID145 Dynamic Connection ID Messages

This finding is covered by the combined report:

`id145_146_dynamic_connection_id_request_response_confirmed_unsatisfied.md`

Root cause: wolfSSL has static DTLS CID extension and unified-header CID support, but no RFC 9147 `RequestConnectionId` / `NewConnectionId` handshake-message state machine.
