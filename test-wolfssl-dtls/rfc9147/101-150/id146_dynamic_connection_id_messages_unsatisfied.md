# ID146 Dynamic Connection ID num_cids/cid_spare Handling

This finding is covered by the combined report:

`id145_146_dynamic_connection_id_request_response_confirmed_unsatisfied.md`

Root cause: wolfSSL has static DTLS CID extension and unified-header CID support, but no `RequestConnectionId.num_cids` parsing and no `NewConnectionId(usage = cid_spare)` response path.
