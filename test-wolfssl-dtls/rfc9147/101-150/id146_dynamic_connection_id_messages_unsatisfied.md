# Dynamic Connection ID num_cids/cid_spare Response

This finding is covered by the combined report:

`id145_146_dynamic_connection_id_request_response_confirmed_unsatisfied.md`

Meaning: this is the main interoperability gap. RFC 9147 says endpoints SHOULD respond to `RequestConnectionId` with `NewConnectionId(usage = cid_spare)` containing the requested `num_cids` CIDs. wolfSSL has static DTLS CID extension and unified-header CID support, but no `RequestConnectionId.num_cids` parser and no `NewConnectionId(usage = cid_spare)` response path.
