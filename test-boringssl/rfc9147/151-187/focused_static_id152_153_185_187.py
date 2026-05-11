import pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
repo = ROOT / 'boringssl-main'
texts = {str(p.relative_to(repo)).replace('\\','/'): p.read_text(encoding='utf-8', errors='replace') for p in (repo/'ssl').glob('*.cc')}
texts.update({str(p.relative_to(repo)).replace('\\','/'): p.read_text(encoding='utf-8', errors='replace') for p in (repo/'ssl').glob('*.h')})
texts.update({str(p.relative_to(repo)).replace('\\','/'): p.read_text(encoding='utf-8', errors='replace') for p in (repo/'include'/'openssl').glob('*.h')})
all_text = '\n'.join(texts.values())
assert 'SSL3_RT_ACK 26' in all_text, 'ACK content type 26 constant missing'
heartbeat_tokens = ['SSL3_RT_HEARTBEAT', 'DTLS1_RT_HEARTBEAT', 'tls1_process_heartbeat', 'dtls1_process_heartbeat']
assert not any(tok in all_text for tok in heartbeat_tokens), 'unexpected heartbeat implementation token found'
cid_tokens = ['NewConnectionId', 'RequestConnectionId', 'ConnectionIdUsage', 'cid_spare', 'cid_immediate', 'request_connection_id', 'new_connection_id', 'tls12_cid']
assert not any(tok in all_text for tok in cid_tokens), 'unexpected DTLS CID update implementation token found'
dtls_record = (repo/'ssl'/'dtls_record.cc').read_text(encoding='utf-8', errors='replace')
assert 'if (out->type & 0x10)' in dtls_record and "Connection ID bit set" in dtls_record and 'return false;' in dtls_record, 'C-bit rejection not found'
assert 'We set C=0 (no Connection ID)' in dtls_record and 'out[0] = 0x2c | (epoch & 0x3);' in dtls_record, 'fixed no-CID send header not found'
print('PASS focused_static_id152_153_185_187: heartbeat unsupported; CID update/demux unsupported; ACK constant exists; C-bit rejected; sender C=0')
