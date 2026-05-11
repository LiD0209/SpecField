import pathlib, re
ROOT = pathlib.Path(__file__).resolve().parents[2]
d1 = (ROOT/'boringssl-main'/'ssl'/'d1_both.cc').read_text(encoding='utf-8', errors='replace')
assert 'void dtls1_schedule_ack(SSL *ssl)' in d1, 'dtls1_schedule_ack missing'
assert 'ssl->d1->sending_ack = !ssl->d1->records_to_ack.empty();' in d1, 'ACK scheduling is not gated by non-empty records_to_ack as expected'
assert 'if (max_plaintext < 2 + 16)' in d1, 'send_ack no longer assumes room for at least one RecordNumber'
assert 'CBB_add_u16_length_prefixed(&cbb, &child)' in d1, 'ACK vector encoding missing'
# There should be no obvious helper that schedules an ACK independent of records_to_ack.
for token in ['send_empty_ack', 'empty ACK', 'empty_ack', 'records_to_ack.Clear();\n  ssl->d1->sending_ack = true']:
    assert token not in d1, f'unexpected empty ACK scheduling marker found: {token}'
print('PASS focused_static_id157_empty_ack: ACK format can encode a vector, but scheduling requires records_to_ack to be non-empty')
