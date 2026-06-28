# Issue: 0-RTT Anti-Replay Minimum Requirement Not Enforced (RFC 8446 Section 8)

## Summary
- Conclusion: when `WOLFSSL_EARLY_DATA` is enabled, the current implementation path does not show the RFC 8446 Section 8 minimum guarantee that the same 0-RTT handshake is accepted at most once per server instance.
- Scope: conditional risk, because early data is off by default.

---

## RFC Exact Text (verbatim)

Source: `document/TLS1.3.txt`

### 1) Minimum requirement: at most once per server instance
```text
5479       only a limited number of times.  The server MUST ensure that any
5480       instance of it (be it a machine, a thread, or any other entity within
5481       the relevant serving infrastructure) would accept 0-RTT for the same
5482       0-RTT handshake at most once; this limits the number of replays to
5483       the number of server instances in the deployment.
```

```text
5495       provides the same or a stronger guarantee.  The "at most once per
5496       server instance" guarantee is a minimum requirement; servers SHOULD
5497       limit 0-RTT replays further when feasible.
```

### 2) Example anti-replay mechanisms from RFC
```text
5506       The simplest form of anti-replay defense is for the server to only
5507       allow each session ticket to be used once.  For instance, the server
5508       can maintain a database of all outstanding valid tickets, deleting
5509       each ticket from the database as it is used.  If an unknown ticket is
5510       provided, the server would then fall back to a full handshake.
```

```text
5528       An alternative form of anti-replay is to record a unique value
5529       derived from the ClientHello (generally either the random value or
5530       the PSK binder) and reject duplicates.
...
5551       If the expected_arrival_time is in the window, then the server checks
5552       to see if it has recorded a matching ClientHello.  If one is found,
5553       it either aborts the handshake with an "illegal_parameter" alert or
5554       accepts the PSK but rejects 0-RTT.  If no matching ClientHello is
5555       found, then it accepts 0-RTT and then stores the ClientHello for as
5556       long as the expected_arrival_time is inside the window.
```

### 3) Separate ticket-age freshness requirement
```text
2942       For PSKs provisioned via NewSessionTicket, a server MUST validate
2943       that the ticket age for the selected PSK identity ...
2946       was issued (see Section 8).  If it is not, the server SHOULD proceed
2947       with the handshake but reject 0-RTT ...
```

---

## Code Exact Text (verbatim)

### A) Feature default is off
Source: `wolfssl-master/src/tls13.c`
```c
40  * WOLFSSL_EARLY_DATA:       Allow 0-RTT early data                default: off
```

### B) Ticket-age freshness check exists
Source: `wolfssl-master/src/internal.c`
```c
39542        ato32(psk->it->ageAdd, &ticketAdd);
39543        /* Subtract client's ticket age and unobfuscate. */
39544        diff -= psk->ticketAge;
39545        diff += ticketAdd;
39546        /* Check session and ticket age timeout.
39547         * Allow +/- 1000 milliseconds on ticket age.
39548         */
39549        if (diff < -1000 || diff - MAX_TICKET_AGE_DIFF * 1000 > 1000)
39550            return WOLFSSL_FATAL_ERROR;
```

### C) After freshness check, flow continues to early-data path
Source: `wolfssl-master/src/tls13.c`
```c
6195            ret = DoClientTicketCheck(ssl, current, ssl->timeout, suite);
6196            if (ret == 0)
6197                DoClientTicketFinalize(ssl, current->it, current->sess);
...
6205            if (ret != 0)
6206                continue;
```

```c
6434        extEarlyData = TLSX_Find(ssl->extensions, TLSX_EARLY_DATA);
6435        if (extEarlyData != NULL) {
6436            /* Check if accepting early data and first PSK. */
6437            if (ssl->earlyData != no_early_data && first) {
6438                extEarlyData->resp = 1;
...
6449                ssl->earlyData = process_early_data;
```

### D) Early-data acceptance status is set from config/state
Source: `wolfssl-master/src/tls.c`
```c
12710        if (ssl->earlyData == expecting_early_data) {
12712            if (ssl->options.maxEarlyDataSz != 0)
12713                ssl->earlyDataStatus = WOLFSSL_EARLY_DATA_ACCEPTED;
12714            else
12715                ssl->earlyDataStatus = WOLFSSL_EARLY_DATA_REJECTED;
12717            return TLSX_EarlyData_Use(ssl, 0, 0);
```

### E) Repo-wide scan for RFC 8.2 replay-recording keywords
Command:
```text
rg -n "expected_arrival_time|recording window|matching ClientHello|Bloom|single-use ticket|rejecting repeats|apparent replay" wolfssl-master/src wolfssl-master/wolfssl
```
Observed result: `Exit code: 1` (no matches).

---

## Why This Is Non-Compliant

RFC 8446 Section 8 minimum requirement is:
- same 0-RTT handshake accepted at most once per server instance (`5479-5483`, `5495-5497`).

What is visible in code:
- freshness/age checks are implemented (`internal.c:39542-39550`);
- then handshake proceeds to early-data acceptance flow (`tls13.c:6195-6197`, `6434-6449`);
- no visible per-instance replay-state check for "this same 0-RTT handshake already accepted" in inspected paths;
- no visible single-use ticket deletion path or ClientHello-recording duplicate rejection mechanism in repo-wide keyword scan.

Therefore:
- with early data enabled, this appears inconsistent with RFC 8446 Section 8 minimum anti-replay requirement.

---

## Security Impact
- Risk type: high risk, condition-triggered.
- Trigger condition: `WOLFSSL_EARLY_DATA` enabled and non-idempotent business actions processed in 0-RTT.
- Impact: possible duplicate business execution (duplicate submit/charge/state transition).

---

## Notes
- This is not default-on exposure: early data is off by default (`tls13.c:40`).
- Once enabled, implementation should provide the RFC Section 8 minimum anti-replay guarantee, or the application must enforce an equivalent control.
