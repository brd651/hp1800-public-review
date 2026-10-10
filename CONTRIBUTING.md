# Contributing

This project targets observed behavior of the J9028B with PB.03.10. Changes
that affect HTTP workflows should include sanitized fixtures or mocked
responses; do not include credentials, cookies, session tokens, public IPs, or
unreviewed switch exports in commits.

Do not test write operations against production switches. Hardware validation
must use a lab switch with independent recovery access, and should record the
model and firmware. Unit tests should mock all HTTP traffic and must not
require hardware.

Before submitting a change, describe its impact on read-only and mutating
commands, its verification evidence, and any hardware assumptions. Automatic
rollback and binary configuration restore are not currently supported.
