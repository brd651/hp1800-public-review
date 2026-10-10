# Security policy

## Reporting

Please do not publish credentials, session cookies, captured HTTP traffic, or
switch configuration files in an issue. Send a private report to the
maintainer of the repository where this project is published. Include the
affected version, impact, and a minimal sanitized reproduction.

## Operational security

The supported switch interface uses HTTP. Operate on a trusted, isolated
management network. Do not reuse switch passwords, prefer the interactive
password prompt or `HP1800_PASSWORD`, and keep snapshots and support reports
private. This client does not implement automatic rollback or binary restore.
