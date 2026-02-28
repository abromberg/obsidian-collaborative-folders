# Security Test Matrix

## AuthN/AuthZ

- Missing bearer token on protected route returns `401`.
- Token with wrong folder scope returns `403`.
- Token for removed member returns `403`.
- Token with old `tokenVersion` returns `401`.
- Revoked `jti` token returns `401`.
- Editor trying owner-only route returns `403`.

## Invite Lifecycle

- Owner can create invite for existing folder.
- Non-owner cannot create invite for existing folder.
- Bootstrap create invite works for first share with `ownerClientId`.
- Invite with `max_uses=1` cannot be redeemed twice.
- Invite with past `expires_at` cannot be redeemed.
- Revoked invite cannot be redeemed.
- Owner can revoke invite by token hash.

## Token Lifecycle

- `/api/auth/refresh` rotates refresh token and returns new access token.
- Reusing a rotated refresh token revokes family and returns `401`.
- Refresh token for removed member fails and family revoked.
- Refresh token with mismatched token version fails.

## WebSocket Revocation

- Valid member can connect and sync.
- Removed member loses active WS session within one operation cycle.
- Removed member cannot continue sending updates after removal.
- Revoked access token `jti` cannot continue WS updates.

## Blob Integrity / Abuse

- Upload with valid hash succeeds (`201`) or dedups (`409`).
- Upload with mismatched hash returns `400`.
- Upload over max size returns `413` with retry guidance.
- Excess upload throughput returns `429` with `Retry-After`.
- Download rate-limit violation returns `429`.

## Observability

- Invite create/redeem/revoke creates `audit_events`.
- Member removal creates `audit_events`.
- Refresh rotation/replay creates `audit_events`.
- Auth denial and rate-limit events are represented in:
  - `audit_events`
  - `/health/security` counters
