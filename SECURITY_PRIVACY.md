# Security, Privacy, and Incident Response

## 1) HTTPS Everywhere (SSL/TLS Enforcement)

- All traffic is redirected to HTTPS when `FORCE_HTTPS=true` (enabled by default in production).
- HTTP Strict Transport Security (HSTS) is enabled via `helmet` with:
  - `max-age=31536000`
  - `includeSubDomains`
  - `preload`
- Session cookies are marked `Secure` when HTTPS is enforced.

### Operational Notes

- In production, terminate TLS at a trusted reverse proxy/load balancer.
- Ensure `X-Forwarded-Proto=https` is passed to the app.
- Set `TRUST_PROXY=true` when running behind a reverse proxy. Keep it `false` when the app is directly internet-facing.
- Keep TLS certificates current and rotate before expiry.

### Startup Safety Checks

- The app validates critical env values on startup:
   - `MONGO_URI` is required.
   - `SESSION_SECRET` must be present and strong (minimum recommended length enforced).
- Payment destination values should be configured via environment variables:
   - `PAYMENT_UPI_NUMBER`
   - `PAYMENT_UPI_ID`
- A startup payment-config fingerprint is logged for audit tracking of destination changes (without exposing secret/internal values).
- In production, insecure/missing critical values fail fast to reduce silent misconfiguration risk.

---

## 2) Data Privacy and Minimal Collection

This application is configured to collect only data required for attendee onboarding and event participation:

- Name
- Email
- Phone number
- College/institution
- Selected technical and non-technical event
- Payment transaction reference (handled in privacy-preserving form)

### Privacy-by-Default Controls

- Input validation and sanitization are enforced on user-provided fields.
- CSRF protection is enabled for state-changing requests.
- Session and rate-limiting controls reduce abuse risk.
- Frontend third-party libraries are served locally from installed packages (`/vendor/...`) instead of remote CDNs to reduce supply-chain exposure.
- Explicit user consent is captured at sign-up and registration flows with consent version tracking.
- Temporary/uncompleted accounts are automatically removed by a retention cleanup job.
- Raw payment transaction IDs are **not retained** after registration finalization:
  - A SHA-256 hash is stored for duplicate detection.
  - Last 4 digits may be stored for limited support/audit handling.

### Retention & Deletion Controls

- `RETENTION_TEMP_USERS_DAYS` (default: 30) controls stale temporary-account deletion.
- Audit logs use TTL retention with `RETENTION_AUDIT_LOG_DAYS` (default: 180).
- Retention cleanup runs daily and on startup warm-up.

### Audit Logging & Monitoring

- Auth-related route access and outcomes are recorded with IP, user-agent, route, and metadata.
- Login/signup/register/logout actions are logged with success/failure outcomes.
- Auth abuse monitoring tracks failed attempts per IP over a rolling window.
- Security alerts are sent when abuse thresholds are reached (`AUTH_ABUSE_THRESHOLD`) or account lockouts occur.
- Configure `SECURITY_ALERT_TO` to receive security notifications.

### Compliance Guidance

To align with GDPR/DPDP/other privacy frameworks:

- Publish a user-facing privacy notice detailing purpose, retention, and rights.
- Define data retention windows and automatic deletion where feasible.
- Restrict database access with least privilege.
- Encrypt backups and store secrets in environment variables or secret managers.
- Keep auditable records of access and data changes.

---

## 3) Incident Response Plan

### Severity Levels

- **P1 Critical**: Confirmed data breach, active compromise, or mass account impact.
- **P2 High**: Suspicious activity with potential exposure.
- **P3 Medium/Low**: Localized issue, no confirmed exposure.

### Response Workflow

1. **Detect & Triage**
   - Validate alert/source (logs, user reports, monitoring).
   - Classify severity and assign incident owner.

2. **Contain**
   - Revoke compromised credentials/tokens.
   - Disable affected integrations/routes if needed.
   - Increase logging and preserve evidence.

3. **Eradicate & Recover**
   - Patch root cause.
   - Rotate secrets/keys.
   - Restore services and monitor for re-occurrence.

4. **Notification**
   - Notify internal stakeholders immediately.
   - Notify affected users without undue delay.
   - If legally required, notify regulators within mandated timelines (for many jurisdictions, up to 72 hours from breach confirmation).

5. **Post-Incident Review**
   - Produce timeline and impact summary.
   - Document lessons learned.
   - Track remediations with owners and due dates.

### Minimum Incident Record

- Incident ID and owner
- Detection time and confirmation time
- Systems/data affected
- User impact estimate
- Containment/recovery actions
- Notification timestamps
- Final root cause and prevention tasks

---

## 4) Immediate Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Set `FORCE_HTTPS=true`
- [ ] Set strong `SESSION_SECRET`
- [ ] Configure SMTP for security notifications
- [ ] Set `PAYMENT_UPI_NUMBER` and `PAYMENT_UPI_ID`
- [ ] Verify reverse proxy forwards `X-Forwarded-Proto`
- [ ] Review retention/deletion policy with legal/compliance team
