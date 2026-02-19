# Changelog

All notable changes to this project are documented here.

---

## [Security Hardening] – 2026-02-19

### Summary
Four security issues were identified and fixed in the symposium registration application.

---

### 1. Removed Committed Credentials from Version Control

**File:** `.env` (deleted from git tracking)

The `.env` file, which contained a live **MongoDB Atlas connection string with embedded credentials**
and a **weak session secret**, was being tracked by git and was visible in the repository history.

**Fix:**
- Ran `git rm --cached .env` to stop tracking the file without deleting it locally.
- Replaced all real values inside `.env` with safe placeholder strings so the file can still be
  used locally but no longer holds any secret.
- **⚠️ Action required:** The MongoDB Atlas password that was previously committed must be
  **rotated immediately** via MongoDB Atlas → Database Access → Edit User.

---

### 2. Added `.gitignore`

**File:** `.gitignore` *(new)*

No `.gitignore` existed, meaning secrets, dependencies, and OS artefacts could be accidentally
committed at any time.

**Fix:** Created `.gitignore` with the following rules:

| Pattern | Reason |
|---|---|
| `.env` | Prevents future accidental commits of secrets |
| `node_modules/` | Excludes the dependency folder (regenerated via `npm install`) |
| `*.log` / `npm-debug.log*` | Excludes runtime log files |
| `.DS_Store` | Excludes macOS artefacts |

---

### 3. Added `.env.example` Template

**File:** `.env.example` *(new)*

Without a reference file, developers had no way to know which environment variables the
application requires, which can lead to misconfiguration.

**Fix:** Created `.env.example` listing every required and optional variable with placeholder
values and inline comments:

```
MONGO_URI=your_mongodb_connection_string_here
SESSION_SECRET=replace_with_a_long_random_secret_at_least_32_chars
PORT=3000

# Email (optional – OTP prints to console if not configured)
# SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS, SMTP_FROM

# NODE_ENV=production
```

---

### 4. Fixed OTP / Recovery Code Generation to Use a CSPRNG

**File:** `index.js` – `generateNumericCode()` function (line 240)

OTP codes and account-recovery codes were generated using `Math.random()`, which is **not
cryptographically secure**. An attacker who can observe timing or seed information could
predict generated codes.

**Fix:** Replaced `Math.random()` with `crypto.randomInt()`, which uses the operating system's
Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).

```js
// Before (insecure)
return String(Math.floor(min + Math.random() * (max - min + 1)));

// After (cryptographically secure)
return String(crypto.randomInt(min, max + 1));
```

`crypto` was already imported in the file, so no new dependency was required.

---

### Files Changed

| File | Change type | Description |
|---|---|---|
| `.env` | Modified + removed from git | Credentials replaced with placeholders; removed from tracking |
| `.gitignore` | Added | Prevents `.env`, `node_modules/`, logs from being committed |
| `.env.example` | Added | Safe template for required environment variables |
| `index.js` | Modified | `Math.random()` → `crypto.randomInt()` in `generateNumericCode()` |
