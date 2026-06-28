# MFA / 2FA Bypass Techniques — Study Guide

> **Purpose:** This is a learning reference for cybersecurity students on common logic flaws in Multi-Factor Authentication (MFA) implementations. These are _business logic_ and _implementation_ weaknesses — not cryptographic attacks on MFA itself. Real MFA standards (TOTP, WebAuthn, etc.) are sound; almost every bypass below exists because developers wired the _backend logic_ around MFA incorrectly. Only test these against systems you own or are explicitly authorized to test (lab VMs, CTFs, bug bounty programs with MFA in scope).

## Why MFA Bypasses Matter

MFA is meant to be a second independent barrier after the password. Most bypasses succeed not because the OTP/token itself is weak, but because **the application treats MFA verification as a separate, disconnected step** rather than a hard gate the session can't proceed past. A tester's job is to find every place where that gate can be skipped, tricked, or never properly closed.

The general workflow for testing all of these: intercept traffic with a proxy (Burp Suite / OWASP ZAP), walk through the login + 2FA flow once normally to map every request, then go back and tamper with each request individually while watching how the server reacts.

---

## 1. Response Manipulation

**The flaw:** Some single-page apps make the _backend_ do the real verification, but let the _frontend_ decide whether to redirect the user based on a flag in the JSON response (e.g. `{"success": false}`).

**How it's tested:** Intercept the verify-OTP response in your proxy before it reaches the browser, and flip the relevant field (`false` → `true`, or an error code → success code). If the client-side JS trusts that field to decide "let the user in," you've bypassed the check entirely — without ever knowing the correct code.

**Root cause:** Authorization decision is made (or trusted) client-side instead of being enforced server-side via session state.

**Fix:** The server must independently mark the session as "MFA-verified" only after correct validation, and every protected endpoint must check that session flag server-side — never trust a response body field as the source of truth.

---

## 2. Status Code Manipulation

**The flaw:** Some backends reject an invalid OTP with a 4xx status but the actual session-state change (or redirect logic) is keyed off the _HTTP status code_ somewhere in a proxy, gateway, or even buggy frontend logic, rather than the body content.

**How it's tested:** Submit a wrong/blank code, intercept the response, and rewrite the status line from e.g. `401 Unauthorized` to `200 OK`, leaving the body untouched. See if the app proceeds as if you'd passed.

**Root cause:** Same as above — trusting transport-layer metadata instead of a verified server-side session state.

**Fix:** Session/auth state must be the single source of truth, validated independently on every request, regardless of what status code or body the client claims to have seen.

---

## 3. 2FA Code Leakage in Response

**The flaw:** The endpoint that _triggers_ sending an OTP (by SMS/email) sometimes echoes the code back in its own JSON/HTML response — often left over from debugging.

**How it's tested:** Trigger the "send code" action, then carefully inspect the _entire_ response body (not just the part the UI displays) for any field containing the code, a hash that decodes to it, or a debug parameter.

**Root cause:** Debug/test code paths left in production, or a poorly designed API that returns more than the client needs.

**Fix:** The verification code should never be present in any server response after being generated — only delivered via the out-of-band channel (SMS/email/push).

---

## 4. JS File Analysis

**The flaw:** Client-side JavaScript bundles occasionally contain hardcoded test/bypass logic, debug OTPs, or comments left in by developers (e.g. `if (otp === "DEV_BYPASS")`).

**How it's tested:** Pull all JS files loaded during the auth flow and search them (manually or with tools like LinkFinder, JSParser, or just browser dev tools + grep) for keywords like `otp`, `2fa`, `bypass`, `debug`, `test`.

**Root cause:** Sensitive logic or secrets shipped to a place attackers fully control (the client).

**Fix:** Never embed verification logic, secrets, or bypass conditions in client-side code. All of it belongs server-side.

---

## 5. 2FA Code Reusability

**The flaw:** A code that was already used successfully once is still accepted on a second attempt (codes aren't invalidated after use).

**How it's tested:** Complete a normal login with a valid OTP, then try replaying that exact same code on a fresh login attempt (possibly from a new session/IP).

**Root cause:** The backend checks "is this code correct" but never checks "has this code already been consumed."

**Fix:** Invalidate a code the instant it's used successfully (and also after expiry/a max attempt count), tracked server-side per-code, not per-session.

---

## 6. Lack of Brute-Force Protection

**The flaw:** A 6-digit numeric OTP has only 1,000,000 possible values. Without rate limiting, that's trivially brute-forceable in minutes with automated requests.

**How it's tested:** Send the OTP-verification request to an intruder/fuzzer tool (Burp Intruder, ffuf) and iterate through the possible code space, watching for a different response (length, status, timing) indicating success.

**Root cause:** No rate limiting, no account lockout, no CAPTCHA, no exponential backoff on the verification endpoint.

**Fix:** Lock the account or require a cooldown after a small number of failed attempts (e.g. 5), use longer/alphanumeric codes, and add server-side throttling independent of the client.

---

## 7. Missing 2FA Code Integrity Validation

**The flaw:** The backend checks "is the submitted code valid for _some_ user" instead of "is it valid for _this specific_ authenticated user/session."

**How it's tested:** Trigger an OTP for your own account, then submit _that_ code while the request is scoped (via a manipulated user ID, email, or session token parameter) to a different victim account.

**Root cause:** The verification query isn't strictly bound to the user ID tied to the original OTP-generation request.

**Fix:** Bind every generated code to the specific user/session that requested it server-side, and validate that binding — not just the code's correctness — on every verification attempt.

---

## 8. CSRF on 2FA Disabling

**The flaw:** The "disable 2FA" endpoint doesn't use a CSRF token and doesn't ask the user to re-confirm their password/current OTP, so it can be triggered by a forged cross-site request.

**How it's tested:** Capture the disable-2FA request, build an auto-submitting HTML form/fetch call on an attacker-controlled page, and check whether a logged-in victim visiting that page has their 2FA silently disabled.

**Root cause:** Sensitive state-changing actions lack CSRF protection and lack "step-up" re-authentication.

**Fix:** Require a fresh CSRF token _and_ a re-auth step (current password or OTP) before disabling MFA — treat it as a sensitive action, not a routine settings toggle.

---

## 9. Password Reset Disables 2FA

**The flaw:** Going through the "forgot password" flow silently turns off 2FA on the account as a side effect, even though the reset flow itself doesn't require knowing the second factor.

**How it's tested:** Trigger a password reset on a target account (e.g. via email-based reset) and check, after resetting, whether 2FA is still enabled.

**Root cause:** Password reset and 2FA state are not properly isolated; a flow designed to recover _one_ factor ends up undermining the _other_.

**Fix:** Password resets should never change 2FA enrollment status. If account recovery genuinely needs to bypass 2FA, that should be its own carefully audited, logged, and rate-limited process — not an automatic side effect.

---

## 10. Backup Code Abuse

**The flaw:** Backup/recovery codes (meant for "I lost my phone" scenarios) are often protected by weaker logic than the main 2FA flow — no rate limiting, predictable generation, or reusable after use.

**How it's tested:** Apply the same techniques from sections 1–9 (brute-force, reusability, response manipulation, lack of binding to the user) specifically against the backup-code entry point, since teams often forget to apply the same hardening there.

**Root cause:** Security controls applied inconsistently across "primary" vs. "fallback" code paths that ultimately grant the same level of access.

**Fix:** Backup codes need the exact same protections as the primary OTP flow: single-use, rate-limited, properly bound to the account, and ideally a smaller, time-limited set that's reissued (invalidating the old set) whenever used.

---

## 11. Clickjacking on 2FA Disabling Page

**The flaw:** The page where a user disables 2FA can be loaded inside an invisible/transparent `<iframe>` on an attacker's site, with the disable button positioned under something the victim is tricked into clicking (e.g. a fake "claim your prize" button).

**How it's tested:** Try loading the 2FA-disable page in an iframe from a different origin. If it loads (no `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header blocking it), build a proof-of-concept page overlaying a decoy button on top of the real disable button's coordinates.

**Root cause:** Missing frame-busting headers on sensitive pages.

**Fix:** Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and a `Content-Security-Policy: frame-ancestors 'none'` on every sensitive settings page.

---

## 12. Enabling 2FA Doesn't Expire Previously Active Sessions

**The flaw:** If an attacker already hijacked a session (via a stolen cookie, XSS, etc.) _before_ the victim turns on 2FA, that old hijacked session often remains valid afterward — 2FA only gets enforced on _new_ logins.

**How it's tested:** Establish two concurrent sessions for the same account (simulating "attacker" and "victim" sessions) before 2FA is enabled, then enable 2FA from one session and check whether the other session is still active and usable.

**Root cause:** Enabling a new security control doesn't retroactively invalidate sessions established before that control existed.

**Fix:** Enabling 2FA (or any major security setting) should invalidate all other active sessions and force re-authentication everywhere.

---

## 13. Bypass 2FA by Force Browsing

**The flaw:** After password login, the app redirects to an intermediate `/2fa/verify` page, but the actual protected destination (e.g. `/my-account` or a dashboard API) doesn't separately check whether MFA was completed — it only checks "is there a valid session," which already exists from step one.

**How it's tested:** Log in with the password, and the moment you land on `/2fa/verify`, manually navigate directly to the post-login URL (`/my-account`, `/dashboard`, or call its API endpoint directly) instead of submitting the code.

**Root cause:** Session creation and MFA verification are two separate flags, but only the first one is actually checked by protected resources.

**Fix:** Protected endpoints/middleware must check a distinct `mfa_verified` flag on the session — a logged-in-but-not-yet-2FA-verified session should be treated as effectively unauthenticated for everything except the verify endpoint itself.

---

## 14. Bypass 2FA with `null` or `000000`

**The flaw:** Developers sometimes leave a literal backdoor/default value in the verification logic — submitting `null`, an empty string, or the default seed value `000000` is silently accepted regardless of the real generated code.

**How it's tested:** Simply submit those values at the OTP-verification step and observe the response — this is one of the first low-effort checks worth trying on any custom MFA implementation.

**Root cause:** Leftover debug/default values, or a comparison function that has a falsy/empty-string edge case treated as "skip check."

**Fix:** Explicitly reject empty, null, or default-looking values before doing any comparison, and code-review verification logic for default/fallback branches.

---

## 15. Bypass 2FA with Array Input

**The flaw:** Some backends (commonly in loosely-typed languages/frameworks) compare the submitted OTP using a loose equality check across a list. If the parameter is submitted as an _array_ of guesses instead of a single string, a poorly written comparison (e.g. iterating with `in` or a loose `==` against each array element) may return "match" if _any_ element happens to be correct — letting an attacker submit a batch of guesses in one request.

**How it's tested:** Instead of sending `{"otp": "1234"}`, send `{"otp": ["0000","1111","1234","9999", ...]}` and see whether the backend treats it as valid if any single value in that array happens to match.

**Root cause:** Type confusion — the backend code assumes `otp` will always be a scalar string and doesn't validate the input type before comparison.

**Fix:** Strictly validate input types server-side (reject anything that isn't a single string/number of the expected length) before any comparison logic runs.

---

## Defense Checklist (Summary for Developers)

- [ ] All MFA verification state lives server-side, bound to session + user ID — never trust client-reported success/status codes
- [ ] Codes are single-use, expire quickly, and are invalidated immediately after a successful (or excessive failed) attempt
- [ ] Rate limiting / lockout / CAPTCHA on every code-verification endpoint, including backup codes
- [ ] Verification codes never appear in any API response or client-side JS
- [ ] Sensitive actions (disabling MFA, password reset) require CSRF tokens + re-authentication, and never silently disable MFA as a side effect
- [ ] Enabling/disabling MFA invalidates all other active sessions
- [ ] Every protected route checks an explicit `mfa_verified` session flag — not just "is logged in"
- [ ] Strict server-side input type validation (reject arrays/objects where a scalar is expected)
- [ ] Frame-busting headers (`X-Frame-Options`, `CSP frame-ancestors`) on all account-security pages

## Ethical / Legal Note

Every technique above should only be exercised against systems you own or have explicit written authorization to test (CTF environments, your own lab setup, or a bug bounty program where MFA is in scope). Testing these against real production systems without authorization is illegal in most jurisdictions regardless of intent.
