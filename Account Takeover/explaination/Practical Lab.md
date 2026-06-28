# Practical Lab Guide: Testing MFA Bypasses Hands-On

> Goal: actually _do_ the techniques from the theory guide, against systems you legally control. No live targets, no production sites you don't own.

---

## Part 1 — Where to Practice (Legal, Free)

You need a target that actually _has_ MFA implemented (most "beginner" vulnerable apps like DVWA/Juice Shop don't). Pick one or more:

### Option A — PortSwigger Web Security Academy (best starting point)

Free, browser-based, intentionally-vulnerable live labs — no setup required, fully legal to attack.

- Go to `portswigger.net/web-security` → **Authentication** topic
- Look for labs literally named things like _"2FA simple bypass," "2FA broken logic," "2FA bypass using a brute-force attack," "Brute-forcing a stay-logged-in cookie"_
- Each lab gives you a live broken app + Burp Suite Community built into their cloud browser, and tells you when you've solved it
- This maps almost 1:1 to the techniques in the previous guide — do these first

### Option B — Build your own tiny app (deepest learning)

Write a ~100-line Flask or Node app yourself with login + a basic OTP step (e.g. `pyotp` for Python, `otplib` for Node). Deliberately implement it badly at first (e.g. compare OTP with loose `==`, don't invalidate after use), attack your own bugs, then fix them and try to attack the fixed version. This is the single best way to internalize _why_ each fix matters, because you wrote both the bug and the patch.

### Option C — Self-hosted vulnerable VMs

- **OWASP Juice Shop** (`docker run -p 3000:3000 bkimminich/juice-shop`) — great for the _other_ categories (XSS, SQLi, IDOR) even though it's light on MFA
- **TryHackMe / HackTheBox** "Authentication Bypass" rooms — legal, sandboxed VMs

**Rule for all of the above:** only attack what's in front of you in the lab/your own deployed app. Never point these techniques at someone else's live site, even "just to check."

---

## Part 2 — Tools You'll Actually Use

| Tool                                             | Purpose                                            | Setup                                                                                                                  |
| ------------------------------------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Burp Suite Community** (free)                  | Intercept/modify HTTP requests & responses         | Download from portswigger.net, set browser proxy to `127.0.0.1:8080`, install Burp's CA cert in your browser for HTTPS |
| **Browser DevTools**                             | Quick inspection, JS file review                   | Built into Chrome/Firefox, `F12`                                                                                       |
| **ffuf** or **Burp Intruder**                    | Automated brute-forcing of OTP values              | `ffuf` is CLI and free; Intruder is built into Burp                                                                    |
| **A second browser profile / incognito session** | Simulate "two sessions" tests (e.g. technique #12) | Just open a second browser or private window                                                                           |

**One-time setup checklist:**

1. Install Burp Suite Community
2. Launch it → open the built-in Chromium browser (it auto-configures the proxy), or manually set your own browser's proxy to Burp
3. Visit `http://burp` in that browser and install the CA certificate so HTTPS sites don't error
4. Confirm traffic shows up in Burp's **Proxy → HTTP history** tab — if you see requests there, you're ready

---

## Part 3 — General Workflow for Any Test

This is the loop you repeat for every technique below:

1. **Map the flow first.** Log in normally once, with Burp's proxy intercept _off_ but history recording _on_. Walk through password entry → OTP entry → landing on the dashboard. Look at Proxy → HTTP history afterward and identify every request involved.
2. **Pick one request to attack.** Right-click it in history → **Send to Repeater**.
3. **Modify and resend** in Repeater — this lets you tweak one field at a time and immediately see the raw response, without going through the UI each time.
4. **Compare against the original baseline.** Always know what a _correct_ login looks like first, so you can spot what's different when something works that shouldn't.

---

## Part 4 — Hands-On Steps Per Technique

### 1 & 2 — Response / Status Code Manipulation

In Burp, turn on **Proxy intercept** before submitting a wrong OTP. When the _response_ (not request) is intercepted, click it open, edit `"success": false` → `true` or the status line `403 Forbidden` → `200 OK`, then forward it. Watch if the frontend lets you through.

### 3 — Code Leakage in Response

Send the "trigger OTP" request to Repeater. Look at the full raw response (not the rendered page) — search for any 4-6 digit number, or a base64 string, anywhere in the JSON/HTML.

### 4 — JS File Analysis

In DevTools → **Sources** tab, open every `.js` file loaded on the login/2FA page. Use `Ctrl+F` (search across all files in Chrome DevTools) for `otp`, `bypass`, `debug`, `2fa`.

### 5 — Code Reusability

Complete one full login with a real OTP. Log out. Try logging in again and reuse the _same_ OTP value at the verify step (do this quickly, before it naturally expires).

### 6 — Brute-Force

Send the OTP-verify request to **Burp Intruder**. Highlight the OTP parameter value, set it as the payload position (`§000000§`), choose **Numbers** payload type, range `000000`–`999999`. Run it, then sort results by **response length** or **status code** — the correct one usually stands out.

### 7 — Missing Integrity Validation (cross-account)

Open two accounts (Account A = "you", Account B = "victim test account you also own"). Trigger an OTP for Account A. In Repeater, take that verify request and swap any user-identifying parameter (user ID, email, session cookie) to point at Account B, keeping Account A's OTP. See if it's accepted.

### 8 — CSRF on Disable-2FA

Send the disable-2FA request to Repeater, check the request for a CSRF token. If there's none, build a minimal HTML file: `<form action="https://target/disable2fa" method="POST"><input type="hidden" name="..." value="..."></form><script>document.forms[0].submit()</script>`. Open this file in a browser where you're already logged into your _own_ test account and see if it fires.

### 9 — Password Reset Disabling 2FA

On your test account, go through "forgot password," set a new password, then check your account settings page — is 2FA still showing as enabled?

### 10 — Backup Code Abuse

Generate backup codes on your test account, then re-run techniques #5 and #6 (reusability, brute-force) specifically against the backup-code entry field instead of the normal OTP field.

### 11 — Clickjacking

Build a basic HTML file: `<iframe src="https://your-test-site/disable-2fa" style="opacity:0.1;position:absolute;top:0;left:0;"></iframe><button style="position:absolute;top:120px;left:50px;">Click for a prize</button>`. Adjust the iframe position until the real disable button lines up under your decoy button, then open the file while logged in.

### 12 — Sessions Surviving 2FA Enable

Log into your test account from two browsers (or one normal + one incognito). From browser A, enable 2FA. Go to browser B and try performing an action — is it still logged in without being asked for 2FA?

### 13 — Force Browsing

At the `/2fa/verify` step, before entering any code, manually type the post-login URL (e.g. `/dashboard` or `/account`) directly into the address bar, or replay the dashboard's API request in Repeater using your current cookies.

### 14 — `null` / `000000`

At the OTP field, just try submitting `000000`, an empty string, or literal `null` as the value and see what comes back.

### 15 — Array Input

In Repeater, change the request body from `{"otp":"123456"}` to `{"otp":["000000","111111","123456"]}` (match Content-Type to JSON if needed) and see whether the backend accepts it when any array element is a real, valid code.

---

## Part 5 — After Each Test: Close the Loop

For every technique that _works_ against your own app:

1. Write down exactly what request/response made it succeed (this is literally how you'd write up a bug bounty report or pentest finding)
2. Go implement the fix from the "Defense Checklist" in the theory guide
3. Re-run the same test and confirm it now fails

That loop — break it, understand why, fix it, confirm the fix — is the actual skill. Anyone can run a tool; knowing why the bug existed and what closed it is what separates a tester from someone running a tool.

---

## Legal Reminder

Everything above assumes the target is: your own deployed app, a VM/container you run locally, or a platform explicitly built for this (PortSwigger Academy, TryHackMe, HTB). The moment a target isn't one of those three, stop — testing real third-party systems without written authorization is a computer crime in essentially every country, regardless of intent.
