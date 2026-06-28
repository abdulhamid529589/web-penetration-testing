# 🔐 Brute Force & Rate Limit Bypass — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/Brute Force Rate Limit](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Brute%20Force%20Rate%20Limit)
> **Audience:** Cybersecurity students, ethical hackers, CTF players
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো। Unauthorized use illegal।

---

## 📚 Table of Contents

1. [Concept Overview — Brute Force কী?](#1-concept-overview--brute-force-কী)
2. [Tools Overview](#2-tools-overview)
3. [Burp Suite Intruder — 4 Attack Types](#3-burp-suite-intruder--4-attack-types)
   - [Sniper Attack](#31-sniper-attack)
   - [Battering Ram Attack](#32-battering-ram-attack)
   - [Pitchfork Attack](#33-pitchfork-attack)
   - [Cluster Bomb Attack](#34-cluster-bomb-attack)
4. [FFUF — Fast Web Fuzzer](#4-ffuf--fast-web-fuzzer)
5. [Rate Limit — কী এবং কেন?](#5-rate-limit--কী-এবং-কেন)
6. [Rate Limit Bypass Techniques](#6-rate-limit-bypass-techniques)
   - [HTTP Pipelining](#61-http-pipelining)
   - [TLS Fingerprint (JA3) Bypass](#62-tls-fingerprint-ja3-bypass)
   - [IPv4 Proxy Rotation](#63-ipv4-proxy-rotation)
   - [IPv6 Mass Rotation](#64-ipv6-mass-rotation)
7. [Practical Lab — DVWA Setup](#7-practical-lab--dvwa-setup)
8. [Defense Cheat Sheet](#8-defense-cheat-sheet)
9. [Attack Decision Tree](#9-attack-decision-tree)
10. [References](#10-references)

---

## 1. Concept Overview — Brute Force কী?

**Brute Force** মানে হলো systematically সব possible combination try করা যতক্ষণ না সঠিক answer পাওয়া যায়।

Web application এর context এ এটা হয়:

- Login form এ username/password guess করা
- OTP বা security token iterate করা (0000 থেকে 9999 পর্যন্ত)
- API key বা session token discover করা

```
Attack Flow:
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Attacker                Target Server              │
│    │                          │                     │
│    │── POST /login ──────────>│                     │
│    │   user=admin             │                     │
│    │   pass=password1         │                     │
│    │<── 401 Unauthorized ─────│                     │
│    │                          │                     │
│    │── POST /login ──────────>│                     │
│    │   user=admin             │                     │
│    │   pass=password2         │                     │
│    │<── 401 Unauthorized ─────│                     │
│    │                          │                     │
│    │── POST /login ──────────>│                     │
│    │   user=admin             │                     │
│    │   pass=letmein  ✅       │                     │
│    │<── 200 OK ───────────────│                     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Brute Force এর প্রকারভেদ

| Type                    | বাংলায় ব্যাখ্যা              | Example                 |
| ----------------------- | ----------------------------- | ----------------------- |
| **Simple Brute Force**  | সব combination try করা        | aaaa → aaab → aaac      |
| **Dictionary Attack**   | wordlist ব্যবহার করা          | rockyou.txt             |
| **Credential Stuffing** | leaked username:password pair | HaveIBeenPwned data     |
| **Password Spraying**   | একটা password, অনেক username  | `Summer2024!` → সব user |
| **Reverse Brute Force** | একটা password, অনেক username  | Same as above           |

---

## 2. Tools Overview

| Tool                 | কী কাজ করে                             | কখন ব্যবহার করবে                     |
| -------------------- | -------------------------------------- | ------------------------------------ |
| **Burp Suite**       | HTTP intercept, replay, intruder       | Web app login brute force            |
| **FFUF**             | Fast fuzzing tool (Go language)        | Directory/file/param fuzzing + brute |
| **OmniProx**         | Multi-cloud IP rotation (GCP/Azure/CF) | Rate limit bypass via IP change      |
| **curl-impersonate** | Chrome/Firefox এর মতো TLS handshake    | JA3 fingerprint bypass               |
| **proxychains**      | Multiple proxy দিয়ে request route করা | IPv4 rotation                        |

---

## 3. Burp Suite Intruder — 4 Attack Types

Burp Suite Intruder এ ৪ ধরনের attack আছে। এগুলো বুঝতে হলে **position** (§ mark করা জায়গা) এবং **payload** (list of values) এই দুটো concept মাথায় রাখতে হবে।

### 3.1 Sniper Attack

**একটা position, একটা payload list।**

> একটা বন্দুক দিয়ে একটা target এ একটা একটা করে গুলি।

```
Request Template:
POST /login
username=admin&password=§PASS§

Payload List (passwords.txt):
- password1
- password2
- 123456
- letmein

Result:
Request 1: username=admin&password=password1
Request 2: username=admin&password=password2
Request 3: username=admin&password=123456
Request 4: username=admin&password=letmein
```

**Use case:** একটা known username এর password জানা নেই। শুধু password field fuzz করছি।

---

### 3.2 Battering Ram Attack

**একাধিক position, কিন্তু সব position এ একই payload।**

> একটা battering ram দিয়ে একসাথে সব দরজায় ধাক্কা।

```
Request Template:
POST /login
username=§VALUE§&password=§VALUE§

Payload List:
- admin
- root
- user1

Result:
Request 1: username=admin    & password=admin
Request 2: username=root     & password=root
Request 3: username=user1    & password=user1
```

**Use case:** কোনো system যেখানে username = password হওয়ার সম্ভাবনা আছে (weak systems)।

---

### 3.3 Pitchfork Attack

**একাধিক position, আলাদা আলাদা payload list, কিন্তু parallel চলে।**

> দুটো pitchfork একসাথে কিন্তু আলাদাভাবে কাজ করছে। List 1 এর 1st item → List 2 এর 1st item।

```
Position 1 (usernames.txt):   Position 2 (passwords.txt):
- alice                        - alice_pass
- bob                          - bob_pass
- charlie                      - charlie_pass

Result:
Request 1: username=alice    & password=alice_pass
Request 2: username=bob      & password=bob_pass
Request 3: username=charlie  & password=charlie_pass
```

**Use case:** তোমার কাছে leaked username:password pair আছে (credential stuffing)।

⚠️ **Note:** দুটো list এর length same হতে হবে। যেটা ছোট সেটা শেষ হলে attack বন্ধ হয়।

---

### 3.4 Cluster Bomb Attack

**একাধিক position, আলাদা payload list, সব combination try করে।**

> সব username × সব password = cartesian product।

```
Position 1 (usernames.txt): [admin, root]
Position 2 (passwords.txt): [pass1, pass2, pass3]

Result (2 × 3 = 6 requests):
Request 1: username=admin & password=pass1
Request 2: username=admin & password=pass2
Request 3: username=admin & password=pass3
Request 4: username=root  & password=pass1
Request 5: username=root  & password=pass2
Request 6: username=root  & password=pass3
```

**Use case:** Username ও Password দুটোই unknown। সব combination test করতে চাই।

⚠️ **Warning:** 1000 username × 1000 password = **1,000,000 requests**! Slow এবং noisy।

---

### Attack Type Comparison Table

```
┌───────────────┬───────────┬──────────────┬────────────────────────┐
│ Attack Type   │ Positions │ Payload Sets │ Total Requests         │
├───────────────┼───────────┼──────────────┼────────────────────────┤
│ Sniper        │ 1         │ 1            │ = payload count        │
│ Battering Ram │ Multiple  │ 1            │ = payload count        │
│ Pitchfork     │ Multiple  │ Multiple     │ = shortest list length │
│ Cluster Bomb  │ Multiple  │ Multiple     │ = product of all lists │
└───────────────┴───────────┴──────────────┴────────────────────────┘
```

---

## 4. FFUF — Fast Web Fuzzer

FFUF (Fuzz Faster U Fool) হলো Go দিয়ে লেখা একটা fast fuzzing tool। Burp এর চেয়ে অনেক দ্রুত।

### Basic Syntax

```bash
ffuf -w <wordlist>:<KEYWORD> -u <URL> [options]
```

### Login Brute Force (Pitchfork style)

```bash
ffuf -w usernames.txt:USER \
     -w passwords.txt:PASS \
     -u https://target.tld/login \
     -X POST \
     -d "username=USER&password=PASS" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -mc 200,302
```

### Flag Breakdown

| Flag                      | মানে                                         |
| ------------------------- | -------------------------------------------- |
| `-w wordlist.txt:KEYWORD` | wordlist load করো, KEYWORD দিয়ে replace হবে |
| `-u`                      | Target URL                                   |
| `-X POST`                 | HTTP method                                  |
| `-d`                      | POST body data                               |
| `-H`                      | Extra header                                 |
| `-mc`                     | Match করো শুধু এই status code গুলো           |
| `-fc`                     | Filter করো (এই status code বাদ দাও)          |
| `-fs`                     | Filter by response size                      |
| `-t`                      | Threads (default 40)                         |

### Rate Limit Bypass with X-Forwarded-For Header

```bash
# IP address list দিয়ে X-Forwarded-For header rotate করো
ffuf -w usernames.txt:USER \
     -w passwords.txt:PASS \
     -w ipv4-list.txt:IP \
     -u https://target.tld/login \
     -X POST \
     -d "username=USER&password=PASS" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "X-Forwarded-For: IP" \
     -mc all \
     -fc 429
```

> ⚠️ এটা শুধু তখনই কাজ করে যখন server `X-Forwarded-For` header কে trust করে rate limiting এর জন্য।

### Useful FFUF Wordlists

```bash
# SecLists থেকে common passwords
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Common usernames
/usr/share/seclists/Usernames/Names/names.txt

# rockyou.txt
/usr/share/wordlists/rockyou.txt
```

---

## 5. Rate Limit — কী এবং কেন?

**Rate Limit** হলো server এর একটা protection mechanism যেটা নির্দিষ্ট সময়ে নির্দিষ্ট সংখ্যার বেশি request block করে।

```
Normal User:
  IP: 1.2.3.4 → 5 requests/min → ✅ OK

Attacker:
  IP: 1.2.3.4 → 500 requests/min → ❌ 429 Too Many Requests
```

### Rate Limit সাধারণত যেভাবে কাজ করে

```
Server checks:
  1. IP address → per-IP counter
  2. User-Agent → browser fingerprint
  3. TLS fingerprint (JA3) → client fingerprint
  4. Session/Cookie → per-session counter
  5. Account ID → per-account lockout
```

**Attacker এর goal:** এই সব identifier কে bypass করা।

---

## 6. Rate Limit Bypass Techniques

### 6.1 HTTP Pipelining

HTTP/1.1 এ একটা connection এ multiple request পাঠানো যায় response এর জন্য wait না করেই।

```
Normal (HTTP/1.0 style):
  Client: Request 1 → Server
  Client: (wait)
  Server: Response 1 → Client
  Client: Request 2 → Server
  ...

Pipelining (HTTP/1.1):
  Client: Request 1 ─┐
  Client: Request 2  ├─> Server (একসাথে)
  Client: Request 3 ─┘
  Server: Response 1, 2, 3 → Client
```

**কেন কাজ করে?** Rate limiter অনেক সময় TCP connection count দেখে, request count না। Pipelining এ multiple requests একটা connection এ যায়।

---

### 6.2 TLS Fingerprint (JA3) Bypass

#### JA3 কী?

যখন তুমি HTTPS connection করো, browser/client একটা **TLS Client Hello** packet পাঠায়। এই packet এ থাকে:

- SSL/TLS Version
- Cipher Suites (encryption algorithms)
- Extensions list
- Elliptic Curves
- Elliptic Curve Point Formats

JA3 এই সব values কে MD5 hash করে একটা **fingerprint** বানায়।

```
TLS Client Hello:
┌────────────────────────────────────────────┐
│ SSL Version: 771 (TLS 1.2)                │
│ Ciphers: 49195-49199-49196-49200-52393... │
│ Extensions: 0-23-65281-10-11-35-16-5...  │
│ Elliptic Curves: 29-23-24                 │
│ EC Point Formats: 0                       │
└────────────────────────────────────────────┘
           ↓ MD5 Hash
   JA3: 53d67b2a806147a7d1d5df74b54dd049
```

#### Known JA3 Fingerprints

| Tool             | JA3 Hash                           |
| ---------------- | ---------------------------------- |
| Burp Suite       | `53d67b2a806147a7d1d5df74b54dd049` |
| Burp Suite (alt) | `62f6a6727fda5a1104d5b147cd82e520` |
| Tor Browser      | `e7d705a3286e19ea42f587b344ee6865` |
| Chrome (typical) | `aaa..` (varies by version)        |

**Problem:** Server যদি Burp Suite এর JA3 detect করে, সে automatically block করতে পারে — এমনকি User-Agent বদলালেও!

#### Bypass Methods

```bash
# Method 1: curl-impersonate (Chrome এর মতো TLS handshake করে)
curl_chrome110 https://target.tld/login \
  -X POST \
  -d "username=admin&password=test"

# Method 2: Playwright/Puppeteer (real browser automation)
# Real browser use করো, তাহলে real browser JA3 যাবে

# Method 3: JA3 randomization
# কিছু library আছে যেটা প্রতি request এ different JA3 generate করে
```

---

### 6.3 IPv4 Proxy Rotation

Server যদি IP দিয়ে rate limit করে, তাহলে প্রতি request এ IP বদলাও।

#### proxychains দিয়ে

```bash
# /etc/proxychains4.conf কনফিগ করো:
[ProxyList]
# type    host              port
socks5    127.0.0.1         1080    # Tor
socks5    192.168.1.50      1080    # Local proxy
http      proxy1.example.com  8080
http      proxy2.example.com  8080
```

```bash
# proxychains এ random_chain mode চালু করো
# proxychains4.conf এ:
random_chain        # প্রতি request এ random proxy
chain_len = 1       # একটা proxy per connection

# তারপর:
proxychains ffuf -w wordlist.txt -u https://target.tld/FUZZ
```

```
Request 1: তোমার IP → Proxy A → Target
Request 2: তোমার IP → Proxy B → Target
Request 3: তোমার IP → Proxy C → Target
```

---

### 6.4 IPv6 Mass Rotation

IPv4 তে proxy কিনতে হয়। কিন্তু IPv6 তে অনেক cloud provider (যেমন Vultr) একটা **/64 subnet** দেয়।

```
/64 subnet মানে:
  2^64 = 18,446,744,073,709,551,616 টা IP address!
  (18 quadrillion!)
```

```bash
# Linux এ IPv6 range থেকে random IP bind করা
ip -6 addr add 2001:db8::/64 dev eth0

# প্রতি request এ নতুন IPv6 address ব্যবহার
# Tools: ddd/gpb, custom scripts
```

**কেন এটা powerful?** Rate limiter যদি per-IP কাজ করে, তাহলে প্রতিটা request নতুন IP থেকে আসছে বলে মনে হবে।

---

## 7. Practical Lab — DVWA Setup

### Lab Environment Setup

```bash
# Docker দিয়ে DVWA চালাও (Parrot OS / Kali তে)
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa

# Browser এ যাও: http://localhost/dvwa
# Default creds: admin / password
```

### Lab 1: Burp Suite Sniper — DVWA Brute Force

```
Step 1: DVWA → Brute Force page এ যাও
        Security level: Low সেট করো

Step 2: Burp Suite চালাও, Proxy intercept on করো

Step 3: Login form এ যেকোনো username/password দিয়ে Submit করো

Step 4: Burp এ intercepted request দেখবে:
        GET /vulnerabilities/brute/?username=admin&password=test&Login=Login

Step 5: Right click → Send to Intruder

Step 6: Intruder → Positions tab
        "password=§test§" — শুধু password position mark করো
        Attack type: Sniper

Step 7: Payloads tab
        Payload type: Simple list
        Add wordlist: /usr/share/wordlists/rockyou.txt (top 100 lines)

Step 8: Start Attack
        Response length বা status code দেখো
        "Welcome" text আছে → সেটাই correct password
```

### Lab 2: FFUF Login Brute Force

```bash
# DVWA এর login endpoint test করো
# প্রথমে request structure বুঝো (Burp দিয়ে intercept করো)

ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:PASS \
     -u "http://localhost/vulnerabilities/brute/?username=admin&password=PASS&Login=Login" \
     -H "Cookie: PHPSESSID=<your_session_id>; security=low" \
     -fs 4290
     # -fs: filter করো যেগুলোর size 4290 bytes (wrong password response size)
```

### Lab 3: Rate Limit Test

```bash
# Headers দিয়ে bypass test করো

# Test 1: X-Forwarded-For
curl -X POST http://localhost/login \
  -H "X-Forwarded-For: 8.8.8.8" \
  -d "username=admin&password=test"

# Test 2: X-Real-IP
curl -X POST http://localhost/login \
  -H "X-Real-IP: 1.1.1.1" \
  -d "username=admin&password=test"

# Common IP spoofing headers to test:
# X-Forwarded-For
# X-Real-IP
# X-Originating-IP
# X-Remote-IP
# X-Client-IP
# CF-Connecting-IP (Cloudflare)
# True-Client-IP
```

---

## 8. Defense Cheat Sheet

**Defender হিসেবে তোমার কী করা উচিত:**

```
Attack                    → Defense
─────────────────────────────────────────────────────────────
Password Guessing         → Strong password policy + MFA
IP-based Rate Limit only  → Multi-layer rate limiting (IP + account + device)
X-Forwarded-For bypass    → Rate limit করো real IP দিয়ে, header trust করো না
JA3 bypass via curl-imp.  → Behavioral analysis (timing, mouse movement)
IPv6 rotation             → CAPTCHA after N failed attempts
HTTP Pipelining           → Fail2ban, account lockout after 5 attempts
Credential Stuffing       → HaveIBeenPwned API integration, MFA mandatory
```

### Secure Implementation Example (Node.js)

```javascript
const rateLimit = require('express-rate-limit')

// IP + Account উভয়ের জন্য rate limit
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  keyGenerator: (req) => {
    // X-Forwarded-For trust করো না, real IP নাও
    return req.socket.remoteAddress + ':' + req.body.username
  },
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many login attempts. Try again in 15 minutes.',
    })
  },
})

app.post('/login', loginLimiter, loginHandler)
```

---

## 9. Attack Decision Tree

```
Target এ login form পেলাম
          │
          ▼
    Rate limit আছে?
    ┌──────────────┐
    │              │
   না             হ্যাঁ
    │              │
    ▼              ▼
Burp Intruder  Rate limit কীভাবে কাজ করে?
Cluster Bomb   ┌────────────────────────────┐
               │                            │
            IP-based                  Account-based
               │                            │
               ▼                            ▼
    X-Forwarded-For             Password Spray করো
    header bypass?              (slow, 1 pass/user)
    ┌─────────────┐
    │             │
   হ্যাঁ          না
    │             │
    ▼             ▼
FFUF with     Proxy Rotation
IP header     (proxychains)
rotation      বা IPv6 rotation
              বা JA3 bypass
```

---

## 10. References

| Resource                          | Link                                                                                                           |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings              | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Brute%20Force%20Rate%20Limit)         |
| Burp Suite Intruder Docs          | [PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types) |
| FFUF GitHub                       | [ffuf/ffuf](https://github.com/ffuf/ffuf)                                                                      |
| curl-impersonate                  | [lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate)                                      |
| SecLists (Wordlists)              | [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)                                          |
| DVWA Lab                          | [digininja/DVWA](https://github.com/digininja/DVWA)                                                            |
| JA3 Fingerprinting                | [salesforce/ja3](https://github.com/salesforce/ja3)                                                            |
| Bruteforcing Google Phone Numbers | [brutecat.com](https://web.archive.org/web/20250609141236/https://brutecat.com/articles/leaking-google-phones) |

---

> ✅ **Next Topic Suggestions:**
>
> - `SQL Injection/README.md` — SQLi basics থেকে advanced
> - `File Inclusion/README.md` — LFI/RFI & LFI-to-RCE
> - `XSS Injection/README.md` — Stored, Reflected, DOM XSS

> ⚠️ **Ethical Reminder:** এই সব technique শুধুমাত্র authorized penetration testing, CTF challenges, এবং নিজের lab environment এ practice করো। Unauthorized system এ use করা criminal offense।
