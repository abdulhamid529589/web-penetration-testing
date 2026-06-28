# CORS Misconfiguration Lab — Instructions

Everything in this lab runs on `localhost` only. Nothing here touches the internet or any real third-party system.

## Files

- `vulnerable_server.py` — the API with a deliberately broken CORS config (Origin reflection)
- `fixed_server.py` — the same API with a correct exact-match allowlist
- `poc_page.html` — a page simulating an "attacker" page on a different origin

## Step 1 — Run the vulnerable version

```bash
pip install flask
python vulnerable_server.py
```

This starts the API at `http://localhost:5000`.

## Step 2 — Log in to get a session cookie

Open `http://localhost:5000/login` in your browser. This sets a cookie simulating a logged-in user named "alice."

## Step 3 — Serve the PoC page from a _different_ origin

In a **separate terminal**, in the same folder as `poc_page.html`:

```bash
python -m http.server 8000
```

This serves files at `http://localhost:8000` — a different port means a different origin to the browser, exactly like an attacker's separate website would be.

## Step 4 — Run the exploit demo

Open `http://localhost:8000/poc_page.html` in the **same browser** (so it shares cookies with `localhost:5000`). Click **"Attempt Cross-Origin Read."**

**Expected result (vulnerable server):** the page successfully reads back alice's fake profile data and api_key — even though `poc_page.html` is running on a completely different origin (`:8000` vs `:5000`). This is the exact mechanism described in the theory notes: the server reflected the `Origin` header and set `Access-Control-Allow-Credentials: true`, so the browser allowed it.

## Step 5 — Swap to the fixed server and repeat

Stop `vulnerable_server.py` (Ctrl+C), then:

```bash
python fixed_server.py
```

Repeat steps 2 and 4 exactly. **Expected result (fixed server):** the request is blocked — your browser's console / the PoC page output will show a CORS error, because `localhost:8000` isn't in the server's allowlist.

## What to Take Away

Open your browser's DevTools → Network tab during both runs and compare the response headers on `/api/profile`:

- **Vulnerable:** `Access-Control-Allow-Origin: http://localhost:8000` (it matched whatever Origin you sent)
- **Fixed:** that header is simply absent when the origin isn't allowlisted

That header's presence or absence is the entire vulnerability and the entire fix — everything else (cookies, JS, fetch calls) is identical between the two runs.

## Extending the Lab (Optional)

Try modifying `vulnerable_server.py` yourself to reproduce the other patterns from the theory notes:

- Trust only `Origin: null` (then load the PoC via a sandboxed iframe with a `data:` URI instead of `localhost:8000`)
- Replace the allowlist in `fixed_server.py` with `origin.endswith("localhost:5000")` and see how `http://evillocalhost:5000` (you'd need to add this to your `/etc/hosts` as a loopback alias to test) would slip through a broken check like that

Modifying your own broken/fixed pairs and re-running the same PoC is the fastest way to make each failure pattern from the theory guide concrete.
