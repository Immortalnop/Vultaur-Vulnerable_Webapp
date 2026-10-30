# Vulnerabilities, Exploits & Fixes

Each flaw below is tagged `# VULN:` in `vulnerable/app.py` and `# FIX:` in
`secure/app.py`. Run both apps side by side (ports 5000 vs 5001) to compare.

Seed accounts: `alice/password123`, `bob/hunter2`, `admin/S3cr3tAdminPass!`.

---

## 1. SQL Injection (`/login`)

**Flaw.** The login query concatenates raw input:
`SELECT * FROM users WHERE username='<u>' AND password='<p>'`.

**Exploit.**
- Auth bypass: username `admin' --`, any password → the `--` comments out the
  password check and you are logged in as admin.
- Data theft: `x' UNION SELECT id,username,password,role FROM users --` returns
  every row, dumping all credentials.

**Fix.** Parameterized query — bind input as data, never concatenate:
`execute("SELECT * FROM users WHERE username=?", (u,))`, then verify the
password separately. Input can no longer change the SQL structure.

---

## 2. Broken Authentication / Access Control (`/admin`, cookies)

**Flaw.** Identity lives in a plaintext, unsigned cookie (`user=alice`), and
`/admin` trusts `user=admin` from that cookie. Passwords are stored in plaintext.

**Exploit.** Send `Cookie: user=admin` with no login at all → full admin panel,
including every user's plaintext password. No credentials needed.

**Fix.** Server-side signed sessions (`app.secret_key` + Flask `session`), so the
client can't forge identity or role. Store **salted hashes**
(`generate_password_hash` / `check_password_hash`), and read `role` from the
session, not the request.

---

## 3. IDOR — Insecure Direct Object Reference (`/note/<id>`)

**Flaw.** Any note is returned by id with no ownership or privacy check.

**Exploit.** As `alice`, request `/note/4` (admin's private note) → reads
`FLAG{...}`. Just increment the id to walk every record.

**Fix.** Enforce authorization on the object: return a private note only if
`note.owner == current_user()`, else `403`. The home list is filtered the same way.

---

## 4. Stored XSS (`/note/new` → `/note/<id>`)

**Flaw.** A note body is saved verbatim and rendered with Jinja `|safe`, so
markup executes for every viewer.

**Exploit.** Save a note whose body is
`<script>fetch('/admin')</script>` → the script runs in the browser of anyone
(including admin) who opens it, enabling session theft / actions as the victim.

**Fix.** Keep autoescaping ON (never `|safe` on user data); escape every field
(`markupsafe.escape`). Add a Content-Security-Policy in production.

---

## 5. Reflected XSS (`/search?q=`)

**Flaw.** The search term is echoed into the HTML attribute/body unescaped.

**Exploit.** `/search?q='><script>alert(1)</script>` → breaks out of the input
and executes. Delivered via a crafted link.

**Fix.** Escape the value before reflecting it (`escape(q)`); autoescaping in
templates handles this automatically when you don't bypass it.

---

## 6. SSRF — Server-Side Request Forgery (`/fetch?url=`)

**Flaw.** The server fetches any user-supplied URL with no validation, so it
reaches internal services the attacker can't reach directly.

**Exploit.**
- `url=http://127.0.0.1:5000/admin` → server hits its own internal surface.
- On a cloud host: `url=http://169.254.169.254/latest/meta-data/` → steals cloud
  instance credentials. Also usable for internal port scanning.

**Fix.** Allowlist scheme (`http/https`) and host; resolve the hostname and
**reject private / loopback / link-local / reserved IPs** before connecting.
Disable redirects, set timeouts. (Belt-and-braces: egress firewall + block the
metadata endpoint.)

---

## General hardening (production)
- Parameterized queries everywhere; least-privilege DB user.
- Signed, `HttpOnly`, `Secure`, `SameSite` cookies; rotate on login.
- Password hashing (argon2/bcrypt), rate limiting, lockout on `/login`.
- Output encoding + CSP; input validation as defense in depth.
- Authorization checks on every object access (default deny).
- SSRF: allowlist + IP filtering + network egress controls.
