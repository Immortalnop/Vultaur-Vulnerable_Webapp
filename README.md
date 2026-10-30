# VulnNotes — Vulnerable Web App Lab

A deliberately insecure Flask "notes" app for learning web security, plus a
fixed version and working exploits. Covers **SQLi, Stored & Reflected XSS,
SSRF, IDOR, and Broken Authentication**.

> ⚠️ **TRAINING ONLY.** The app in `vulnerable/` is intentionally broken. Run it
> on `localhost` or an isolated VM only. Never deploy it or expose it to a
> network. Attack only this app, on your own machine.

## Layout
```
vulnerable/app.py   intentionally vulnerable app   (port 5000)
secure/app.py       same app, every flaw fixed     (port 5001)
exploits/run_all.py stdlib exploit runner, all 6 vulns
FIXES.md            vuln → exploit → fix writeup
```
Vulnerabilities are tagged `# VULN:` in the vulnerable app and `# FIX:` in the
secure app, so you can diff them line by line.

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Run the vulnerable app + exploits
```bash
python vulnerable/app.py          # terminal 1  -> http://127.0.0.1:5000
python exploits/run_all.py        # terminal 2  -> all exploits PASS
```

## Run the secure app (exploits should now fail)
```bash
python secure/app.py              # http://127.0.0.1:5001
```
Point the exploit runner's `PORT` at 5001 to confirm each attack is blocked.

## Seed accounts
| user  | password          | role  |
|-------|-------------------|-------|
| alice | password123       | user  |
| bob   | hunter2           | user  |
| admin | S3cr3tAdminPass!  | admin |

## Try it by hand
- **SQLi**: log in with username `admin' --`, any password.
- **Broken auth**: `curl -H "Cookie: user=admin" http://127.0.0.1:5000/admin`
- **IDOR**: open `/note/4` as any user.
- **Stored XSS**: create a note with body `<script>alert(1)</script>`, reopen it.
- **Reflected XSS**: visit `/search?q='><script>alert(1)</script>`
- **SSRF**: `/fetch?url=http://127.0.0.1:5000/admin`

See `FIXES.md` for the full exploit-and-fix explanation of each.
